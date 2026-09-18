package realm

import (
	"context"
	"net/netip"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ★S3：对称 NAT 下打洞与中继**并发竞速**
// （CMCC_CELLULAR_CONNECTIVITY_FIX_DESIGN.md S3，2026-09-17）
//
// 问题：原流程是「先 racePunch，失败后才 DialRelay」。对称 NAT（中国移动蜂窝）
// 下打洞**必败**，客户端每次连接都要先烧满 punchTimeout=10s 才回退中继。这 10s
// 里非 CN 域名 DNS（DoH over proxy）全挂、App 自身 API 全挂，用户表现为「连上了
// 但十几秒没网」。诊断实证：每次连接/每次网络切换必现，是主诉的稳定复现段。
//
// 方案：STUN 反射地址显示对称 NAT（多个映射端口不一致）且会合面下发了中继地址时，
// **同时**发起 racePunch 与 DialRelay，谁先拿到可用连接就用谁，取消另一路。
// 打洞若能成功（少数对称 NAT 仍能靠端口预测撞通），走打洞，出口是本地直连；
// 打洞打不通（多数），中继几百毫秒就接上，不再干等 10s。
//
// 🔴 边界（与既有行为一致，违反即回归）：
//   - 只在 guessNATType == symmetric 且 len(relay) > 0 时进本路径。cone / unknown /
//     无中继 → 恒走原「先打洞后回退」路径，逐字节不变。对称 NAT 判据本就是
//     「打洞大概率失败」的信号，用它做门槛既省 10s、又不动正常网络的用户。
//   - trace 语义不变：FailStage 只在两路都失败时记 punch（打洞确实失败过）；
//     relay 赢则 RelayEstablished（relay_used=true，FailStage 不设）；punch 赢则
//     PunchDone。与非竞速路径的口径完全一致。
//   - 打洞与中继用**各自独立的 socket**：racePunch 用 STUN 阶段开的 family socket，
//     DialRelay 自开新 socket，互不重叠，赢家定后另一路自行关闭自己的 socket。

// racePunchAndRelay 并发跑打洞与中继，返回先成功的一方。
// punchAddresses / metadata 同 racePunch；relayAddresses 为会合面下发的中继（非空）。
//
// 返回 (conn, viaRelay, err)：
//   - err == nil && viaRelay：中继赢，conn 是中继 PacketConn（PeerAddr = 中继地址）；
//   - err == nil && !viaRelay：打洞赢，conn.PacketConn 是打洞 socket；
//   - err != nil：两路都失败，err 里带**打洞**错误（与原路径 return 的 err 同源，
//     保证 classifyError / trace 归类不变）；中继错误只作次要项附加。
func racePunchAndRelay(
	ctx context.Context,
	cfg Config,
	families []*familyConn,
	punchAddresses []netip.AddrPort,
	relayAddresses []netip.AddrPort,
	metadata squic.PunchMetadata,
) (conn *PunchedConn, viaRelay bool, err error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type punchOutcome struct {
		family *familyConn
		result squic.PunchResult
		err    error
	}
	type relayOutcome struct {
		conn *PunchedConn
		err  error
	}
	punchCh := make(chan punchOutcome, 1)
	relayCh := make(chan relayOutcome, 1)

	go func() {
		winner, result, perr := racePunch(raceCtx, families, punchAddresses, metadata)
		punchCh <- punchOutcome{family: winner, result: result, err: perr}
	}()
	go func() {
		rc, rerr := DialRelay(raceCtx, cfg, relayAddresses, metadata.Nonce)
		relayCh <- relayOutcome{conn: rc, err: rerr}
	}()

	// 收两路结果。先到的成功者是赢家；赢家定后 cancel 让另一路收敛，再把它的
	// 结果收干净（成功则关掉多余连接，避免泄漏一只 socket + 中继一条会话）。
	var (
		punchDone, relayDone bool
		punchRes             punchOutcome
		relayRes             relayOutcome
	)
	for !punchDone || !relayDone {
		select {
		case punchRes = <-punchCh:
			punchDone = true
			if punchRes.err == nil {
				// 打洞赢：取消中继路，等它收敛后关掉可能已建成的中继连接。
				raceCancel()
				if !relayDone {
					relayRes = <-relayCh
					relayDone = true
				}
				if relayRes.err == nil && relayRes.conn != nil {
					_ = relayRes.conn.Close()
				}
				return &PunchedConn{
					PacketConn: punchRes.family.conn,
					PeerAddr:   M.SocksaddrFromNetIP(punchRes.result.PeerAddr),
				}, false, nil
			}
		case relayRes = <-relayCh:
			relayDone = true
			if relayRes.err == nil {
				// 中继赢：取消打洞路，等它收敛（racePunch 自己关掉全部 family socket）。
				raceCancel()
				if !punchDone {
					punchRes = <-punchCh
					punchDone = true
				}
				// 打洞路若也成功了（罕见竞态），racePunch 已保留一只赢家 socket
				// 未关 —— 我们不用它，关掉避免泄漏。
				if punchRes.err == nil && punchRes.family != nil {
					_ = punchRes.family.conn.Close()
				}
				return relayRes.conn, true, nil
			}
		}
	}

	// 两路都失败：返回打洞错误为主（与原「先打洞后回退」路径的 return 值同源），
	// 中继错误附加，供日志排查。family socket 已由 racePunch 关闭；中继 socket 由
	// DialRelay 关闭。
	perr := punchRes.err
	if perr == nil {
		perr = E.New("realm punch: no result")
	}
	if relayRes.err != nil {
		return nil, false, E.Cause(perr, "relay also failed: "+relayRes.err.Error())
	}
	return nil, false, perr
}
