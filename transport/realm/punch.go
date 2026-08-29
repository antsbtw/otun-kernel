// Package realm is the protocol-agnostic CLIENT-side "register + hole-punch"
// library: the dialer half of the rendezvous foundation (M2).
//
// It exposes a single primitive:
//
//	Punch(ctx, cfg, realmID) (net.PacketConn, error)
//
// which performs STUN discovery, talks to the rendezvous control plane to swap
// candidate addresses with the target node, races UDP hole punching across
// address families, and returns a RAW, already-punched net.PacketConn. It does
// NOT touch any overlay protocol: no QUIC handshake, no obfs, no TLS. The caller
// (hysteria2 / TUIC / …) takes the returned PacketConn and runs its own
// handshake on top — splitting the old "punch→QUIC welded" path into
// "punch" + "protocol".
//
// This is the client counterpart to OTun-S (the rendezvous engine, server
// side). Together they are the independent, protocol-agnostic rendezvous
// foundation that DEV M1+M2 call for.
//
// IMPLEMENTATION NOTE: the low-level punch primitives (packet codec, STUN,
// control client, symmetric-NAT candidate expansion) are reused verbatim from
// sing-quic's hysteria2/realm package — the exact code already proven on the
// Hy2 path — so behavior matches the regression baseline. What lives HERE is
// only the dialer-side orchestration that sing-quic had tangled inside
// hysteria2's client.go (offerNewRealm), lifted out protocol-free.
//
// ★ 归位（2026-07-30，客户端栈归位阶段一）：本文件原住 otun-s（服务端仓），
// 逐字节搬到 kernel（客户端仓），逻辑一行未改。归位的原因是三仓分工：
// 客户端能力迭代只该动 kernel，而 Punch() 是客户端拨号侧的编排入口，
// 也是六协议七阶段埋点（阶段二）的落点 —— 埋点必须能在 kernel 里做。
package realm

import (
	"context"
	"net"
	"net/netip"
	"sync"

	otunsrealm "github.com/antsbtw/otun-s/transport/realm"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// 🔴 Config / PunchedConn / Resolver 三个类型故意**别名回 otun-s**，不在本仓
// 重新定义。原因是 otun-s/underlay（线格式包，两侧共用，按决策 D1 留在 otun-s）
// 的客户端半边签名里写死了这三个类型：
//
//	underlay.FromPunch(*otunsrealm.PunchedConn)
//	underlay.Config = otunsrealm.Config
//	underlay.NewLazyDialer(cfg, id, func(...) (*otunsrealm.PunchedConn, error))
//
// Go 里两个具名类型即使字段完全相同也不可互相赋值，所以若本仓另起一套定义，
// overlay/* 就没法再调 underlay 的这些入口 —— 那就不是「搬代码 + 改 import」，
// 而是改调用方式，违反本阶段「零行为变更」。用别名则类型完全同一，
// underlay 一行不用动，otun-s 仓一行不用改。
//
// ★ 归位的目标是 **Punch() 的编排逻辑**（埋点落点）落到 kernel，这已达成；
// 剩下这三个类型定义是「线格式/接口约定」性质，留在 otun-s 与 D1 的判断一致。
// 将来抽出 otun-wire 独立仓（D1 选项 B）时，别名换成指向 otun-wire 即可。
type (
	Resolver    = otunsrealm.Resolver
	Config      = otunsrealm.Config
	PunchedConn = otunsrealm.PunchedConn
)

// Punch performs the full client-side rendezvous + hole-punch for realmID and
// returns a raw, punched PacketConn. On failure the caller falls back to relay
// (out of scope here) or retries; all sockets are closed before returning an
// error.
//
// Flow (mirrors sing-quic hysteria2 client.go offerNewRealm, QUIC/obfs removed):
//  1. open v4 + v6 UDP sockets ("families");
//  2. STUN-discover each family's reflexive candidates;
//  3. control.Connect — push our candidates, get the peer's + shared nonce/obfs;
//  4. race-punch across families; the first to open a hole wins;
//  5. return the winning socket (others closed).
func Punch(ctx context.Context, cfg Config, realmID string) (*PunchedConn, error) {
	return PunchTraced(ctx, cfg, realmID, nil)
}

// PunchMode 选择拨号走哪条路径。生产/默认恒为 ModeNormal（打洞优先、失败回退
// 中继），只有探针入口为「隔离测某一条路径」才用另外两个。
//
// 🔴 这三条路径只影响 PunchTracedWithMode 内部的路径选择，不改任何返回类型或
// 既有调用点签名 —— PunchTraced == PunchTracedWithMode(ModeNormal)。
type PunchMode int

const (
	// ModeNormal：打洞优先，打洞失败且会合面下发了中继地址时回退中继。
	// 这是生产唯一路径，与埋点前逐字节等价。
	ModeNormal PunchMode = iota
	// ModePunchOnly：只打洞，禁用中继回退（即便会合面下发了中继地址）。
	// 探针用它隔离验证「这条路的打洞本身通不通」，不让中继成功掩盖打洞失败。
	ModePunchOnly
	// ModeRelayOnly：跳过打洞，直接连中继。探针用它隔离验证中继链路，
	// 不受打洞结果干扰。会合面未下发中继地址时直接失败（candidate 阶段）。
	ModeRelayOnly
)

// PunchTracedWithMode 是 PunchTraced 的路径可选版本：ModeNormal 时行为与
// PunchTraced 逐字节等价（探针入口之外无人用别的 mode）。
//
// 🔴 零回归：PunchTraced 就是本函数 mode=ModeNormal 的薄包装，控制流在
// ModeNormal 分支上与改动前一字未变，由 TestPunchTracedNilTraceMatchesPunch
// 等既有单测继续把关。ModePunchOnly/ModeRelayOnly 是新增的、只有探针触达的分支。

// PunchTraced 与 Punch 等价，额外把各阶段耗时与打洞细节记进 trace。
//
// ★ 刻意做成 Punch 的**兄弟函数**而不是改 Punch 的签名 —— 生产路径调用点
// （overlay/* 五个、underlay.NewLazyDialer 的 punchFn）保持零改动。
// 这个模式抄自旧探针内核 probe 分支的 PunchTraced/DiscoverTraced。
//
// 🔴 trace 为 nil 时**必须**与改动前逐字等价：Trace 的所有方法都是 nil-receiver
// no-op，本函数除此之外不引入任何分支。这是埋点能进主线的前提（硬约束 4），
// 由 TestPunchTracedNilTraceMatchesPunch 等单测把关。
//
// 🔴 阶段归类刻意与 fail_stage 枚举一一对应，且**在错误发生的那一层**归类，
// 不在上层猜：上层只看得到被 E.Cause 包过的错误原文，靠字符串反推必然漂。
func PunchTraced(ctx context.Context, cfg Config, realmID string, trace *Trace) (*PunchedConn, error) {
	return PunchTracedWithMode(ctx, cfg, realmID, trace, ModeNormal)
}

// PunchTracedWithMode 见 PunchMode 文档。ModeNormal 分支即原 PunchTraced 逻辑。
func PunchTracedWithMode(ctx context.Context, cfg Config, realmID string, trace *Trace, mode PunchMode) (*PunchedConn, error) {
	if realmID == "" {
		return nil, E.New("realm: realm ID is required")
	}
	// ★ModeRelayOnly 走精简路径：中继回退的立意就是「STUN/打洞不可用时的兜底」，
	// 且服务端下发的中继地址来自节点注册（与客户端反射地址无关，已核 otun-s
	// engine.Connect），所以 relay-only **不需要 STUN、不开打洞 socket**。只跑
	// control.Connect 拿 relay 地址 + nonce，再直连中继。这也让「节点没配 STUN」
	// （枚举 API 未下发 stun）不再阻塞纯中继链路的验证。
	if mode == ModeRelayOnly {
		return dialRelayOnly(ctx, cfg, realmID, trace)
	}
	if len(cfg.STUNServers) == 0 {
		return nil, E.New("realm: at least one STUN server is required")
	}
	if cfg.Resolver == nil {
		return nil, E.New("realm: resolver is required")
	}
	control, err := squic.NewControlClient(cfg.ServerURL, cfg.Token, cfg.HTTPClient)
	if err != nil {
		// 会合面 URL 解析失败，还没发出任何请求，归 rendezvous。
		trace.Fail(FailStageRendezvous, err)
		return nil, err
	}

	families, err := openFamilies(ctx, cfg)
	if err != nil {
		// 本地 UDP socket 都开不出来，STUN 无从谈起，归 stun。
		trace.Fail(FailStageSTUN, err)
		return nil, err
	}

	surviving, localAddresses, err := discoverFamilies(ctx, cfg, families)
	if err != nil {
		trace.Fail(FailStageSTUN, err)
		return nil, err // discoverFamilies closed all sockets on error
	}
	// serversUsed 只记配置里的 STUN 列表，不记「实际哪台回了包」——
	// 🔴 那个映射(transactionID→server)在 squic.Discover 内部且不导出，
	// kernel 侧拿不到。宁可少记一个字段，也不编造一个看着精确的假值。
	trace.STUNDone(localAddresses, cfg.STUNServers)

	closeSurviving := func() {
		for _, f := range surviving {
			_ = f.conn.Close()
		}
	}

	metadata, err := squic.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		trace.Fail(FailStageRendezvous, err)
		return nil, E.Cause(err, "generate punch metadata")
	}

	response, err := control.Connect(ctx, realmID, localAddresses, metadata)
	if err != nil {
		closeSurviving()
		// ★ 鉴权 404（该账号没被分配到这个节点）在这里被归成 rendezvous，
		// 再由 classifyError 细分成 not_assigned —— 与「凭证错」区分开。
		trace.Fail(FailStageRendezvous, err)
		return nil, E.Cause(err, "realm connect")
	}
	trace.RendezvousDone(response.Addresses)
	// ★双端 join 键：用会合面下发的 metadata（下面 racePunch 实际打洞用的就是它），
	// 不是上面本地生成的 metadata——接收端记的是前者，用错就永远配不上对。
	trace.NonceNegotiated(response.PunchMetadata)
	trace.CandidatesComputed(response.Addresses)

	winner, result, err := racePunch(ctx, surviving, response.Addresses, response.PunchMetadata)
	if err != nil {
		// candidate 与 punch 的区分：会合面没给出任何可用地址 → candidate
		// （压根没得打）；给了地址但打不通 → punch。
		//
		// 🔴 刻意**不**在 racePunch 之前提前 return —— 那会改变 trace=nil 时的
		// 错误原文与 socket 清理路径（racePunch 自己负责关闭），违反零行为变更。
		// 这里只是给同一个失败换个归类，控制流一字未动。
		stage := FailStagePunch
		if len(response.Addresses) == 0 {
			stage = FailStageCandidate
		}
		trace.Fail(stage, err)

		// ★中继回退（RELAY_FALLBACK_DESIGN.md §3.1）：对称 NAT 下打洞必败，
		// 改由客户端与节点各自主动出站连中继、按 nonce 对接。返回的 PacketConn
		// 与打洞出来的等价，上层握手照常端到端跑（中继看不到明文）。
		//
		// 🔴 三条硬约束（违反即破坏既有行为）：
		//  1. 只在会合面下发了 relay 地址时触发 —— 空则**一行都不执行**，
		//     与改动前逐字节一致（老会合面不返 relay 字段 → 恒为空）。
		//  2. 上面的 trace.Fail 保持在回退**之前**：Fail 是首次记录生效，
		//     所以 trace 里留下的永远是真实的打洞卡点，不会被中继结果覆盖。
		//  3. 回退失败时 return 的是**原 err**（打洞错误原文一字不改）——
		//     既有 trace 归类、classifyError 与单测都依赖它。中继自身的错误
		//     只进日志语义的 relay trace 字段，不进返回值。
		// ★ModePunchOnly（探针专用）：禁用中继回退，即便会合面下发了 relay 地址也不用，
		// 让打洞失败如实暴露（不被中继成功掩盖）。ModeNormal 恒进回退分支，行为不变。
		if mode == ModePunchOnly {
			return nil, err // 打洞失败原文原样返回，与无中继老会合面路径一致
		}
		if len(response.Relay) > 0 {
			// racePunch 已关闭全部 socket；DialRelay 自己开新 socket、自己在
			// 失败时关掉 —— 两条路径的 socket 所有权互不重叠，不存在重复关闭。
			relayConn, relayErr := DialRelay(ctx, cfg, response.Relay, response.PunchMetadata.Nonce)
			if relayErr == nil {
				trace.RelayEstablished(relayConn.PeerAddr.String())
				return relayConn, nil
			}
			trace.RelayFailed(relayErr)
		}
		return nil, err // racePunch closed all sockets on error
	}
	// mode 传空：punch/direct 是**节点侧配置**，客户端无从得知，由 prober 填
	// （硬约束 3 的同类要求 —— 内核不编造自己观测不到的事实）。
	trace.PunchDone(result, winner.family, "")
	return &PunchedConn{
		PacketConn: winner.conn,
		PeerAddr:   M.SocksaddrFromNetIP(result.PeerAddr),
	}, nil
}

// dialRelayOnly 是 ModeRelayOnly 的精简路径：不做 STUN、不开打洞 socket，只跑
// control.Connect 拿会合面下发的中继地址 + nonce，再直连中继。
//
// 🔴 为什么可以跳过 STUN 与打洞 socket：
//   - 服务端下发的中继地址来自【节点注册】时上报的 relay 列表，与客户端反射地址
//     无关（已核 otun-s core.Engine.Connect：relay=append(s.relay...)，clientAddrs
//     只被转发给节点用于打洞，不影响 relay 下发）。所以传空 addresses 也能拿到
//     relay + nonce。
//   - 中继回退的立意本就是「对称 NAT 下 STUN/打洞不可用时的兜底」。若纯中继链路
//     的验证还要先跑通 STUN，就把「中继是否工作」与「STUN 是否工作」耦在一起，
//     违反探针「隔离某一条路径」的目标（也让没配 STUN 的节点无法验中继）。
//
// nonce 仍必须来自 control.Connect 的响应（response.PunchMetadata）——那是双端 join
// 键，节点侧按它在中继上配对，本地生成的用错就永远配不上对（与打洞路径同一铁律）。
func dialRelayOnly(ctx context.Context, cfg Config, realmID string, trace *Trace) (*PunchedConn, error) {
	control, err := squic.NewControlClient(cfg.ServerURL, cfg.Token, cfg.HTTPClient)
	if err != nil {
		trace.Fail(FailStageRendezvous, err)
		return nil, err
	}
	metadata, err := squic.GeneratePunchMetadata()
	if err != nil {
		trace.Fail(FailStageRendezvous, err)
		return nil, E.Cause(err, "generate punch metadata")
	}
	// 会合面 /connect 硬性要求至少一个客户端地址（wire 层校验，与 relay 下发无关，
	// 实测 400 bad_request）。relay-only 不打洞、不做 STUN，没有反射地址可填 ——
	// 于是开一只【经 binder 绑定的】本地 UDP socket，用它的本地地址占位过校验。
	//  - 走 cfg.Dialer（= netbind）保证真机上这只 socket 也绑到目标网络（蜂窝），
	//    与中继 socket 的绑定行为一致；
	//  - 节点侧会收到这个地址去尝试打洞，但 relay-only 场景下打洞不会成功也不影响
	//    中继对接（中继按 nonce 配对，与地址无关）—— 占位地址无害。
	// 用完即关：它只为拿一个本地地址，中继另开自己的 socket（DialRelay）。
	placeholderConn, err := listenPacket(ctx, cfg, M.SocksaddrFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		trace.Fail(FailStageSTUN, err)
		return nil, E.Cause(err, "relay-only: open local socket for address")
	}
	localAddr := placeholderConn.LocalAddr().(*net.UDPAddr)
	localAddresses := []netip.AddrPort{localAddr.AddrPort()}
	_ = placeholderConn.Close()

	response, err := control.Connect(ctx, realmID, localAddresses, metadata)
	if err != nil {
		trace.Fail(FailStageRendezvous, err)
		return nil, E.Cause(err, "realm connect")
	}
	trace.RendezvousDone(response.Addresses)
	trace.NonceNegotiated(response.PunchMetadata)

	if len(response.Relay) == 0 {
		err := E.New("realm relay-only: rendezvous returned no relay address")
		// 会合面没给中继地址 → 与「没地址可打」同类，归 candidate。
		trace.Fail(FailStageCandidate, err)
		return nil, err
	}
	relayConn, relayErr := DialRelay(ctx, cfg, response.Relay, response.PunchMetadata.Nonce)
	if relayErr != nil {
		// 与 ModeNormal 回退失败同源：RelayFailed 记中继侧错误，整体归 punch 阶段
		// （relay 是打洞的替身，同类失败面）。
		trace.Fail(FailStagePunch, relayErr)
		trace.RelayFailed(relayErr)
		return nil, E.Cause(relayErr, "realm relay-only")
	}
	trace.RelayEstablished(relayConn.PeerAddr.String())
	return relayConn, nil
}

// familyConn is one address-family UDP socket plus its discovered candidates.
type familyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

func openFamilies(ctx context.Context, cfg Config) ([]*familyConn, error) {
	specs := []struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}{
		{"v4", true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{"v6", false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	conns := make([]*familyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := listenPacket(ctx, cfg, spec.addr)
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &familyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*familyConn
	var errs []error
	for i, f := range conns {
		if f != nil {
			families = append(families, f)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

func listenPacket(ctx context.Context, cfg Config, addr M.Socksaddr) (net.PacketConn, error) {
	if cfg.Dialer != nil {
		return cfg.Dialer.ListenPacket(ctx, addr)
	}
	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr.AddrPort()))
}

func discoverFamilies(ctx context.Context, cfg Config, families []*familyConn) ([]*familyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, f := range families {
		if f.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := squic.ResolveSTUNServers(ctx, cfg.STUNServers, cfg.Resolver, needIPv4, needIPv6)
	if err != nil {
		for _, f := range families {
			_ = f.conn.Close()
		}
		return nil, nil, E.Cause(err, "resolve STUN servers")
	}
	type discoverResult struct {
		addrs []netip.AddrPort
		err   error
	}
	results := make([]discoverResult, len(families))
	var wg sync.WaitGroup
	for i, f := range families {
		wg.Add(1)
		go func() {
			defer wg.Done()
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == f.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := squic.Discover(ctx, f.conn, servers)
			results[i] = discoverResult{addrs: addrs, err: discoverErr}
		}()
	}
	wg.Wait()
	var surviving []*familyConn
	var union []netip.AddrPort
	var errs []error
	for i, f := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, f.family))
			_ = f.conn.Close()
			continue
		}
		f.localAddresses = result.addrs
		surviving = append(surviving, f)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 {
		return nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, nil
}

func racePunch(
	ctx context.Context,
	families []*familyConn,
	peerAddresses []netip.AddrPort,
	metadata squic.PunchMetadata,
) (*familyConn, squic.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	type outcome struct {
		family *familyConn
		result squic.PunchResult
		err    error
	}
	out := make(chan outcome, len(families))
	for _, family := range families {
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			punchResult, punchErr := squic.Punch(raceCtx, family.conn, peers, metadata)
			out <- outcome{family: family, result: punchResult, err: punchErr}
		}()
	}
	var errs []error
	for pending := len(families); pending > 0; pending-- {
		result := <-out
		if result.err == nil {
			for _, family := range families {
				if family != result.family {
					_ = family.conn.Close()
				}
			}
			return result.family, result.result, nil
		}
		errs = append(errs, E.Cause(result.err, result.family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, squic.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}
