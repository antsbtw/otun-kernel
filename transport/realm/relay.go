package realm

import (
	"context"
	"net"
	"net/netip"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// ★中继回退（RELAY_FALLBACK_DESIGN.md §3.5）：打洞失败时，客户端与私宅节点各自
// **主动出站**连一台有公网 IP 的中继，中继按 nonce 把两条流对接、只搬字节。
// 对称 NAT 只约束入站与打洞，对"自己主动发起的会话"从不设限 —— 这正是
// WebRTC/TURN 二十年的成熟模型。
//
// 🔴 本文件返回的是一个普通 net.PacketConn，**不懂任何协议**：
// TLS/QUIC 握手在其上端到端跑到私宅节点（§2.0 已查证 underlay.FromPunch 只用
// ReadFrom/WriteTo），中继全程看不到明文，伪装随字节流一起穿过。
// ⇒ 六协议自动全通，这里一行协议代码都不该有。

// 线格式（§3.5.4，按 RFC 5766 ChannelData：寻址明文、载荷不透明）：
//
//	首包 RelayJoin：magic(4) ‖ nonce(16)   ← 中继只读这 20 字节
//	之后：          纯字节流原样双向转发   ← 中继一个字节都不解析
//
// 与 otun-relay 仓的 relay.Magic / relay.EncodeJoin 必须逐字节一致。
// 🔴 刻意在此重新定义而不是 import otun-relay：内核不该为了 20 字节常量
// 依赖一个服务端仓（中继是独立仓，见 memory [探测网独立仓]）。
var relayMagic = [4]byte{'O', 'T', 'R', 'L'}

const (
	relayNonceLen = 16
	relayJoinLen  = 4 + relayNonceLen
	// relayJoinRetryInterval 是 join 重发间隔。UDP 无重传，首包丢了就永远配不上对，
	// 所以在等待对端期间持续重发（中继对同源重复 join 是幂等的：刷新等待、不自配对）。
	relayJoinRetryInterval = 500 * time.Millisecond
	// relayHandshakeTimeout 是等待中继回 ack（= 对端已到、配对完成）的上限。
	// 取值略大于打洞窗口：走到中继时客户端已等过一轮打洞，不宜再等太久。
	relayHandshakeTimeout = 10 * time.Second
)

// encodeRelayJoin 组装 RelayJoin 首包。
func encodeRelayJoin(nonce [relayNonceLen]byte) []byte {
	out := make([]byte, relayJoinLen)
	copy(out[:4], relayMagic[:])
	copy(out[4:], nonce[:])
	return out
}

// isRelayJoinAck 判断一个数据报是否是中继对本 nonce 的配对确认。
// 中继把首包原样回给双方作为 ack（otun-relay handleJoin），所以判据 = 逐字节等于我们发出的 join。
func isRelayJoinAck(payload []byte, nonce [relayNonceLen]byte) bool {
	if len(payload) != relayJoinLen {
		return false
	}
	if [4]byte(payload[:4]) != relayMagic {
		return false
	}
	return [relayNonceLen]byte(payload[4:relayJoinLen]) == nonce
}

// DialRelay 连中继、报 nonce、等对接完成，返回一个可直接承载握手的 PunchedConn。
//
// 返回的 PacketConn 就是本地这只 UDP socket，PeerAddr 是**中继地址** —— 上层
// （underlay.FromPunch → QUIC/TLS）照常 WriteTo(peer) / ReadFrom，字节由中继
// 转发到私宅节点。上层无从得知、也不需要知道这条连接是中继来的。
//
// 🔴 多台中继**并发竞速**，不是顺序重试（与 racePunch 同形）。顺序重试有个隐蔽
// 缺陷：第一台不可达时要死等 relayHandshakeTimeout，把整个 ctx 预算耗光，
// 后面的中继根本没机会试 —— 多候选形同虚设（单测 FallsThroughToSecondRelay 抓到）。
// 并发下总耗时 = 最快的一台，且任一台可用即成功。
//
// 🔴 语义与 racePunch 对齐：出错时**自己关掉全部 socket**，成功时只把赢家交给
// 调用方、其余关掉。
func DialRelay(
	ctx context.Context,
	cfg Config,
	relayAddresses []netip.AddrPort,
	nonce [relayNonceLen]byte,
) (*PunchedConn, error) {
	if len(relayAddresses) == 0 {
		return nil, E.New("realm relay: no relay address")
	}
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type outcome struct {
		addr netip.AddrPort
		conn *PunchedConn
		err  error
	}
	out := make(chan outcome, len(relayAddresses))
	for _, relayAddr := range relayAddresses {
		go func() {
			conn, err := dialRelayOne(raceCtx, cfg, relayAddr, nonce)
			out <- outcome{addr: relayAddr, conn: conn, err: err}
		}()
	}

	var (
		winner *PunchedConn
		errs   []error
	)
	for pending := len(relayAddresses); pending > 0; pending-- {
		result := <-out
		switch {
		case result.err != nil:
			errs = append(errs, E.Cause(result.err, result.addr.String()))
		case winner == nil:
			winner = result.conn
			// 赢家已定，取消其余（它们的 socket 由各自的 dialRelayOne 关掉）。
			raceCancel()
		default:
			// 并发下可能有第二台也配对成功 —— 必须关掉，否则泄漏一只 socket
			// 和中继上的一条会话。
			_ = result.conn.Close()
		}
	}
	if winner != nil {
		return winner, nil
	}
	return nil, E.Cause(E.Errors(errs...), "realm relay")
}

// dialRelayOne 对单台中继完成 join 握手。
func dialRelayOne(
	ctx context.Context,
	cfg Config,
	relayAddr netip.AddrPort,
	nonce [relayNonceLen]byte,
) (*PunchedConn, error) {
	// 用与打洞同一条 listen 路径（cfg.Dialer 非空时走它），保证 Android 上
	// socket 保护（VpnService.protect）等平台行为一致 —— 否则中继流量会被自己
	// 的 VPN 路由回环吃掉。
	listenAddr := M.SocksaddrFrom(netip.IPv4Unspecified(), 0)
	if relayAddr.Addr().Is6() && !relayAddr.Addr().Is4In6() {
		listenAddr = M.SocksaddrFrom(netip.IPv6Unspecified(), 0)
	}
	conn, err := listenPacket(ctx, cfg, listenAddr)
	if err != nil {
		return nil, E.Cause(err, "listen UDP for relay")
	}

	joined, err := relayJoin(ctx, conn, relayAddr, nonce)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return joined, nil
}

// relayJoin 发 RelayJoin 并等中继回 ack（= 对端已到、两条流已对接）。
//
// 🔴 必须等到 ack 再返回，不能"发完就当成功"：中继在对端到达前只是把我们挂起，
// 此时把 conn 交给上层，QUIC 握手会朝一个还没对接的管道发包，直到超时才失败 ——
// 那样失败得更慢，且错误会被归成协议层超时而不是中继未配对，排障困难。
func relayJoin(
	ctx context.Context,
	conn net.PacketConn,
	relayAddr netip.AddrPort,
	nonce [relayNonceLen]byte,
) (*PunchedConn, error) {
	ctx, cancel := context.WithTimeout(ctx, relayHandshakeTimeout)
	defer cancel()

	join := encodeRelayJoin(nonce)
	target := net.UDPAddrFromAddrPort(relayAddr)

	// 重发 goroutine：UDP 首包可能丢，中继对同源重复 join 幂等。
	sendDone := make(chan struct{})
	defer close(sendDone)
	go func() {
		ticker := time.NewTicker(relayJoinRetryInterval)
		defer ticker.Stop()
		for {
			// 写失败不致命（网络瞬断），继续重试到 ctx 超时。
			_, _ = conn.WriteTo(join, target)
			select {
			case <-ticker.C:
			case <-sendDone:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// ctx 到期时解除 ReadFrom 阻塞。
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-readDone:
		}
	}()

	buffer := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, E.New("relay pairing timeout")
			}
			return nil, E.Cause(err, "read relay ack")
		}
		fromAddr, ok := udpAddrPort(from)
		if !ok || fromAddr != relayAddr {
			// 不是中继来的包（扫描/串扰）——丢弃继续等。
			continue
		}
		if !isRelayJoinAck(buffer[:n], nonce) {
			// 中继已对接、对端数据先于 ack 到达也可能发生。
			// 但此时我们还没把 conn 交出去，这个包已被读走 —— 直接丢弃是安全的：
			// QUIC 的首个握手包由上层重传，不依赖这一个数据报。
			continue
		}
		// 清掉为超时设的读截止时间，交回给上层时必须是干净的 socket。
		_ = conn.SetReadDeadline(time.Time{})
		return &PunchedConn{
			PacketConn: conn,
			PeerAddr:   M.SocksaddrFromNetIP(relayAddr),
		}, nil
	}
}

func udpAddrPort(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := udpAddr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
