package realm

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 这些测试针对「假成功」修复（2026-08-29）：Respond 收到一个 PunchHello 只证明
// 入向单向可达，必须确认回程后才能宣告成功。用真实 UDP socket 构造三种链路。

func testMetadata() PunchMetadata {
	var m PunchMetadata
	for i := range m.Nonce {
		m.Nonce[i] = byte(i + 1)
	}
	for i := range m.ObfuscationKey {
		m.ObfuscationKey[i] = byte(i + 7)
	}
	return m
}

func mustUDP(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return conn, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// newServer 起一个节点侧 puncher，并驱动其 ReadFrom 循环（真实节点由 hy2 服务端驱动，
// 非打洞报文经此落到数据面；测试里我们同样必须持续读，否则 watch 观察点不会触发）。
func newServer(t *testing.T, ctx context.Context) (*ServerPuncher, netip.AddrPort) {
	t.Helper()
	udp, addr := mustUDP(t)
	t.Cleanup(func() { _ = udp.Close() })
	pc := NewPunchPacketConn(udp, 16)
	puncher := NewServerPuncher(ctx, pc)
	t.Cleanup(puncher.Close)
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return puncher, addr
}

// ① 假成功必须被判失败：客户端只发 Hello（模拟对称 NAT 下我方 Ack 永远送不回去），
// 之后彻底静默、不发 QUIC 握手。修复前这里会 success，修复后必须超时失败。
func TestRespondRejectsOneWayHole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	puncher, serverAddr := newServer(t, ctx)

	client, _ := mustUDP(t)
	defer client.Close()
	pkt, err := EncodePunchPacket(PunchHello, meta)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// 只发一次 Hello，然后再不发任何东西。延迟发出以确保 Respond 已登记 attempt——
	// 生产中顺序天然如此（会合面事件先到，节点才调用 Respond），先发会让 Hello
	// 被当成普通数据面报文，测的就不是目标场景了。
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = client.WriteToUDPAddrPort(pkt, serverAddr)
	}()

	respCtx, respCancel := context.WithTimeout(ctx, 3*time.Second)
	defer respCancel()
	_, err = puncher.Respond(respCtx, "attempt-oneway", nil, meta, true)
	if err == nil {
		t.Fatal("单向洞被判成功 —— 假成功回归了")
	}
}

// ② 老客户端（不回 Ack，但打洞成功后立刻发 QUIC 握手）必须仍判成功。
// 这是向后兼容的关键：节点先升级、客户端后升级期间不能全量误判。
func TestRespondAcceptsLegacyClientQUICTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	puncher, serverAddr := newServer(t, ctx)

	client, _ := mustUDP(t)
	defer client.Close()
	hello, _ := EncodePunchPacket(PunchHello, meta)
	go func() {
		// 先等 Respond 登记 attempt（生产中会合面事件先到，顺序天然如此）。
		time.Sleep(100 * time.Millisecond)
		_, _ = client.WriteToUDPAddrPort(hello, serverAddr)
		// 老客户端收到 Ack 后不回打洞包，直接发起 QUIC 握手（这里用任意非打洞字节）。
		time.Sleep(150 * time.Millisecond)
		_, _ = client.WriteToUDPAddrPort([]byte("\x00quic-initial-not-a-punch-packet"), serverAddr)
	}()

	respCtx, respCancel := context.WithTimeout(ctx, 5*time.Second)
	defer respCancel()
	result, err := puncher.Respond(respCtx, "attempt-legacy", nil, meta, true)
	if err != nil {
		t.Fatalf("老客户端被误判失败（兼容性回归）: %v", err)
	}
	if !result.PeerAddr.IsValid() {
		t.Fatal("peer 地址无效")
	}
}

// ③ 对端回 Ack 的情况必须判成功（双向已通的直接证据）。
func TestRespondAcceptsPeerAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	puncher, serverAddr := newServer(t, ctx)

	client, _ := mustUDP(t)
	defer client.Close()
	hello, _ := EncodePunchPacket(PunchHello, meta)
	ack, _ := EncodePunchPacket(PunchAck, meta)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, _ = client.WriteToUDPAddrPort(hello, serverAddr)
		time.Sleep(150 * time.Millisecond)
		_, _ = client.WriteToUDPAddrPort(ack, serverAddr)
	}()

	respCtx, respCancel := context.WithTimeout(ctx, 5*time.Second)
	defer respCancel()
	if _, err := puncher.Respond(respCtx, "attempt-ack", nil, meta, true); err != nil {
		t.Fatalf("收到对端 Ack 仍被判失败: %v", err)
	}
}

// ④ 对端只是不停重发 Hello（从不回 Ack、也不发数据）不能算成功 ——
// 否则等于退回原来的假成功判定。
func TestRespondRejectsRepeatedHelloOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta := testMetadata()
	puncher, serverAddr := newServer(t, ctx)

	client, _ := mustUDP(t)
	defer client.Close()
	hello, _ := EncodePunchPacket(PunchHello, meta)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		time.Sleep(100 * time.Millisecond)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = client.WriteToUDPAddrPort(hello, serverAddr)
			time.Sleep(100 * time.Millisecond)
		}
	}()

	respCtx, respCancel := context.WithTimeout(ctx, 3*time.Second)
	defer respCancel()
	if _, err := puncher.Respond(respCtx, "attempt-hello-only", nil, meta, true); err == nil {
		t.Fatal("只重发 Hello 被判成功 —— 假成功回归了")
	}
}
