package realm

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeRelay 是一台最小中继：按 nonce 配对两条流，原样回 ack、双向转发。
// 与 otun-relay 仓的行为对齐，用来在无网络依赖下测客户端半边。
type fakeRelay struct {
	conn    net.PacketConn
	waiting map[[relayNonceLen]byte]netip.AddrPort
	routes  map[netip.AddrPort]netip.AddrPort
	// ackJoin=false 模拟"中继收到 join 但对端始终不来"（不回 ack）。
	ackJoin bool
}

func startFakeRelay(t *testing.T, ackJoin bool) *fakeRelay {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &fakeRelay{
		conn:    conn,
		waiting: make(map[[relayNonceLen]byte]netip.AddrPort),
		routes:  make(map[netip.AddrPort]netip.AddrPort),
		ackJoin: ackJoin,
	}
	go r.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return r
}

func (r *fakeRelay) addr() netip.AddrPort {
	return r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (r *fakeRelay) serve() {
	buf := make([]byte, 2048)
	for {
		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		src := from.(*net.UDPAddr).AddrPort()
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		payload := append([]byte(nil), buf[:n]...)

		if peer, paired := r.routes[src]; paired {
			_, _ = r.conn.WriteTo(payload, net.UDPAddrFromAddrPort(peer))
			continue
		}
		if len(payload) != relayJoinLen || [4]byte(payload[:4]) != relayMagic {
			continue
		}
		var nonce [relayNonceLen]byte
		copy(nonce[:], payload[4:])
		if !r.ackJoin {
			continue // 永不配对，用于测超时
		}
		if other, ok := r.waiting[nonce]; ok && other != src {
			delete(r.waiting, nonce)
			r.routes[other] = src
			r.routes[src] = other
			_, _ = r.conn.WriteTo(payload, net.UDPAddrFromAddrPort(other))
			_, _ = r.conn.WriteTo(payload, net.UDPAddrFromAddrPort(src))
			continue
		}
		r.waiting[nonce] = src
	}
}

// joinAsPeer 扮演"另一端"（私宅节点）连中继报同一 nonce。
func (r *fakeRelay) joinAsPeer(t *testing.T, nonce [relayNonceLen]byte) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(r.addr()))
	if err != nil {
		t.Fatalf("peer dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write(encodeRelayJoin(nonce)); err != nil {
		t.Fatalf("peer join: %v", err)
	}
	return c
}

// TestDialRelayPairsAndCarriesBytes 是 M2 的核心判据：DialRelay 返回的
// PunchedConn 能双向传字节 —— 这正是上层 QUIC/TLS 握手所需要的全部能力。
func TestDialRelayPairsAndCarriesBytes(t *testing.T) {
	relay := startFakeRelay(t, true)
	nonce := [relayNonceLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	peer := relay.joinAsPeer(t, nonce)
	// 消费掉中继回给对端的 ack。
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialRelay(ctx, Config{}, []netip.AddrPort{relay.addr()}, nonce)
	if err != nil {
		t.Fatalf("DialRelay: %v", err)
	}
	defer conn.Close()

	if conn.PeerAddr.String() != relay.addr().String() {
		t.Fatalf("PeerAddr=%s want relay %s", conn.PeerAddr, relay.addr())
	}

	ackBuf := make([]byte, 64)
	if _, err := peer.Read(ackBuf); err != nil {
		t.Fatalf("peer read ack: %v", err)
	}

	// 客户端 → 节点方向（上层就是这样写的：WriteTo(PeerAddr)）。
	payload := []byte("CLIENT_TO_NODE")
	if _, err := conn.WriteTo(payload, conn.PeerAddr.UDPAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("got %q want %q", buf[:n], payload)
	}

	// 回程：节点 → 客户端。握手要跑通，回程必须通。
	reply := []byte("NODE_TO_CLIENT")
	if _, err := peer.Write(reply); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err = conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf[:n], reply) {
		t.Fatalf("got %q want %q", buf[:n], reply)
	}
}

// TestDialRelayTimesOutWhenPeerNeverJoins：对端不来时必须超时失败，
// 而不是把一条没对接的管道交给上层（那会让失败更慢且归类错位）。
func TestDialRelayTimesOutWhenPeerNeverJoins(t *testing.T) {
	relay := startFakeRelay(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	conn, err := DialRelay(ctx, Config{}, []netip.AddrPort{relay.addr()}, [relayNonceLen]byte{9})
	if err == nil {
		conn.Close()
		t.Fatal("expected timeout, got a conn")
	}
}

// TestDialRelayNoAddress：空地址表直接报错（对应"未配中继"，调用方据此不回退）。
func TestDialRelayNoAddress(t *testing.T) {
	_, err := DialRelay(context.Background(), Config{}, nil, [relayNonceLen]byte{1})
	if err == nil {
		t.Fatal("expected error for empty relay list")
	}
}

// TestDialRelayFallsThroughToSecondRelay：首台不可用时试下一台（爆炸半径缓解，
// 设计 §6.1 的"多台中继 + 客户端多候选"）。
func TestDialRelayFallsThroughToSecondRelay(t *testing.T) {
	dead := netip.MustParseAddrPort("127.0.0.1:1") // 无人监听
	good := startFakeRelay(t, true)
	nonce := [relayNonceLen]byte{5}
	good.joinAsPeer(t, nonce)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	conn, err := DialRelay(ctx, Config{}, []netip.AddrPort{dead, good.addr()}, nonce)
	if err != nil {
		t.Fatalf("DialRelay: %v", err)
	}
	defer conn.Close()
	if conn.PeerAddr.String() != good.addr().String() {
		t.Fatalf("PeerAddr=%s want %s", conn.PeerAddr, good.addr())
	}
}

// TestRelayJoinWireFormat 钉死 20 字节线格式（§3.5.4），
// 与 otun-relay 仓必须逐字节一致。
func TestRelayJoinWireFormat(t *testing.T) {
	nonce := [relayNonceLen]byte{0xde, 0xad, 0xbe, 0xef}
	out := encodeRelayJoin(nonce)
	if len(out) != 20 {
		t.Fatalf("join len %d want 20", len(out))
	}
	if string(out[:4]) != "OTRL" {
		t.Fatalf("magic %q want OTRL", out[:4])
	}
	if !bytes.Equal(out[4:], nonce[:]) {
		t.Fatalf("nonce mismatch")
	}
	if !isRelayJoinAck(out, nonce) {
		t.Fatal("ack check should accept our own join echoed back")
	}
	if isRelayJoinAck(out, [relayNonceLen]byte{0xff}) {
		t.Fatal("ack check must reject a different nonce")
	}
	if isRelayJoinAck(out[:19], nonce) {
		t.Fatal("ack check must reject a short datagram")
	}
}

// TestPunchTracedNoRelayWhenEmpty 锁住硬约束 1：会合面没下发中继地址时，
// 回退分支一行都不执行 —— 错误原文与 trace 归类与改动前一致。
func TestPunchTracedNoRelayWhenEmpty(t *testing.T) {
	trace := NewTrace("r", "hysteria2")
	trace.Fail(FailStagePunch, errPunchForTest{})
	trace.RelayFailed(errPunchForTest{})

	if trace.RelayUsed {
		t.Fatal("relay_used must stay false")
	}
	// 硬约束 2：中继结果不得覆盖真实卡点。
	if trace.FailStage != FailStagePunch {
		t.Fatalf("fail_stage=%q want punch", trace.FailStage)
	}
	if trace.ErrorMsg != "punch failed" {
		t.Fatalf("error_msg=%q must stay the punch error", trace.ErrorMsg)
	}
}

type errPunchForTest struct{}

func (errPunchForTest) Error() string { return "punch failed" }
