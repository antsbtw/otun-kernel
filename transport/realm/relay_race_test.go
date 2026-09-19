package realm

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// newDeadFamily 造一只不会打洞成功的 family：给它一个黑洞对端地址（本机随机端口，
// 无人应答），racePunch 会一直等到 ctx 取消。模拟对称 NAT 下打洞打不通。
func newDeadFamily(t *testing.T) (*familyConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// 黑洞：另开一只 socket 拿到一个真实但无人读的地址。
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	dead := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = sink.Close() // 关掉 → 发过去的打洞包无人应答
	return &familyConn{family: "v4", ipv4: true, conn: conn}, netip.AddrPortFrom(dead.Addr().Unmap(), dead.Port())
}

// TestRacePunchAndRelay_RelayWinsWhenPunchDead 是 S3 的核心判据：
// 对称 NAT 下打洞打不通时，中继必须**几百毫秒内**接管，而不是等满 punchTimeout。
func TestRacePunchAndRelay_RelayWinsWhenPunchDead(t *testing.T) {
	relay := startFakeRelay(t, true)
	nonce := [relayNonceLen]byte{9, 9, 9, 3}
	peer := relay.joinAsPeer(t, nonce) // 私宅节点侧已在中继就位
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))

	fam, deadPeer := newDeadFamily(t)
	meta := squic.PunchMetadata{Nonce: nonce}

	// ctx 给足 30s：本测试要证明中继在**远早于**这个上限时就赢，靠的是它自己
	// 几百 ms 配对成功，而不是靠 ctx 超时。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	conn, viaRelay, err := racePunchAndRelay(ctx, Config{}, []*familyConn{fam},
		[]netip.AddrPort{deadPeer}, []netip.AddrPort{relay.addr()}, meta)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("race returned error: %v", err)
	}
	if !viaRelay {
		t.Fatalf("expected relay to win, got punch")
	}
	defer conn.Close()
	if conn.PeerAddr.String() != relay.addr().String() {
		t.Fatalf("PeerAddr=%s want relay %s", conn.PeerAddr, relay.addr())
	}
	if elapsed > 3*time.Second {
		t.Fatalf("relay took %v — did not win concurrently (punchTimeout is 10s)", elapsed)
	}

	// 中继赢得的连接必须能双向传字节（上层握手所需）。
	_, _ = peer.Read(make([]byte, 64)) // 吃掉 ack
	if _, err := conn.WriteTo([]byte("PING"), conn.PeerAddr.UDPAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := peer.Read(buf)
	if err != nil || string(buf[:n]) != "PING" {
		t.Fatalf("peer read = %q, %v", buf[:n], err)
	}
}

// TestRacePunchAndRelay_BothFailReturnsPunchError：两路都失败时返回的必须以打洞错误
// 为主（classifyError / trace 归类依赖它），而不是中继错误。
func TestRacePunchAndRelay_BothFailReturnsPunchError(t *testing.T) {
	relay := startFakeRelay(t, false) // 中继永不配对
	fam, deadPeer := newDeadFamily(t)
	nonce := [relayNonceLen]byte{7, 7, 7, 1}
	meta := squic.PunchMetadata{Nonce: nonce}

	// 短 ctx：两路都会失败（打洞黑洞 + 中继不 ack），靠 ctx 超时收敛。
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	conn, viaRelay, err := racePunchAndRelay(ctx, Config{}, []*familyConn{fam},
		[]netip.AddrPort{deadPeer}, []netip.AddrPort{relay.addr()}, meta)
	if err == nil {
		_ = conn.Close()
		t.Fatal("expected error when both punch and relay fail")
	}
	if viaRelay {
		t.Fatal("viaRelay must be false on total failure")
	}
	// 错误里应含打洞卡点语义（"realm punch" 是 racePunch 的错误前缀）。
	if !containsAny(err.Error(), "punch", "deadline", "timeout") {
		t.Fatalf("error %q should carry punch failure as primary cause", err.Error())
	}
}

// TestGuessNATTypeGate 锁定 S3 的门槛判据：只有多个反射地址端口不一致才算对称 NAT。
func TestGuessNATTypeGate(t *testing.T) {
	ap := func(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }
	cases := []struct {
		name  string
		srflx []netip.AddrPort
		want  NATTypeGuess
	}{
		{"single addr unknown", []netip.AddrPort{ap("1.2.3.4:5000")}, NATTypeUnknown},
		{"consistent cone", []netip.AddrPort{ap("1.2.3.4:5000"), ap("1.2.3.4:5000")}, NATTypeCone},
		{"different port symmetric", []netip.AddrPort{ap("1.2.3.4:5000"), ap("1.2.3.4:5001")}, NATTypeSymmetric},
		{"different ip symmetric", []netip.AddrPort{ap("1.2.3.4:5000"), ap("1.2.3.5:5000")}, NATTypeSymmetric},
		{"empty unknown", nil, NATTypeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := guessNATType(tc.srflx); got != tc.want {
				t.Fatalf("guessNATType(%v) = %v, want %v", tc.srflx, got, tc.want)
			}
		})
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}
