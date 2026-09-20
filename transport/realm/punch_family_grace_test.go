package realm

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 最小 STUN 服务端:收 Binding Request 就回 Binding Success + XOR-MAPPED-ADDRESS(只支持 v4)。
// 用于把"一族秒回、另一族黑洞"的形态摆出来,验证 discoverFamilies 不再陪慢族跑满重试。
func serveStunV4(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0001 {
				continue
			}
			src := from.AddrPort()
			ip4 := src.Addr().As4()
			// XOR-MAPPED-ADDRESS: 0x0020, len 8, family 0x01, xport, xaddr
			attr := make([]byte, 12)
			binary.BigEndian.PutUint16(attr[0:2], 0x0020)
			binary.BigEndian.PutUint16(attr[2:4], 8)
			attr[5] = 0x01
			binary.BigEndian.PutUint16(attr[6:8], src.Port()^0x2112)
			magic := []byte{0x21, 0x12, 0xA4, 0x42}
			for i := 0; i < 4; i++ {
				attr[8+i] = ip4[i] ^ magic[i]
			}
			resp := make([]byte, 20+len(attr))
			binary.BigEndian.PutUint16(resp[0:2], 0x0101)
			binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
			copy(resp[4:20], buf[4:20]) // magic cookie + transaction id 原样带回
			copy(resp[20:], attr)
			_, _ = conn.WriteToUDP(resp, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// 黑洞:监听但永不回复。
func blackholeUDP(t *testing.T, network string, ip net.IP) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("listen %s: %v", network, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := conn.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestDiscoverFamiliesDoesNotWaitForBlackholedFamily(t *testing.T) {
	stun4 := serveStunV4(t)
	stun6 := blackholeUDP(t, "udp6", net.IPv6loopback)
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no ipv6 loopback: %v", err)
	}
	families := []*familyConn{
		{family: "v4", ipv4: true, conn: c4},
		{family: "v6", ipv4: false, conn: c6},
	}
	cfg := Config{
		STUNServers: []string{stun4.String(), stun6.String()},
		Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
			return nil, nil
		},
	}
	start := time.Now()
	surviving, union, err := discoverFamilies(context.Background(), cfg, families)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("discoverFamilies: %v", err)
	}
	if len(surviving) != 1 || surviving[0].family != "v4" {
		t.Fatalf("expected only v4 to survive, got %d (%v)", len(surviving), surviving)
	}
	if len(union) != 1 || !union[0].Addr().Is4() {
		t.Fatalf("expected one v4 reflexive address, got %v", union)
	}
	// 老逻辑要陪 v6 黑洞跑满 0.5+2+4s;新逻辑 = v4 回包 + familyDiscoverGrace,应远小于 1.5s
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("took %v, slow family was not abandoned", elapsed)
	}
	t.Logf("elapsed=%v surviving=%s union=%v", elapsed, surviving[0].family, union)
}

func TestDiscoverFamiliesBothFast(t *testing.T) {
	stun4 := serveStunV4(t)
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	families := []*familyConn{{family: "v4", ipv4: true, conn: c4}}
	cfg := Config{STUNServers: []string{stun4.String()}, Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) { return nil, nil }}
	surviving, union, err := discoverFamilies(context.Background(), cfg, families)
	if err != nil || len(surviving) != 1 || len(union) != 1 {
		t.Fatalf("single fast family must survive: %v %v %v", err, surviving, union)
	}
}
