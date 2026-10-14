package hysteria2

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/realm"
)

// 与 kernel transport/realm/punch_family_grace_test.go 同构:把"一族秒回、另一族黑洞"
// 的形态摆出来,验证 hy2 的 realmDiscoverFamilies 不再陪慢族跑满 STUN 重试。

// 最小 STUN 服务端:收 Binding Request 就回 Binding Success + XOR-MAPPED-ADDRESS(v4/v6 都支持)。
func serveStun(t *testing.T, network string, ip net.IP) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("listen %s: %v", network, err)
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
			addr := src.Addr().Unmap()
			// XOR 掩码 = magic cookie(4B) + transaction id(12B);v4 只用前 4 字节
			mask := buf[4:20]
			var raw []byte
			family := byte(0x01)
			if addr.Is4() {
				a := addr.As4()
				raw = a[:]
			} else {
				a := addr.As16()
				raw = a[:]
				family = 0x02
			}
			attr := make([]byte, 8+len(raw))
			binary.BigEndian.PutUint16(attr[0:2], 0x0020)
			binary.BigEndian.PutUint16(attr[2:4], uint16(4+len(raw)))
			attr[5] = family
			binary.BigEndian.PutUint16(attr[6:8], src.Port()^0x2112)
			for i := range raw {
				attr[8+i] = raw[i] ^ mask[i]
			}
			resp := make([]byte, 20+len(attr))
			binary.BigEndian.PutUint16(resp[0:2], 0x0101)
			binary.BigEndian.PutUint16(resp[2:4], uint16(len(attr)))
			copy(resp[4:20], buf[4:20])
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

func nopResolver(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	return nil, nil
}

func TestRealmDiscoverFamiliesDoesNotWaitForBlackholedFamily(t *testing.T) {
	stun4 := serveStun(t, "udp4", net.IPv4(127, 0, 0, 1))
	stun6 := blackholeUDP(t, "udp6", net.IPv6loopback)
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no ipv6 loopback: %v", err)
	}
	client := &Client{realmOptions: &realm.Options{
		STUNServers: []string{stun4.String(), stun6.String()},
		Resolver:    nopResolver,
	}}
	families := []*realmFamilyConn{
		{family: "v4", ipv4: true, conn: c4},
		{family: "v6", ipv4: false, conn: c6},
	}
	start := time.Now()
	surviving, union, err := client.realmDiscoverFamilies(context.Background(), families)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("realmDiscoverFamilies: %v", err)
	}
	if len(surviving) != 1 || surviving[0].family != "v4" {
		t.Fatalf("expected only v4 to survive, got %d", len(surviving))
	}
	if len(union) != 1 || !union[0].Addr().Is4() {
		t.Fatalf("expected one v4 reflexive address, got %v", union)
	}
	// 老逻辑要陪 v6 黑洞跑满 0.5+2+4s;新逻辑 = v4 回包 + realmFamilyDiscoverGrace,应远小于 1.5s
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("took %v, slow family was not abandoned", elapsed)
	}
	t.Logf("elapsed=%v surviving=%s union=%v", elapsed, surviving[0].family, union)
}

func TestRealmDiscoverFamiliesSingleFamily(t *testing.T) {
	stun4 := serveStun(t, "udp4", net.IPv4(127, 0, 0, 1))
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{realmOptions: &realm.Options{
		STUNServers: []string{stun4.String()},
		Resolver:    nopResolver,
	}}
	families := []*realmFamilyConn{{family: "v4", ipv4: true, conn: c4}}
	surviving, union, err := client.realmDiscoverFamilies(context.Background(), families)
	if err != nil || len(surviving) != 1 || len(union) != 1 {
		t.Fatalf("single fast family must survive: %v %v %v", err, surviving, union)
	}
}

// 只给 v6 STUN 时 v4 族必须退出、只剩 v6 —— iOS 调试开关「只走 v6」依赖这条行为
// (按 STUN 列表的地址族裁掉另一路 socket,不需要改打洞逻辑)。
func TestRealmDiscoverFamiliesV6OnlySTUNDropsV4(t *testing.T) {
	stun6 := serveStun(t, "udp6", net.IPv6loopback)
	c4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no ipv6 loopback: %v", err)
	}
	client := &Client{realmOptions: &realm.Options{
		STUNServers: []string{stun6.String()},
		Resolver:    nopResolver,
	}}
	families := []*realmFamilyConn{
		{family: "v4", ipv4: true, conn: c4},
		{family: "v6", ipv4: false, conn: c6},
	}
	start := time.Now()
	surviving, union, err := client.realmDiscoverFamilies(context.Background(), families)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("realmDiscoverFamilies: %v", err)
	}
	if len(surviving) != 1 || surviving[0].family != "v6" {
		t.Fatalf("expected only v6 to survive, got %d", len(surviving))
	}
	if len(union) != 1 || union[0].Addr().Is4() {
		t.Fatalf("expected one v6 reflexive address, got %v", union)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("took %v", elapsed)
	}
	t.Logf("elapsed=%v union=%v", elapsed, union)
}
