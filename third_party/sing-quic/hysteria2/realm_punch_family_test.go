package hysteria2

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-quic/hysteria2/realm"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// recordDialer 记录 ListenPacket 的本地地址族，不真正开 socket。
type recordDialer struct {
	N.Dialer
	ipv4, ipv6 int
}

func (d *recordDialer) ListenPacket(_ context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.Addr.Is4() {
		d.ipv4++
	} else {
		d.ipv6++
	}
	return &net.UDPConn{}, nil
}

func openFamilies(t *testing.T, punchFamily string) (*recordDialer, []*realmFamilyConn) {
	t.Helper()
	dialer := &recordDialer{}
	client := &Client{dialer: dialer, realmOptions: &realm.Options{PunchFamily: punchFamily}}
	families, err := client.realmOpenFamilies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return dialer, families
}

// K4：punch_family=v6 时连 v4 socket 都不开 —— STUN 域名解析回来的 v4、节点朝 v4 的打洞都落不到地。
func TestRealmPunchFamilyV6OnlyOpensV6(t *testing.T) {
	dialer, families := openFamilies(t, realm.PunchFamilyV6)
	if dialer.ipv4 != 0 || dialer.ipv6 != 1 {
		t.Fatalf("opened v4=%d v6=%d sockets, want v4=0 v6=1", dialer.ipv4, dialer.ipv6)
	}
	if len(families) != 1 || families[0].family != realm.PunchFamilyV6 || families[0].ipv4 {
		t.Fatalf("families = %+v, want only v6", families)
	}
}

func TestRealmPunchFamilyV4OnlyOpensV4(t *testing.T) {
	dialer, families := openFamilies(t, realm.PunchFamilyV4)
	if dialer.ipv4 != 1 || dialer.ipv6 != 0 {
		t.Fatalf("opened v4=%d v6=%d sockets, want v4=1 v6=0", dialer.ipv4, dialer.ipv6)
	}
	if len(families) != 1 || families[0].family != realm.PunchFamilyV4 || !families[0].ipv4 {
		t.Fatalf("families = %+v, want only v4", families)
	}
}

func TestRealmPunchFamilyDefaultOpensBoth(t *testing.T) {
	dialer, families := openFamilies(t, "")
	if dialer.ipv4 != 1 || dialer.ipv6 != 1 || len(families) != 2 {
		t.Fatalf("opened v4=%d v6=%d (%d families), want both", dialer.ipv4, dialer.ipv6, len(families))
	}
}
