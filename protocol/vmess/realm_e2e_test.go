package vmess_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	vmessnode "github.com/antsbtw/otun-s/node/vmessnode"
)

// TestVMessRealmOutboundEndToEnd drives the KERNEL's VMess outbound (realm block)
// over the loopback harness to an otun-s vmessnode egress. VMess provides its own
// auth/ciphering; the WrapStream (QUIC) TLS is the only TLS.
func TestVMessRealmOutboundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "kernel-vmess-token"
	const realmID = "kernel-vmess"
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	target := realmtest.EchoTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)
	certPEM, keyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	node, err := vmessnode.New(vmessnode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		WrapTLS:    realmtest.NodeServerTLS(t, ctx, certPEM, keyPEM),
		UUID:       uuid, AlterId: 0,
		Handler: realmtest.EgressHandler,
		Logger:  realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new vmessnode: %v", err)
	}
	nodeUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("node udp: %v", err)
	}
	if err := node.Start(ctx, nodeUDP); err != nil {
		t.Fatalf("node start: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	realmtest.WaitRegistered(t, engine, realmID, 8*time.Second)

	outboundCtx := realmtest.ServicesContext(ctx)
	ob, err := vmess.NewOutbound(outboundCtx, nil, realmtest.Logger(), "vmess-realm-out", option.VMessOutboundOptions{
		UUID:     uuid,
		Security: "auto",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "iptv.local",
				Insecure:   true,
				ALPN:       badoption.Listable[string]{"h3"},
			},
		},
		Realm: &option.RealmOptions{
			ServerURL:   rvURL,
			Token:       token,
			RealmID:     realmID,
			STUNServers: badoption.Listable[string]{stun.String()},
		},
	})
	if err != nil {
		t.Fatalf("kernel vmess NewOutbound: %v", err)
	}
	t.Cleanup(func() { _ = common.Close(ob) })

	conn, err := ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(target.String()))
	if err != nil {
		t.Fatalf("kernel outbound DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("egress round-trip got %q want PING", got)
	}
	t.Logf("kernel VMess-realm outbound round-trip OK: ping -> %s", got)
}
