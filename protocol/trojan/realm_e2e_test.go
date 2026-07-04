package trojan_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	trojannode "github.com/antsbtw/otun-s/node/trojannode"
)

// TestTrojanRealmOutboundEndToEnd drives the KERNEL's Trojan outbound (realm
// block) over the loopback harness to an otun-s trojannode egress. Unlike TUIC,
// Trojan is TCP-family: it rides a WrapStream (QUIC) reliable conn that carries
// exactly one stream, so the kernel outbound punches a FRESH hole per
// DialContext. This test proves that per-dial punch path at runtime.
func TestTrojanRealmOutboundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "kernel-trojan-token"
	const realmID = "kernel-trojan"
	const password = "kernel-trojan-pw"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	target := realmtest.EchoTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)
	certPEM, keyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	// --- egress: otun-s trojannode (WrapStream TLS server + egress handler) ---
	node, err := trojannode.New(trojannode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		WrapTLS:    realmtest.NodeServerTLS(t, ctx, certPEM, keyPEM),
		Password:   password,
		Handler:    realmtest.EgressHandler,
		Logger:     realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new trojannode: %v", err)
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

	// --- the KERNEL Trojan outbound under test ---
	outboundCtx := realmtest.ServicesContext(ctx)
	ob, err := trojan.NewOutbound(outboundCtx, nil, realmtest.Logger(), "trojan-realm-out", option.TrojanOutboundOptions{
		Password: password,
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
		t.Fatalf("kernel trojan NewOutbound: %v", err)
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
	t.Logf("kernel Trojan-realm outbound round-trip OK: ping -> %s", got)
}
