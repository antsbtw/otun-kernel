package tuic_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/protocol/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	tuicnode "github.com/antsbtw/otun-s/node/tuicnode"
)

// TestTUICRealmOutboundEndToEnd drives the KERNEL's own TUIC outbound (built
// from option.TUICOutboundOptions with a Realm block) over the loopback realm
// harness to an otun-s tuicnode egress, and asserts a proxied round-trip.
//
// This is the runtime proof the kernel realm WIRING is correct — option →
// otunrealm.BuildConfig → overlay/tuic.Dial → punched QUIC — not just that it
// compiles. The egress node + rendezvous + STUN are otun-s's already-proven
// loopback components; only the dialer is the kernel's.
func TestTUICRealmOutboundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "kernel-tuic-token"
	const realmID = "kernel-tuic"
	uuid := [16]byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	const uuidStr = "deadbeef-0102-0304-0506-0708090a0b0c"
	const password = "kernel-tuic-pw"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// --- loopback peers (otun-s proven components) ---
	target := realmtest.EchoTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)
	certPEM, keyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	// --- egress: otun-s tuicnode behind the rendezvous ---
	node, err := tuicnode.New(tuicnode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		TLSConfig:  realmtest.NodeServerTLS(t, ctx, certPEM, keyPEM),
		UUID:       uuid, Password: password,
		Logger: realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new tuicnode: %v", err)
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

	// --- the KERNEL outbound under test, configured purely via options.Realm ---
	outboundCtx := realmtest.ServicesContext(ctx)
	ob, err := tuic.NewOutbound(outboundCtx, nil, realmtest.Logger(), "tuic-realm-out", option.TUICOutboundOptions{
		UUID:     uuidStr,
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
		t.Fatalf("kernel tuic NewOutbound: %v", err)
	}
	t.Cleanup(func() { _ = common.Close(ob) })

	conn, err := ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(target.String()))
	if err != nil {
		t.Fatalf("kernel outbound DialContext: %v", err)
	}
	defer conn.Close()

	// Through TUIC-over-realm, the node forwards to the echo target and back.
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
	t.Logf("kernel TUIC-realm outbound round-trip OK: ping -> %s", got)
}
