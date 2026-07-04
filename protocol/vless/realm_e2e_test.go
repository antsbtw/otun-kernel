//go:build with_utls

// Reality (VLESS+Reality) over realm needs the uTLS engine, gated behind
// with_utls. Without the tag this file is skipped and `go test ./...` stays green.
package vless_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	realitynode "github.com/antsbtw/otun-s/node/realitynode"
)

// TestRealityRealmOutboundEndToEnd drives the KERNEL's VLESS+Reality outbound
// (the two-TLS realm case) over the loopback harness to an otun-s realitynode.
// Inner Reality TLS comes from the `tls.reality` block; outer WrapStream (QUIC)
// TLS from `realm.wrap_tls`. The overlay writes the VLESS header; the node reads
// the destination and egresses to an arbitrary target. This is the runtime proof
// the kernel's most complex realm wiring (two TLS layers + VLESS) is correct.
func TestRealityRealmOutboundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "kernel-reality-token"
	const realmID = "kernel-reality"
	const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
	const handshakeSNI = "www.example-handshake.com"
	const shortID = "0123456789abcdef"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	privB64, pubB64 := realmtest.RealityKeypair(t)
	handshakeAddr := realmtest.TLSHandshakeTarget(t, handshakeSNI)

	target := realmtest.EchoTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)

	// Outer WrapStream TLS (self-signed; client validates with Insecure).
	wrapCertPEM, wrapKeyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	// --- egress: realitynode (inner Reality server + VLESS read + egress) ---
	node, err := realitynode.New(realitynode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		WrapTLS:    realmtest.NodeServerTLS(t, ctx, wrapCertPEM, wrapKeyPEM),
		Reality:    realmtest.RealityServerTLS(t, ctx, privB64, shortID, handshakeSNI, handshakeAddr),
		UUID:       uuid,
		Handler:    realmtest.EgressHandler,
		Logger:     realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new realitynode: %v", err)
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

	// --- the KERNEL VLESS+Reality outbound under test ---
	outboundCtx := realmtest.ServicesContext(ctx)
	ob, err := vless.NewOutbound(outboundCtx, nil, realmtest.Logger(), "reality-realm-out", option.VLESSOutboundOptions{
		UUID: uuid,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			// INNER Reality TLS (server_name = borrowed-SNI handshake target).
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: handshakeSNI,
				UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{
					Enabled: true, PublicKey: pubB64, ShortID: shortID,
				},
			},
		},
		Realm: &option.RealmOptions{
			ServerURL:   rvURL,
			Token:       token,
			RealmID:     realmID,
			STUNServers: badoption.Listable[string]{stun.String()},
			// OUTER WrapStream (QUIC) TLS.
			WrapTLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "iptv.local",
				Insecure:   true,
				ALPN:       badoption.Listable[string]{"h3"},
			},
		},
	})
	if err != nil {
		t.Fatalf("kernel vless+reality NewOutbound: %v", err)
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
	t.Logf("kernel Reality-realm outbound round-trip OK: ping -> %s", got)
}
