package shadowsocks_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	ssnode "github.com/antsbtw/otun-s/node/ssnode"
)

// TestShadowsocksRealmOutboundEndToEnd drives the KERNEL's Shadowsocks outbound
// (realm block) over the loopback harness to an otun-s ssnode egress. SS's own
// AEAD ciphers the stream; the WrapStream (QUIC) TLS is the only TLS. Client and
// node share the same SS library (sing-shadowsocks v1) and method — the real
// pitfall the otun-s real-machine run surfaced.
func TestShadowsocksRealmOutboundEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "kernel-ss-token"
	const realmID = "kernel-ss"
	const method = "aes-128-gcm"
	const password = "kernel-ss-pw"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	target := realmtest.EchoTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)
	certPEM, keyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	node, err := ssnode.New(ssnode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		WrapTLS:    realmtest.NodeServerTLS(t, ctx, certPEM, keyPEM),
		Method:     method, Password: password,
		Handler: realmtest.EgressHandler,
		Logger:  realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new ssnode: %v", err)
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
	ob, err := shadowsocks.NewOutbound(outboundCtx, nil, realmtest.Logger(), "ss-realm-out", option.ShadowsocksOutboundOptions{
		Method:   method,
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
		t.Fatalf("kernel ss NewOutbound: %v", err)
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
	t.Logf("kernel Shadowsocks-realm outbound round-trip OK: ping -> %s", got)
}
