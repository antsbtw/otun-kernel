//go:build with_utls

// Reality test builders, gated behind with_utls (the uTLS engine Reality needs).
// Kept in a separate file so the base harness builds without the tag.
package realmtest

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"testing"

	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	"golang.org/x/crypto/curve25519"
)

// RealityKeypair returns a base64 (raw-url) x25519 private/public keypair for
// Reality.
func RealityKeypair(t *testing.T) (privB64, pubB64 string) {
	t.Helper()
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(priv[:]),
		base64.RawURLEncoding.EncodeToString(pub)
}

// RealityServerTLS builds the egress node's INNER Reality server TLS (borrows
// identity from the handshake target).
func RealityServerTLS(t *testing.T, ctx context.Context, privB64, shortID, serverName string, handshake netip.AddrPort) sbtls.ServerConfig {
	t.Helper()
	cfg, err := sbtls.NewServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     handshake.Addr().String(),
					ServerPort: handshake.Port(),
				},
			},
			PrivateKey: privB64,
			ShortID:    []string{shortID},
		},
	})
	if err != nil {
		t.Fatalf("reality server: %v", err)
	}
	if err := cfg.Start(); err != nil {
		t.Fatalf("reality server start: %v", err)
	}
	return cfg
}

// TLSHandshakeTarget starts the real TLS site Reality borrows identity from
// (borrowed-SNI must be an IP-reachable host serving valid TLS for serverName).
func TLSHandshakeTarget(t *testing.T, serverName string) netip.AddrPort {
	t.Helper()
	certPEM, keyPEM := SelfSignedCert(t, serverName)
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("handshake target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	la := ln.Addr().(*net.TCPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(la.Port))
}
