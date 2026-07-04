// Package realmtest is the in-process loopback harness for the kernel's
// realm-over-* outbounds. It stands up — all on 127.0.0.1, no VPS, no Xcode, no
// gomobile — the four moving parts a realm dial needs as peers:
//
//	STUN()        a minimal STUN responder (so punch can discover a candidate).
//	Rendezvous()  a real OTun-S control plane (core.Engine + wire router) over httptest.
//	EchoTarget()  a TCP "internet host" that uppercases bytes, the egress destination.
//	Services()    a context carrying the fake HTTPClientManager / DNSRouter the
//	              kernel's otunrealm.BuildConfig pulls via service.FromContext.
//
// The harness is the SAME loopback rig the otun-s overlay/node tests already
// prove out; the kernel tests reuse it but drive the dial through the kernel's
// OWN outbound (option.RealmOptions → NewOutbound → DialContext) instead of the
// otun-s overlay client. That single substitution is what these tests verify:
// the kernel's realm WIRING, at runtime, not just at compile time.
//
// Egress nodes (node/tuicnode, node/trojannode, …) are started by each test
// directly from otun-s, since their New/Start signatures differ per protocol.
package realmtest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/antsbtw/otun-s/core"
	"github.com/antsbtw/otun-s/wire"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"

	"github.com/miekg/dns"
)

// Resolver is the trivial loopback resolver: STUN servers are passed as IP
// literals, so it just parses the host. The kernel's realm path uses this via
// the DNSRouter stub below; it is never asked to resolve a real name.
func Resolver(_ context.Context, host string, _, _ bool) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(host)}, nil
}

// Rendezvous starts an in-process OTun-S control plane authorizing `token` and
// returns its base URL and the engine (for RealmRegistered polling).
func Rendezvous(t *testing.T, token string) (string, *core.Engine) {
	t.Helper()
	engine := core.New(map[string]*core.User{token: {Name: "node", MaxRealms: 0}})
	rv := httptest.NewServer(wire.NewHandler(engine, nil).Router())
	t.Cleanup(rv.Close)
	return rv.URL, engine
}

// WaitRegistered blocks until the egress node has registered realmID on the
// rendezvous, or fails the test after timeout.
func WaitRegistered(t *testing.T, e *core.Engine, realmID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if e.RealmRegistered(realmID) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("node did not register in time")
}

// ServicesContext returns a context carrying the minimal services the kernel's
// otunrealm.BuildConfig resolves via service.FromContext: an HTTPClientManager
// (whose transport reaches the loopback rendezvous) and a DNSRouter (never
// actually queried, since STUN is by IP). Without these the realm path panics
// inside service.FromContext, so every kernel realm test must build on this.
func ServicesContext(ctx context.Context) context.Context {
	ctx = service.ContextWith[adapter.HTTPClientManager](ctx, fakeHTTPClientManager{})
	ctx = service.ContextWith[adapter.DNSRouter](ctx, fakeDNSRouter{})
	return ctx
}

// Logger returns a no-op context logger for outbound construction.
func Logger() log.ContextLogger { return logger.NOP() }

// --- fake services ---

type fakeHTTPTransport struct{}

func (fakeHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return http.DefaultTransport.RoundTrip(req)
}
func (fakeHTTPTransport) CloseIdleConnections() {}
func (fakeHTTPTransport) Reset()                {}

type fakeHTTPClientManager struct{}

func (fakeHTTPClientManager) ResolveTransport(_ context.Context, _ logger.ContextLogger, _ option.HTTPClientOptions) (adapter.HTTPTransport, error) {
	return fakeHTTPTransport{}, nil
}
func (fakeHTTPClientManager) DefaultTransport() adapter.HTTPTransport { return fakeHTTPTransport{} }
func (fakeHTTPClientManager) ResetNetwork()                          {}

// fakeDNSRouter satisfies adapter.DNSRouter but is never exercised on the
// loopback path (STUN by IP). Lookup falls back to parsing IP literals so any
// stray call still behaves.
type fakeDNSRouter struct{}

func (fakeDNSRouter) Start(adapter.StartStage) error { return nil }
func (fakeDNSRouter) Close() error                   { return nil }
func (fakeDNSRouter) Exchange(context.Context, *dns.Msg, adapter.DNSQueryOptions) (*dns.Msg, error) {
	return nil, nil
}
func (fakeDNSRouter) Lookup(_ context.Context, domain string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(domain); err == nil {
		return []netip.Addr{addr}, nil
	}
	return nil, nil
}
func (fakeDNSRouter) ClearCache()                                       {}
func (fakeDNSRouter) LookupReverseMapping(netip.Addr) (string, bool)    { return "", false }
func (fakeDNSRouter) ResetNetwork()                                     {}

// --- self-signed cert + sing-box TLS builders (mirror otun-s overlay tests) ---

// SelfSignedCert returns a PEM cert/key for host (CN + SAN), CA-capable, 24h.
func SelfSignedCert(t *testing.T, host string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// NodeServerTLS builds the egress node's WrapStream/QUIC server TLS from a
// self-signed cert (ServerName iptv.local, ALPN h3) — the server side the kernel
// outbound's client TLS validates against (with Insecure).
func NodeServerTLS(t *testing.T, ctx context.Context, certPEM, keyPEM string) sbtls.ServerConfig {
	t.Helper()
	cfg, err := sbtls.NewSTDServer(ctx, logger.NOP(), option.InboundTLSOptions{
		Enabled: true, ServerName: "iptv.local", ALPN: []string{"h3"},
		Certificate: []string{certPEM}, Key: []string{keyPEM},
	})
	if err != nil {
		t.Fatalf("server tls: %v", err)
	}
	if err := cfg.Start(); err != nil {
		t.Fatalf("server tls start: %v", err)
	}
	return cfg
}

// --- echo target (the "internet host") ---

// EchoTarget starts a loopback TCP server that uppercases the bytes it receives
// and returns its address — the destination the kernel outbound asks the egress
// node to proxy to.
func EchoTarget(t *testing.T) *net.TCPAddr {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						for i := 0; i < n; i++ {
							if buf[i] >= 'a' && buf[i] <= 'z' {
								buf[i] -= 32
							}
						}
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr)
}

// EgressHandler is the ConnHandler shared by the TCP-family egress nodes
// (trojannode / ssnode / vmessnode / realitynode): it dials the destination the
// client requested and splices bytes both ways, making the node a real egress.
// Signature matches node/*.ConnHandler = func(ctx, net.Conn, M.Socksaddr).
func EgressHandler(ctx context.Context, conn net.Conn, destination M.Socksaddr) {
	defer conn.Close()
	out, err := (&net.Dialer{}).DialContext(ctx, "tcp", destination.String())
	if err != nil {
		return
	}
	defer out.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(out, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, out); done <- struct{}{} }()
	<-done
}

// --- loopback STUN ---

// STUN starts a minimal STUN responder on loopback and returns its addr:port.
func STUN(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("stun listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint32(buf[4:8]) != 0x2112A442 {
				continue
			}
			var txid [12]byte
			copy(txid[:], buf[8:20])
			_, _ = conn.WriteToUDPAddrPort(buildSTUNResponse(txid, from), from)
		}
	}()
	la := conn.LocalAddr().(*net.UDPAddr)
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(la.Port))
}

func buildSTUNResponse(txid [12]byte, source netip.AddrPort) []byte {
	const magic = 0x2112A442
	ip4 := source.Addr().As4()
	attr := make([]byte, 4+8)
	binary.BigEndian.PutUint16(attr[0:2], 0x0020)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[5] = 0x01
	binary.BigEndian.PutUint16(attr[6:8], source.Port()^uint16(magic>>16))
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magic)
	copy(key[4:], txid[:])
	for i := 0; i < 4; i++ {
		attr[8+i] = ip4[i] ^ key[i]
	}
	msg := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], magic)
	copy(msg[8:20], txid[:])
	copy(msg[20:], attr)
	return msg
}
