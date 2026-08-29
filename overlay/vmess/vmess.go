// Package vmess is OTun's glue for running the VMess transport over a
// realm-punched hole — a TCP-family overlay (DEV M5 family) that follows the
// same substitution pattern proved by overlay/reality.
//
// VMess is TCP-family: it needs a reliable, ordered net.Conn, not the raw
// datagram hole. M4's WrapStream provides that (a QUIC stream over the hole,
// presented as net.Conn); this glue feeds that net.Conn to the VMess client.
// Unlike Reality, VMess carries its OWN authenticated encryption, so it runs
// directly over the WrapStream conn with NO extra inner TLS — the outer
// transport (QUIC, already TLS) is the only TLS in the path.
//
// The VMess engine is reused from sing-vmess as a LIBRARY (no fork): we build a
// vmess.Client and call DialEarlyConn over the wrapped stream, exactly as
// sing-box's vmess outbound does (minus the optional outer TLS, which our
// WrapStream already provides).
package vmess

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/transport/realm"
	"github.com/antsbtw/otun-s/underlay"

	"github.com/sagernet/sing-vmess"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a VMess-over-realm client. Realm carries the rendezvous
// coordinates (protocol-agnostic); WrapTLS is the OUTER QUIC/TLS for the
// reliable stream; the rest are VMess's own credentials, passed straight
// through to the sing-vmess engine.
type Options struct {
	// Realm is the rendezvous + STUN config used to punch the hole.
	Realm   realm.Config
	RealmID string

	// WrapTLS is the QUIC/TLS client config for the WrapStream layer (the
	// reliable stream that carries VMess). Caller-built; this is the OUTER
	// transport's TLS. VMess itself needs no inner TLS.
	WrapTLS aTLS.Config

	// UUID is the VMess user id (the canonical UUID string; sing-vmess parses
	// it, falling back to a UUIDv5 derivation for non-UUID strings).
	UUID string
	// Security is the VMess cipher: "auto" (default), "aes-128-gcm",
	// "chacha20-poly1305", "none", "zero", etc.
	Security string
	// AlterId selects legacy alterId users; 0 (AEAD-only) for modern VMess.
	AlterId int

	// Mode 选打洞路径（探针专用）。零值 = realm.ModeNormal，生产不设即原行为。
	Mode realm.PunchMode

	// Trace 探针注入的埋点。非 nil 时用它；nil 时保持 env 驱动的 realm.Session。
	Trace *realm.Trace
}

// Client is a VMess overlay bound to one punched+wrapped hole. Build with Dial.
type Client struct {
	inner *vmess.Client
	wrap  net.Conn // the underlying WrapStream conn (closed with this)
}

// Dial punches a hole to RealmID, wraps it in a reliable QUIC stream, then
// stands up a VMess client over that stream. The returned Client's DialConn
// opens proxied streams that exit the punched peer (the egress node) — the
// punch and the wrap are invisible to the VMess engine.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("vmess-over-realm: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.UUID == "" {
		return nil, E.New("vmess-over-realm: UUID is required")
	}
	security := opts.Security
	if security == "" {
		security = "auto"
	}
	// 埋点：未开启时 trace 为 nil，以下所有 trace 调用都是 no-op（生产路径零影响）。
	trace := realm.SessionOr(opts.Trace, opts.RealmID, "vmess")
	punched, err := realm.PunchTracedWithMode(ctx, opts.Realm, opts.RealmID, trace, opts.Mode)
	if err != nil {
		// 阶段归类已在 PunchTraced 内部完成，这里只负责输出。
		realm.Emit(opts.Realm.Logger, trace)
		return nil, E.Cause(err, "punch")
	}
	// M4: reliable stream over the hole.
	wrap, err := underlay.WrapStreamFromPunch(ctx, underlay.FromPunch(punched), opts.WrapTLS)
	if err != nil {
		_ = punched.Close()
		realm.FailAndEmit(opts.Realm.Logger, trace, realm.FailStageHandshake, err)
		return nil, E.Cause(err, "wrap stream")
	}
	inner, err := vmess.NewClient(opts.UUID, security, opts.AlterId)
	if err != nil {
		_ = wrap.Close()
		realm.FailAndEmit(opts.Realm.Logger, trace, realm.FailStageHandshake, err)
		return nil, E.Cause(err, "create vmess client")
	}
	// ★ VMess 无独立握手（认证随首个请求发出）：wrap 建立即隧道建立。
	realm.HandshakeDoneAndEmit(opts.Realm.Logger, trace)
	return &Client{inner: inner, wrap: wrap}, nil
}

// DialConn opens a TCP-like proxied stream to destination through the VMess
// tunnel (which itself rides the wrapped, punched hole). The VMess request
// header is sent lazily with the first write (DialEarlyConn), so no extra
// round-trip is paid here.
//
// NOTE: one wrapped stream carries one VMess session, so DialConn is
// single-use per Client — mirrors the one-hole-one-connection model of the
// other TCP-family overlays.
func (c *Client) DialConn(_ context.Context, destination M.Socksaddr) (net.Conn, error) {
	return c.inner.DialEarlyConn(c.wrap, destination), nil
}

// Close tears down the VMess session and the underlying wrapped hole.
func (c *Client) Close() error {
	return c.wrap.Close()
}
