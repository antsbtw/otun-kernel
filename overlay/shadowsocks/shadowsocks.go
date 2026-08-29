// Package shadowsocks is OTun's glue for running the Shadowsocks (TCP) overlay
// over a realm-punched hole — another TCP-family proof riding M4's WrapStream
// (alongside overlay/reality).
//
// TCP-family overlays (Reality, Trojan, SS-TCP, VMess) need a reliable, ordered
// net.Conn, not the raw datagram hole. M4's WrapStreamFromPunch provides exactly
// that: a QUIC stream over the punched hole, presented as net.Conn. Shadowsocks
// then layers its own AEAD framing on top of that stream — the SAME net.Conn
// entry point Reality used, with the SS engine substituted in.
//
// The Shadowsocks engine is reused as a LIBRARY (no fork): sing-shadowsocks
// (v1) shadowaead.Method does the client-side AEAD encode. We use v1 (not v2)
// on BOTH ends — its shadowaead.Service is the matching server decoder — so the
// response (server→client) AEAD framing decodes correctly. (v2's Method is
// client-only with no server, and pairing v2-client with v1-server left the
// response direction undecodable.) We feed Method the punched+wrapped net.Conn;
// DialEarlyConn turns it into an SS proxied stream to a target.
//
// CONTEXT §10 caveat: the OUTER transport here is WrapStream (QUIC, already
// encrypted/authenticated), so SS's own AEAD is a second, inner layer — no extra
// TLS is needed. If this underlay crosses the GFW, the wrap (QUIC) must carry
// obfs; that is a DEPLOYMENT concern, out of scope here.
package shadowsocks

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/transport/realm"
	"github.com/antsbtw/otun-s/underlay"

	"github.com/sagernet/sing-shadowsocks/shadowaead"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

// Options configures a Shadowsocks-over-realm client.
type Options struct {
	// Realm is the rendezvous + STUN config used to punch the hole.
	Realm   realm.Config
	RealmID string

	// WrapTLS is the QUIC/TLS client config for the WrapStream layer (the
	// reliable stream that carries Shadowsocks). Caller-built; this is the OUTER
	// transport's TLS. Shadowsocks adds its own AEAD on top, so no inner TLS.
	WrapTLS aTLS.Config

	// Method is the Shadowsocks AEAD cipher, e.g. "aes-128-gcm". Password
	// derives the key. These must match the egress node's ssnode config.
	Method   string
	Password string

	// Mode 选打洞路径（探针专用）。零值 = realm.ModeNormal，生产不设即原行为。
	Mode realm.PunchMode

	// Trace 探针注入的埋点。非 nil 时用它；nil 时保持 env 驱动的 realm.Session。
	Trace *realm.Trace
}

// Client is a Shadowsocks overlay bound to one punched hole. Build with Dial.
// Each DialConn multiplexing is NOT supported: the wrap is a single reliable
// stream, so one Client carries exactly one proxied SS stream (one hole = one
// connection, mirroring overlay/reality).
type Client struct {
	method *shadowaead.Method
	wrap   net.Conn // the underlying WrapStream conn (closed with this)
}

// Dial punches a hole to RealmID, wraps it in a reliable QUIC stream, then
// constructs the Shadowsocks client method. The returned Client's DialConn opens
// the SS proxied stream to a target through that wrap — exactly like a normal SS
// outbound, the punch invisible to the SS engine.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if opts.WrapTLS == nil {
		return nil, E.New("shadowsocks-over-realm: WrapTLS (outer QUIC TLS) is required")
	}
	if opts.Method == "" {
		return nil, E.New("shadowsocks-over-realm: Method is required")
	}
	method, err := shadowaead.New(opts.Method, nil, opts.Password)
	if err != nil {
		return nil, E.Cause(err, "create shadowsocks method")
	}
	// 埋点：未开启时 trace 为 nil，以下所有 trace 调用都是 no-op（生产路径零影响）。
	trace := realm.SessionOr(opts.Trace, opts.RealmID, "shadowsocks")
	punched, err := realm.PunchTracedWithMode(ctx, opts.Realm, opts.RealmID, trace, opts.Mode)
	if err != nil {
		// 阶段归类已在 PunchTraced 内部完成，这里只负责输出。
		realm.Emit(opts.Realm.Logger, trace)
		return nil, E.Cause(err, "punch")
	}
	// M4: reliable stream over the hole — the net.Conn SS rides.
	wrap, err := underlay.WrapStreamFromPunch(ctx, underlay.FromPunch(punched), opts.WrapTLS)
	if err != nil {
		_ = punched.Close()
		realm.FailAndEmit(opts.Realm.Logger, trace, realm.FailStageHandshake, err)
		return nil, E.Cause(err, "wrap stream")
	}
	// ★ SS 无独立握手：wrap（QUIC/TLS）建立即隧道建立。
	// 密钥错在这里发现不了 —— 要等真实往返，那由 prober 判（内核不自报 ok）。
	realm.HandshakeDoneAndEmit(opts.Realm.Logger, trace)
	return &Client{method: method, wrap: wrap}, nil
}

// DialConn opens a proxied stream to destination through the Shadowsocks tunnel
// (which itself rides the reliable wrap over the punched hole). It uses
// DialEarlyConn so the SS request header is sent lazily with the first write,
// matching how a normal SS outbound behaves.
func (c *Client) DialConn(_ context.Context, destination M.Socksaddr) (net.Conn, error) {
	return c.method.DialEarlyConn(c.wrap, destination), nil
}

// Close tears down the underlying wrap (and with it the QUIC connection over the
// punched hole).
func (c *Client) Close() error {
	return c.wrap.Close()
}
