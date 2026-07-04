package trojan

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/otunrealm"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"

	otunrealmlib "github.com/antsbtw/otun-s/transport/realm"
	otuntrojan "github.com/antsbtw/otun-s/overlay/trojan"
)

// realmDialer holds the parameters to stand up a FRESH Trojan-over-realm conn
// per outbound dial. A WrapStream carries exactly one Trojan stream (single
// use), so — unlike TUIC's multiplexed QUIC client — each DialContext must punch
// its own hole. This dialer captures the immutable config; DialConn does the
// per-call punch + wrap + Trojan header.
type realmDialer struct {
	realmConfig otunrealmlib.Config
	realmID     string
	wrapTLS     tls.Config
	password    string
}

// newRealmDialer validates the realm Trojan config and builds the per-dial
// template. Trojan runs DIRECTLY over the WrapStream (QUIC) — the QUIC layer
// carries TLS, so there is no inner Trojan TLS. The `tls` block builds that
// OUTER WrapStream TLS (ALPN should match the egress node's WrapStream listener,
// e.g. "h3").
func newRealmDialer(ctx context.Context, logger log.ContextLogger, options option.TrojanOutboundOptions) (*realmDialer, error) {
	if options.Server != "" || options.ServerPort != 0 {
		return nil, E.New("realm conflicts with server and server_port")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("realm requires tls (the outer WrapStream/QUIC TLS)")
	}
	if common.PtrValueOrDefault(options.Multiplex).Enabled {
		return nil, E.New("realm conflicts with multiplex")
	}
	if common.PtrValueOrDefault(options.Transport).Type != "" {
		return nil, E.New("realm conflicts with transport")
	}
	if options.Password == "" {
		return nil, E.New("realm requires password")
	}
	serverName, err := otunrealm.TLSServerName(options.Realm)
	if err != nil {
		return nil, err
	}
	wrapTLS, err := tls.NewClient(ctx, logger, serverName, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	realmConfig, err := otunrealm.BuildConfig(ctx, logger, options.DialerOptions, options.Realm)
	if err != nil {
		return nil, err
	}
	return &realmDialer{
		realmConfig: realmConfig,
		realmID:     options.Realm.RealmID,
		wrapTLS:     wrapTLS,
		password:    options.Password,
	}, nil
}

// DialConn punches a fresh hole, wraps it, and returns a Trojan client conn to
// destination. The returned net.Conn owns the punched hole + WrapStream and
// closing it tears everything down (otuntrojan.Conn.Close closes the wrap).
func (d *realmDialer) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	overlayConn, err := otuntrojan.Dial(ctx, otuntrojan.Options{
		Realm:    d.realmConfig,
		RealmID:  d.realmID,
		WrapTLS:  d.wrapTLS,
		Password: d.password,
	})
	if err != nil {
		return nil, E.Cause(err, "trojan-realm dial")
	}
	stream, err := overlayConn.DialConn(ctx, destination)
	if err != nil {
		_ = overlayConn.Close()
		return nil, err
	}
	return &realmStreamConn{Conn: stream, overlay: overlayConn}, nil
}

// realmStreamConn ties the Trojan stream's lifetime to its owning overlay conn
// (punched hole + WrapStream): closing the stream closes the hole, so no holes
// leak when the proxied connection ends.
type realmStreamConn struct {
	net.Conn
	overlay *otuntrojan.Conn
}

func (c *realmStreamConn) Close() error {
	return c.overlay.Close()
}
