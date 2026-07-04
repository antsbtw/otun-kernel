package shadowsocks

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

	otunss "github.com/antsbtw/otun-s/overlay/shadowsocks"
	otunrealmlib "github.com/antsbtw/otun-s/transport/realm"
)

// realmDialer dials a FRESH Shadowsocks-over-realm conn per call. Like Trojan, a
// WrapStream carries exactly one SS stream (single use), so each DialContext
// punches its own hole. SS's AEAD provides ciphering; the only TLS is the outer
// WrapStream (QUIC) TLS. Client and server MUST use the same SS library/version
// (otun-s uses sing-shadowsocks v1) — a cross-version mismatch decodes the
// request but fails the response AEAD framing (real-device-only pitfall).
type realmDialer struct {
	realmConfig otunrealmlib.Config
	realmID     string
	wrapTLS     tls.Config
	method      string
	password    string
}

func newRealmDialer(ctx context.Context, logger log.ContextLogger, options option.ShadowsocksOutboundOptions) (*realmDialer, error) {
	if options.Server != "" || options.ServerPort != 0 {
		return nil, E.New("realm conflicts with server and server_port")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("realm requires tls (the outer WrapStream/QUIC TLS)")
	}
	if options.Plugin != "" {
		return nil, E.New("realm conflicts with plugin")
	}
	if common.PtrValueOrDefault(options.UDPOverTCP).Enabled {
		return nil, E.New("realm conflicts with udp_over_tcp")
	}
	if common.PtrValueOrDefault(options.Multiplex).Enabled {
		return nil, E.New("realm conflicts with multiplex")
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
		method:      options.Method,
		password:    options.Password,
	}, nil
}

func (d *realmDialer) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	overlayConn, err := otunss.Dial(ctx, otunss.Options{
		Realm:    d.realmConfig,
		RealmID:  d.realmID,
		WrapTLS:  d.wrapTLS,
		Method:   d.method,
		Password: d.password,
	})
	if err != nil {
		return nil, E.Cause(err, "shadowsocks-realm dial")
	}
	stream, err := overlayConn.DialConn(ctx, destination)
	if err != nil {
		_ = overlayConn.Close()
		return nil, err
	}
	return &realmStreamConn{Conn: stream, overlay: overlayConn}, nil
}

// realmStreamConn ties the SS stream lifetime to its owning overlay conn
// (punched hole + WrapStream) so closing the stream frees the hole.
type realmStreamConn struct {
	net.Conn
	overlay *otunss.Client
}

func (c *realmStreamConn) Close() error {
	return c.overlay.Close()
}
