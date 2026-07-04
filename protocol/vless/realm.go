package vless

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

	otunreality "github.com/antsbtw/otun-s/overlay/reality"
	otunrealmlib "github.com/antsbtw/otun-s/transport/realm"
)

// realmDialer dials a FRESH VLESS-Reality-over-realm conn per call.
//
// Reality is the two-TLS case (handoff §3): the OUTER WrapStream (QUIC) TLS
// comes from realm.wrap_tls, the INNER Reality TLS from the `tls` block (which
// must carry a `reality` sub-block). overlay/reality now owns the FULL
// VLESS+Reality stack: punch → WrapStream → Reality ClientHandshake → VLESS
// framing. So the kernel just hands it the inner/outer TLS + UUID and calls
// DialConn(dest); the overlay writes the VLESS request header that conveys the
// destination, and the egress node (realitynode) reads it back. (Earlier the
// kernel layered VLESS itself; that moved down into the overlay so client and
// node share one VLESS implementation — no kernel-side framing anymore.)
type realmDialer struct {
	realmConfig otunrealmlib.Config
	realmID     string
	wrapTLS     tls.Config
	realityTLS  tls.Config
	uuid        string
}

func newRealmDialer(ctx context.Context, logger log.ContextLogger, options option.VLESSOutboundOptions) (*realmDialer, error) {
	if options.Server != "" || options.ServerPort != 0 {
		return nil, E.New("realm conflicts with server and server_port")
	}
	if common.PtrValueOrDefault(options.Multiplex).Enabled {
		return nil, E.New("realm conflicts with multiplex")
	}
	if common.PtrValueOrDefault(options.Transport).Type != "" {
		return nil, E.New("realm conflicts with transport")
	}
	if options.Flow != "" {
		// VLESS over realm runs the bare VLESS framing the overlay writes; XTLS
		// flow control would need the inner conn to be a real TLS conn the flow
		// can splice, which the overlay does not expose.
		return nil, E.New("realm does not support vless flow")
	}
	if options.TLS == nil || !options.TLS.Enabled || options.TLS.Reality == nil || !options.TLS.Reality.Enabled {
		return nil, E.New("realm on vless requires tls with a reality block (the inner Reality TLS)")
	}
	if options.Realm.WrapTLS == nil || !options.Realm.WrapTLS.Enabled {
		return nil, E.New("realm on vless requires realm.wrap_tls (the outer WrapStream/QUIC TLS)")
	}
	serverName, err := otunrealm.TLSServerName(options.Realm)
	if err != nil {
		return nil, err
	}
	// Inner Reality TLS — built from the `tls` block (server_name = Reality's
	// borrowed-SNI handshake target, NOT the rendezvous host).
	realityTLS, err := tls.NewClient(ctx, logger, options.TLS.ServerName, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, E.Cause(err, "build inner reality tls")
	}
	// Outer WrapStream TLS — built from realm.wrap_tls; SNI defaults to the
	// rendezvous host.
	wrapTLS, err := tls.NewClient(ctx, logger, serverName, *options.Realm.WrapTLS)
	if err != nil {
		return nil, E.Cause(err, "build outer wrap tls")
	}
	realmConfig, err := otunrealm.BuildConfig(ctx, logger, options.DialerOptions, options.Realm)
	if err != nil {
		return nil, err
	}
	return &realmDialer{
		realmConfig: realmConfig,
		realmID:     options.Realm.RealmID,
		wrapTLS:     wrapTLS,
		realityTLS:  realityTLS,
		uuid:        options.UUID,
	}, nil
}

func (d *realmDialer) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	client, err := otunreality.Dial(ctx, otunreality.Options{
		Realm:   d.realmConfig,
		RealmID: d.realmID,
		WrapTLS: d.wrapTLS,
		Reality: d.realityTLS,
		UUID:    d.uuid,
	})
	if err != nil {
		return nil, E.Cause(err, "vless-reality-realm dial")
	}
	// The overlay writes the VLESS request header conveying the destination.
	stream, err := client.DialConn(ctx, destination)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &realmStreamConn{Conn: stream, overlay: client}, nil
}

// realmStreamConn ties the proxied stream lifetime to its owning overlay client
// (punched hole + WrapStream + Reality + VLESS) so closing the stream frees the
// hole.
type realmStreamConn struct {
	net.Conn
	overlay *otunreality.Client
}

func (c *realmStreamConn) Close() error {
	return c.overlay.Close()
}
