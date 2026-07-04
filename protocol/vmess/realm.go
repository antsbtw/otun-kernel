package vmess

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

	otunvmess "github.com/antsbtw/otun-s/overlay/vmess"
	otunrealmlib "github.com/antsbtw/otun-s/transport/realm"
)

// realmDialer dials a FRESH VMess-over-realm conn per call. Like Trojan/SS, a
// WrapStream carries exactly one VMess stream (single use), so each DialContext
// punches its own hole. VMess needs no inner TLS; the only TLS is the outer
// WrapStream (QUIC) TLS.
type realmDialer struct {
	realmConfig otunrealmlib.Config
	realmID     string
	wrapTLS     tls.Config
	uuid        string
	security    string
	alterID     int
}

func newRealmDialer(ctx context.Context, logger log.ContextLogger, options option.VMessOutboundOptions) (*realmDialer, error) {
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
		uuid:        options.UUID,
		security:    options.Security,
		alterID:     options.AlterId,
	}, nil
}

func (d *realmDialer) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	overlayConn, err := otunvmess.Dial(ctx, otunvmess.Options{
		Realm:    d.realmConfig,
		RealmID:  d.realmID,
		WrapTLS:  d.wrapTLS,
		UUID:     d.uuid,
		Security: d.security,
		AlterId:  d.alterID,
	})
	if err != nil {
		return nil, E.Cause(err, "vmess-realm dial")
	}
	stream, err := overlayConn.DialConn(ctx, destination)
	if err != nil {
		_ = overlayConn.Close()
		return nil, err
	}
	return &realmStreamConn{Conn: stream, overlay: overlayConn}, nil
}

// realmStreamConn ties the VMess stream lifetime to its owning overlay conn
// (punched hole + WrapStream) so closing the stream frees the hole.
type realmStreamConn struct {
	net.Conn
	overlay *otunvmess.Client
}

func (c *realmStreamConn) Close() error {
	return c.overlay.Close()
}
