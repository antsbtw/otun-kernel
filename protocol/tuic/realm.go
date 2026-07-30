package tuic

import (
	"context"

	"github.com/sagernet/sing-box/common/otunrealm"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"

	otuntuic "github.com/sagernet/sing-box/overlay/tuic"

	"github.com/gofrs/uuid/v5"
)

// tuicTLSServerAddress returns the address whose host seeds the TLS SNI.
// Non-realm: the configured server. Realm: the realm.server_url host (server /
// server_port must NOT be set in realm mode). Mirrors Hy2's outboundTLSOptions.
func tuicTLSServerAddress(options option.TUICOutboundOptions) (string, error) {
	if options.Realm == nil {
		return options.Server, nil
	}
	if options.Server != "" || options.ServerPort != 0 {
		return "", E.New("realm conflicts with server and server_port")
	}
	return otunrealm.TLSServerName(options.Realm)
}

// newRealmClient stands up a TUIC-over-realm client (overlay/tuic) for the
// realm branch of NewOutbound. tlsConfig is the SAME caller-built TUIC TLS
// config the non-realm path uses; the punch is invisible to the engine.
func newRealmClient(ctx context.Context, logger log.ContextLogger, options option.TUICOutboundOptions, tlsConfig aTLS.Config) (*otuntuic.Client, error) {
	userUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	realmConfig, err := otunrealm.BuildConfig(ctx, logger, options.DialerOptions, options.Realm)
	if err != nil {
		return nil, err
	}
	return otuntuic.Dial(ctx, otuntuic.Options{
		Realm:             realmConfig,
		RealmID:           options.Realm.RealmID,
		TLSConfig:         tlsConfig,
		UUID:              userUUID,
		Password:          options.Password,
		CongestionControl: options.CongestionControl,
		UDPStream:         options.UDPRelayMode == "quic",
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
	})
}
