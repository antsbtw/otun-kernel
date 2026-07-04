package tuic

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	otuntuic "github.com/antsbtw/otun-s/overlay/tuic"

	"github.com/gofrs/uuid/v5"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TUICOutboundOptions](registry, C.TypeTUIC, NewOutbound)
}

var _ adapter.InterfaceUpdateListener = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	logger logger.ContextLogger
	// client is the normal (non-realm) sing-quic TUIC client. nil when realm is set.
	client *tuic.Client
	// realmClient is the TUIC-over-realm overlay client. nil unless options.Realm is set.
	realmClient *otuntuic.Client
	udpStream   bool
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	// realm mode: the server address comes from the rendezvous (realm.server_url
	// host is the SNI default), NOT server/server_port. Mirrors Hy2's
	// outboundTLSOptions.
	tlsServerAddress, err := tuicTLSServerAddress(options)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, tlsServerAddress, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	if options.Realm != nil {
		realmClient, err := newRealmClient(ctx, logger, options, tlsConfig)
		if err != nil {
			return nil, err
		}
		return &Outbound{
			Adapter:     outbound.NewAdapterWithDialerOptions(C.TypeTUIC, tag, options.Network.Build(), options.DialerOptions),
			logger:      logger,
			realmClient: realmClient,
			udpStream:   options.UDPOverStream,
		}, nil
	}
	userUUID, err := uuid.FromString(options.UUID)
	if err != nil {
		return nil, E.Cause(err, "invalid uuid")
	}
	var tuicUDPStream bool
	if options.UDPOverStream && options.UDPRelayMode != "" {
		return nil, E.New("udp_over_stream is conflict with udp_relay_mode")
	}
	switch options.UDPRelayMode {
	case "native":
	case "quic":
		tuicUDPStream = true
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	client, err := tuic.NewClient(tuic.ClientOptions{
		Context:       ctx,
		Dialer:        outboundDialer,
		ServerAddress: options.ServerOptions.Build(),
		TLSConfig:     tlsConfig,
		QUICOptions: qtls.QUICOptions{
			IdleTimeout:             options.IdleTimeout.Build(),
			KeepAlivePeriod:         options.KeepAlivePeriod.Build(),
			StreamReceiveWindow:     options.StreamReceiveWindow.Value(),
			ConnectionReceiveWindow: options.ConnectionReceiveWindow.Value(),
			MaxConcurrentStreams:    options.MaxConcurrentStreams,
			InitialPacketSize:       options.InitialPacketSize,
			DisablePathMTUDiscovery: options.DisablePathMTUDiscovery,
		},
		UUID:              userUUID,
		Password:          options.Password,
		CongestionControl: options.CongestionControl,
		UDPStream:         tuicUDPStream,
		ZeroRTTHandshake:  options.ZeroRTTHandshake,
		Heartbeat:         time.Duration(options.Heartbeat),
	})
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeTUIC, tag, options.Network.Build(), options.DialerOptions),
		logger:    logger,
		client:    client,
		udpStream: options.UDPOverStream,
	}, nil
}

// dialConn dials a proxied stream through whichever client is active (realm or
// normal). Both expose the same DialConn(ctx, dest) (net.Conn, error) contract.
func (h *Outbound) dialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if h.realmClient != nil {
		return h.realmClient.DialConn(ctx, destination)
	}
	return h.client.DialConn(ctx, destination)
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dialConn(ctx, destination)
	case N.NetworkUDP:
		if h.udpStream {
			h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
			streamConn, err := h.dialConn(ctx, uot.RequestDestination(uot.Version))
			if err != nil {
				return nil, err
			}
			return uot.NewLazyConn(streamConn, uot.Request{
				IsConnect:   true,
				Destination: destination,
			}), nil
		} else {
			conn, err := h.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(conn, destination), nil
		}
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.udpStream {
		h.logger.InfoContext(ctx, "outbound stream packet connection to ", destination)
		streamConn, err := h.dialConn(ctx, uot.RequestDestination(uot.Version))
		if err != nil {
			return nil, err
		}
		return uot.NewLazyConn(streamConn, uot.Request{
			IsConnect:   false,
			Destination: destination,
		}), nil
	} else {
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		if h.realmClient != nil {
			return h.realmClient.ListenPacket(ctx)
		}
		return h.client.ListenPacket(ctx)
	}
}

func (h *Outbound) InterfaceUpdated() {
	if h.realmClient != nil {
		// The overlay client owns the punched hole; closing it forces a fresh
		// punch on the next dial after a network change.
		_ = h.realmClient.Close()
		return
	}
	_ = h.client.CloseWithError(E.New("network changed"))
}

func (h *Outbound) Close() error {
	if h.realmClient != nil {
		return h.realmClient.Close()
	}
	return h.client.CloseWithError(os.ErrClosed)
}
