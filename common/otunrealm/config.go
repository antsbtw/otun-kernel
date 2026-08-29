// Package otunrealm bridges the kernel's option.RealmOptions to the
// protocol-agnostic otun-s realm.Config, factoring out the DNS / managed
// http-client wiring so each realm-capable outbound (TUIC / Reality / Trojan /
// Shadowsocks / VMess) shares ONE copy of it.
//
// The wiring is lifted verbatim from upstream hysteria2/outbound.go's realm
// branch — keeping it identical is what guarantees the realm config pitfalls
// (STUN-by-IP, no http_client.detour, domestic proxy-dns) behave the same for
// the five non-Hy2 protocols as they already do for Hy2.
package otunrealm

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	otunrealm "github.com/sagernet/sing-box/transport/realm"
)

// BuildConfig translates option.RealmOptions into otun-s realm.Config using the
// same DNS resolver + managed http transport upstream Hy2 uses.
func BuildConfig(ctx context.Context, logger log.ContextLogger, dialerOptions option.DialerOptions, realmOptions *option.RealmOptions) (otunrealm.Config, error) {
	queryOptions, err := adapter.DNSQueryOptionsFrom(ctx, dialerOptions.DomainResolver)
	if err != nil {
		return otunrealm.Config{}, err
	}
	httpClientTransport, err := service.FromContext[adapter.HTTPClientManager](ctx).ResolveTransport(ctx, logger, common.PtrValueOrDefault(realmOptions.HTTPClient))
	if err != nil {
		return otunrealm.Config{}, E.Cause(err, "create realm http client")
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	// CRITICAL: the STUN + hole-punch UDP sockets MUST be opened through the
	// outbound's sing-box dialer, not a raw net.ListenUDP. In a global-proxy TUN
	// (the typical client setup), raw sockets get captured by the TUN and the
	// punch/STUN packets loop back into the tunnel instead of reaching the
	// internet — the connection "establishes" but carries 0 traffic. sing-box's
	// dialer binds/protects these sockets (auto on Apple/Android) so they egress
	// the real interface. Without this, realm punching cannot work inside a VPN
	// extension. (Found in B3 macOS real-machine regression, 2026-06-30.)
	punchDialer, err := dialer.New(ctx, dialerOptions, false)
	if err != nil {
		return otunrealm.Config{}, E.Cause(err, "create realm punch dialer")
	}
	return otunrealm.Config{
		ServerURL:   realmOptions.ServerURL,
		Token:       realmOptions.Token,
		STUNServers: realmOptions.STUNServers,
		Dialer:      punchDialer,
		HTTPClient:  &http.Client{Transport: httpClientTransport},
		Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
			dnsOptions := queryOptions
			switch {
			case ipv4 && !ipv6:
				dnsOptions.Strategy = C.DomainStrategyIPv4Only
			case !ipv4 && ipv6:
				dnsOptions.Strategy = C.DomainStrategyIPv6Only
			}
			return dnsRouter.Lookup(ctx, host, dnsOptions)
		},
		Logger: logger,
	}, nil
}

// TLSServerName returns the host of realm.server_url, used as the TLS SNI
// default in realm mode (where there is no server / server_port to derive it
// from). Mirrors upstream Hy2's outboundTLSOptions.
func TLSServerName(realmOptions *option.RealmOptions) (string, error) {
	serverURL, err := url.Parse(realmOptions.ServerURL)
	if err != nil {
		return "", E.Cause(err, "parse realm server_url")
	}
	serverName := serverURL.Hostname()
	if serverName == "" {
		return "", E.New("missing host in realm server_url")
	}
	return serverName, nil
}
