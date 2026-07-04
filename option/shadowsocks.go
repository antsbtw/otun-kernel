package option

type ShadowsocksInboundOptions struct {
	ListenOptions
	Network      NetworkList              `json:"network,omitempty"`
	Method       string                   `json:"method"`
	Password     string                   `json:"password,omitempty"`
	Users        []ShadowsocksUser        `json:"users,omitempty"`
	Destinations []ShadowsocksDestination `json:"destinations,omitempty"`
	Multiplex    *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Managed      bool                     `json:"managed,omitempty"`
}

type ShadowsocksUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type ShadowsocksDestination struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	ServerOptions
}

type ShadowsocksOutboundOptions struct {
	DialerOptions
	ServerOptions
	Method        string                    `json:"method"`
	Password      string                    `json:"password"`
	Plugin        string                    `json:"plugin,omitempty"`
	PluginOptions string                    `json:"plugin_opts,omitempty"`
	Network       NetworkList               `json:"network,omitempty"`
	UDPOverTCP    *UDPOverTCPOptions        `json:"udp_over_tcp,omitempty"`
	Multiplex     *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	// Realm, when set, makes this Shadowsocks outbound connect over an OTun realm
	// hole-punch (shadowsocks-realm://) instead of dialing server/server_port. SS
	// runs over a WrapStream (QUIC) reliable conn on the punched hole; SS's own
	// AEAD provides ciphering, so the only TLS is the outer WrapStream TLS (the
	// tls block, supplied by OutboundTLSOptionsContainer, used in realm mode only).
	// Realm conflicts with plugin, udp_over_tcp, and multiplex.
	OutboundTLSOptionsContainer
	Realm *RealmOptions `json:"realm,omitempty"`
}
