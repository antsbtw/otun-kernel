package option

type TrojanInboundOptions struct {
	ListenOptions
	Users []TrojanUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Fallback        *ServerOptions            `json:"fallback,omitempty"`
	FallbackForALPN map[string]*ServerOptions `json:"fallback_for_alpn,omitempty"`
	Multiplex       *InboundMultiplexOptions  `json:"multiplex,omitempty"`
	Transport       *V2RayTransportOptions    `json:"transport,omitempty"`
}

type TrojanUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type TrojanOutboundOptions struct {
	DialerOptions
	ServerOptions
	Password string      `json:"password"`
	Network  NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions    `json:"transport,omitempty"`
	// Realm, when set, makes this Trojan outbound connect over an OTun realm
	// hole-punch (trojan-realm://) instead of dialing server/server_port. Trojan
	// runs over a WrapStream (QUIC) reliable conn on the punched hole, with NO
	// inner TLS, multiplex, or v2ray transport — those conflict with realm.
	Realm *RealmOptions `json:"realm,omitempty"`
}
