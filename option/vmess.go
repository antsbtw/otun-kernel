package option

type VMessInboundOptions struct {
	ListenOptions
	Users []VMessUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type VMessUser struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	AlterId int    `json:"alterId,omitempty"`
}

type VMessOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID                string      `json:"uuid"`
	Security            string      `json:"security"`
	AlterId             int         `json:"alter_id,omitempty"`
	GlobalPadding       bool        `json:"global_padding,omitempty"`
	AuthenticatedLength bool        `json:"authenticated_length,omitempty"`
	Network             NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	PacketEncoding string                    `json:"packet_encoding,omitempty"`
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	// Realm, when set, makes this VMess outbound connect over an OTun realm
	// hole-punch (vmess-realm://) instead of dialing server/server_port. VMess
	// runs over a WrapStream (QUIC) reliable conn on the punched hole; VMess needs
	// no inner TLS, so the only TLS is the outer WrapStream TLS (the tls block).
	// Realm conflicts with multiplex and transport.
	Realm *RealmOptions `json:"realm,omitempty"`
}
