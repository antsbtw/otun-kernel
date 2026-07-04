package option

type VLESSInboundOptions struct {
	ListenOptions
	Users []VLESSUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Multiplex *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport *V2RayTransportOptions   `json:"transport,omitempty"`
}

type VLESSUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

type VLESSOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID    string      `json:"uuid"`
	Flow    string      `json:"flow,omitempty"`
	Network NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	PacketEncoding *string                   `json:"packet_encoding,omitempty"`
	// Realm, when set, makes this VLESS outbound connect over an OTun realm
	// hole-punch with Reality (vless+reality over realm) instead of dialing
	// server/server_port. Requires a tls.reality block (inner Reality TLS) and
	// realm.wrap_tls (outer WrapStream/QUIC TLS). Conflicts with multiplex and
	// transport. See protocol/vless/realm.go.
	Realm *RealmOptions `json:"realm,omitempty"`
}
