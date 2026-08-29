package option

import "github.com/sagernet/sing/common/json/badoption"

// RealmOptions is the OTun realm (rendezvous + hole-punch) config shared by the
// five non-Hysteria2 outbounds (TUIC / Reality / Trojan / Shadowsocks / VMess).
//
// Hysteria2 has its own Hysteria2Realm (built into upstream sing-box, with
// separate inbound/outbound variants). The five protocols here only ever run
// CLIENT-side over realm, and the punch coordinates are protocol-agnostic, so
// they share ONE outbound-only struct.
//
// When an outbound's Realm is non-nil, the protocol does NOT dial server /
// server_port directly; instead it punches a hole to the rendezvous (ServerURL,
// Token, RealmID) and runs its handshake over that hole via the OTun overlay
// glue (本仓 transport/realm + overlay/*，2026-07-30 已从 otun-s 归位到这里；
// 只有共用线格式包 underlay 仍在 otun-s)。When Realm is nil the outbound behaves
// exactly as upstream — non-realm packages are unaffected.
//
// Fields mirror Hysteria2Realm verbatim so the config surface is uniform across
// all six realm protocols.
type RealmOptions struct {
	// ServerURL is the rendezvous base URL (e.g. https://host/realm or
	// http://host:9443). SNI defaults to this host when the protocol's TLS
	// server_name is unset.
	ServerURL string `json:"server_url"`
	// Token is the realm bearer credential (per-egress shared).
	Token string `json:"token,omitempty"`
	// RealmID is the slot (egress node) to connect to.
	RealmID string `json:"realm_id"`
	// STUNServers are host:port STUN endpoints (IP recommended — see realm
	// config pitfalls), at least one.
	STUNServers badoption.Listable[string] `json:"stun_servers"`
	// HTTPClient configures the transport used to talk to the rendezvous
	// (managed h2/h3 client). Do NOT set detour here (realm config pitfall).
	HTTPClient *HTTPClientOptions `json:"http_client,omitempty"`
	// WrapTLS is the OUTER WrapStream (QUIC) TLS, used by REALITY only. The four
	// other realm protocols carry no inner TLS, so their `tls` block already IS
	// the outer WrapStream TLS. Reality is different: its `tls` block holds the
	// INNER Reality config (borrowed-SNI handshake), so the outer QUIC TLS needs
	// its own block here (ALPN should match the egress node, e.g. "h3"). Ignored
	// by non-Reality outbounds.
	WrapTLS *OutboundTLSOptions `json:"wrap_tls,omitempty"`
}
