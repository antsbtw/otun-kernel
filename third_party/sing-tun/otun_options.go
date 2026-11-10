package tun

// OTunOptions holds OTun-specific TUN options. Embedded in Options so that
// upgrading sing-tun only conflicts on the single embedding line in tun.go.
type OTunOptions struct {
	// StrictRouteBlockBypassUDP (Windows only, requires StrictRoute): block UDP
	// that leaves through any interface other than the TUN (e.g. WebRTC sockets
	// bound to the physical NIC), in both ALE_AUTH_CONNECT and
	// ALE_AUTH_RECV_ACCEPT layers. Ignored on other platforms.
	StrictRouteBlockBypassUDP bool
	// StrictRouteBypassUDPAllowApps (Windows only): full executable paths still
	// allowed to send/receive UDP outside the TUN. Ignored on other platforms.
	StrictRouteBypassUDPAllowApps []string
}
