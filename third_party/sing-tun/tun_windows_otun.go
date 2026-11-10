//go:build windows

package tun

import (
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/sagernet/sing-tun/internal/winsys"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// OTun: strict route "block bypass UDP".
//
// Upstream strict_route on Windows only blocks DNS (port 53) outside the TUN.
// Any socket explicitly bound to the physical NIC (Chromium WebRTC does this)
// can still send UDP to the Internet and leak the real IP. This adds, inside
// the same dynamic sublayer:
//
//	weight 9  PERMIT  UDP over the TUN interface
//	weight 9  PERMIT  UDP from this process / allow-listed apps
//	weight 9  PERMIT  UDP to local/link-local/multicast/broadcast ranges
//	weight 9  PERMIT  DHCP (remote port 67/547, local port 68/546) — one filter each
//	weight 8  BLOCK   all other UDP
//
// on ALE_AUTH_CONNECT_V4/V6 (locally initiated) and ALE_AUTH_RECV_ACCEPT_V4/V6
// (remotely initiated, e.g. unsolicited UDP to the NIC's public IPv6).
//
// Existing upstream filters (weights 10–13) are untouched and win over these.
// All filters here are added in one WFP transaction: either all of them are
// installed or none are, so a partial install can never block LAN/DHCP while
// missing its exceptions. Failure only logs an error; TUN start continues.

const otunBypassUDPLogTag = "strict_route_block_bypass_udp"

var (
	otunLocalRanges4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/32"), // DHCP discover source
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / Tailscale tailnet (its IPv6 fd7a:115c:a1e0::/48 is inside fc00::/7)
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"), // multicast: mDNS, SSDP, casting
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	otunLocalRanges6 = []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

type otunFilterBuilder struct {
	engine      uintptr
	subLayerKey windows.GUID
	// keepAlive pins Go memory referenced via uintptr in condition values
	// until all FwpmFilterAdd0 calls have returned.
	keepAlive []any
}

func (b *otunFilterBuilder) add(layer windows.GUID, name string, weight uint8, action uint32, conditions []winsys.FWPM_FILTER_CONDITION0) error {
	filter := winsys.FWPM_FILTER0{}
	filter.DisplayData = winsys.CreateDisplayData(TunnelType, name)
	filter.SubLayerKey = b.subLayerKey
	filter.LayerKey = layer
	filter.Action.Type = action
	filter.Weight.Type = winsys.FWP_UINT8
	filter.Weight.Value = uintptr(weight)
	if len(conditions) > 0 {
		filter.FilterCondition = &conditions[0]
		filter.NumFilterConditions = uint32(len(conditions))
	}
	var filterId uint64
	err := winsys.FwpmFilterAddErr(b.engine, &filter, &filterId)
	runtime.KeepAlive(conditions)
	if err != nil {
		return E.Cause(err, "add filter [", name, "]")
	}
	return nil
}

func otunUDPCondition() winsys.FWPM_FILTER_CONDITION0 {
	var c winsys.FWPM_FILTER_CONDITION0
	c.FieldKey = winsys.FWPM_CONDITION_IP_PROTOCOL
	c.MatchType = winsys.FWP_MATCH_EQUAL
	c.ConditionValue.Type = winsys.FWP_UINT8
	c.ConditionValue.Value = uintptr(uint8(winsys.IPPROTO_UDP))
	return c
}

func otunPortCondition(field windows.GUID, port uint16) winsys.FWPM_FILTER_CONDITION0 {
	var c winsys.FWPM_FILTER_CONDITION0
	c.FieldKey = field
	c.MatchType = winsys.FWP_MATCH_EQUAL
	c.ConditionValue.Type = winsys.FWP_UINT16
	c.ConditionValue.Value = uintptr(port)
	return c
}

func (b *otunFilterBuilder) remoteAddrConditions(prefixes []netip.Prefix, v6 bool) []winsys.FWPM_FILTER_CONDITION0 {
	var conditions []winsys.FWPM_FILTER_CONDITION0
	for _, prefix := range prefixes {
		var c winsys.FWPM_FILTER_CONDITION0
		c.FieldKey = winsys.FWPM_CONDITION_IP_REMOTE_ADDRESS
		c.MatchType = winsys.FWP_MATCH_EQUAL
		if !v6 {
			addr := prefix.Addr().As4()
			bits := prefix.Bits()
			var mask uint32
			if bits > 0 {
				mask = ^uint32(0) << (32 - bits)
			}
			value := &winsys.FWP_V4_ADDR_AND_MASK{
				Addr: binary.BigEndian.Uint32(addr[:]),
				Mask: mask,
			}
			b.keepAlive = append(b.keepAlive, value)
			c.ConditionValue.Type = winsys.FWP_V4_ADDR_MASK
			c.ConditionValue.Value = uintptr(unsafe.Pointer(value))
		} else {
			value := &winsys.FWP_V6_ADDR_AND_MASK{
				Addr:         prefix.Addr().As16(),
				PrefixLength: uint8(prefix.Bits()),
			}
			b.keepAlive = append(b.keepAlive, value)
			c.ConditionValue.Type = winsys.FWP_V6_ADDR_MASK
			c.ConditionValue.Value = uintptr(unsafe.Pointer(value))
		}
		conditions = append(conditions, c)
	}
	return conditions
}

// otunAddBypassUDPFilters is called from configure() right after the upstream
// DNS filters, inside the strict-route branch.
func (t *NativeTun) otunAddBypassUDPFilters(engine uintptr, subLayerKey windows.GUID, tunIndex uint32) {
	if !t.options.StrictRouteBlockBypassUDP {
		return
	}
	err := t.otunAddBypassUDPFiltersTx(engine, subLayerKey, tunIndex)
	if t.options.Logger == nil {
		return
	}
	if err != nil {
		t.options.Logger.Error(E.Cause(err, otunBypassUDPLogTag, ": filters not installed, UDP outside TUN is NOT blocked"))
	} else {
		t.options.Logger.Info(otunBypassUDPLogTag, ": UDP outside TUN blocked")
	}
}

func (t *NativeTun) otunAddBypassUDPFiltersTx(engine uintptr, subLayerKey windows.GUID, tunIndex uint32) (err error) {
	// App IDs are resolved before the transaction: a missing allow-list entry
	// is skipped with a warning instead of aborting the whole protection.
	var appIDs []*winsys.FWP_BYTE_BLOB
	defer func() {
		for i := range appIDs {
			winsys.FwpmFreeMemory0(unsafe.Pointer(&appIDs[i]))
		}
	}()
	selfAppID, err := winsys.GetCurrentProcessAppID()
	if err != nil {
		return E.Cause(err, "get current process app id")
	}
	appIDs = append(appIDs, selfAppID)
	for _, path := range t.options.StrictRouteBypassUDPAllowApps {
		if path == "" {
			continue
		}
		appID, appErr := otunGetAppID(path)
		if appErr != nil {
			if t.options.Logger != nil {
				t.options.Logger.Warn(E.Cause(appErr, otunBypassUDPLogTag, ": skip allow app ", path))
			}
			continue
		}
		appIDs = append(appIDs, appID)
	}

	err = winsys.FwpmTransactionBegin0(engine, 0)
	if err != nil {
		return E.Cause(err, "FwpmTransactionBegin0")
	}
	committed := false
	defer func() {
		if !committed {
			winsys.FwpmTransactionAbort0(engine)
		}
	}()

	b := &otunFilterBuilder{engine: engine, subLayerKey: subLayerKey}
	type layerInfo struct {
		key  windows.GUID
		name string
		v6   bool
	}
	layers := []layerInfo{
		{winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V4, "connect ipv4", false},
		{winsys.FWPM_LAYER_ALE_AUTH_CONNECT_V6, "connect ipv6", true},
		{winsys.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "recv-accept ipv4", false},
		{winsys.FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "recv-accept ipv6", true},
	}

	// Permits first (weight 9), block last (weight 8).
	for _, layer := range layers {
		udp := otunUDPCondition()

		// UDP over the TUN interface itself.
		var tunCond winsys.FWPM_FILTER_CONDITION0
		tunCond.FieldKey = winsys.FWPM_CONDITION_LOCAL_INTERFACE_INDEX
		tunCond.MatchType = winsys.FWP_MATCH_EQUAL
		tunCond.ConditionValue.Type = winsys.FWP_UINT32
		tunCond.ConditionValue.Value = uintptr(tunIndex)
		err = b.add(layer.key, "otun permit tun udp "+layer.name, 9, winsys.FWP_ACTION_PERMIT,
			[]winsys.FWPM_FILTER_CONDITION0{udp, tunCond})
		if err != nil {
			return err
		}

		// This process (kernel outbounds, realm hole punching) and allow-listed
		// apps. Same field => OR.
		appConds := []winsys.FWPM_FILTER_CONDITION0{udp}
		for _, appID := range appIDs {
			var c winsys.FWPM_FILTER_CONDITION0
			c.FieldKey = winsys.FWPM_CONDITION_ALE_APP_ID
			c.MatchType = winsys.FWP_MATCH_EQUAL
			c.ConditionValue.Type = winsys.FWP_BYTE_BLOB_TYPE
			c.ConditionValue.Value = uintptr(unsafe.Pointer(appID))
			appConds = append(appConds, c)
		}
		err = b.add(layer.key, "otun permit app udp "+layer.name, 9, winsys.FWP_ACTION_PERMIT, appConds)
		if err != nil {
			return err
		}

		// Local ranges. All remote-address conditions are the same field => OR.
		ranges := otunLocalRanges4
		if layer.v6 {
			ranges = otunLocalRanges6
		}
		localConds := append([]winsys.FWPM_FILTER_CONDITION0{udp}, b.remoteAddrConditions(ranges, layer.v6)...)
		err = b.add(layer.key, "otun permit local udp "+layer.name, 9, winsys.FWP_ACTION_PERMIT, localConds)
		if err != nil {
			return err
		}

		// DHCP: remote port and local port are different fields (AND inside one
		// filter), so they must be two separate filters.
		serverPort, clientPort := uint16(67), uint16(68)
		if layer.v6 {
			serverPort, clientPort = 547, 546
		}
		err = b.add(layer.key, "otun permit dhcp server port "+layer.name, 9, winsys.FWP_ACTION_PERMIT,
			[]winsys.FWPM_FILTER_CONDITION0{udp, otunPortCondition(winsys.FWPM_CONDITION_IP_REMOTE_PORT, serverPort)})
		if err != nil {
			return err
		}
		err = b.add(layer.key, "otun permit dhcp client port "+layer.name, 9, winsys.FWP_ACTION_PERMIT,
			[]winsys.FWPM_FILTER_CONDITION0{udp, otunPortCondition(winsys.FWPM_CONDITION_IP_LOCAL_PORT, clientPort)})
		if err != nil {
			return err
		}
	}
	for _, layer := range layers {
		err = b.add(layer.key, "otun block udp "+layer.name, 8, winsys.FWP_ACTION_BLOCK,
			[]winsys.FWPM_FILTER_CONDITION0{otunUDPCondition()})
		if err != nil {
			return err
		}
	}

	err = winsys.FwpmTransactionCommit0(engine)
	runtime.KeepAlive(b.keepAlive)
	if err != nil {
		return E.Cause(err, "FwpmTransactionCommit0")
	}
	committed = true
	return nil
}

func otunGetAppID(path string) (*winsys.FWP_BYTE_BLOB, error) {
	if !filepath.IsAbs(path) {
		return nil, E.New("not an absolute path")
	}
	pathPtr, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var appID *winsys.FWP_BYTE_BLOB
	err = winsys.FwpmGetAppIdFromFileName0(pathPtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, err
	}
	return appID, nil
}
