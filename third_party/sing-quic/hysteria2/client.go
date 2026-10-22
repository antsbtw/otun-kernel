package hysteria2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/http3"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	"github.com/sagernet/sing-quic/hysteria"
	hyCC "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/sing-quic/hysteria2/internal/protocol"
	"github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"
)

const defaultHandshakeTimeout = 15 * time.Second

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      M.Socksaddr
	ServerPorts        []string
	HopInterval        time.Duration
	HopIntervalMax     time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	GeckoPassword      string
	GeckoMinPacketSize int
	GeckoMaxPacketSize int
	Password           string
	TLSConfig          aTLS.Config
	QUICOptions        qtls.QUICOptions
	UDPDisabled        bool
	BBRProfile         string
	RealmOptions       *realm.Options
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddr         M.Socksaddr
	serverPorts        []uint16
	hopInterval        time.Duration
	hopIntervalMax     time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	geckoPassword      string
	geckoMinPacketSize int
	geckoMaxPacketSize int
	password           string
	tlsConfig          aTLS.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	bbrProfile         congestion_meta2.Profile
	realmOptions       *realm.Options
	controlClient      *realm.ControlClient

	connAccess sync.Mutex
	conn       *clientQUICConnection
	pending    *clientOffer

	// v4 连接僵死后的 v6 偏好期截止时刻(UnixNano,0=无),见 realm_stall.go。
	preferV6Until atomic.Int64

	// 直连握手连续失败计数与中继偏好期,见 realm_relay_fallback.go。
	relayFallback relayFallbackState

	// CloseWithError 后置位,空闲超时不再主动重连,见 realm_idle_reconnect.go。
	closed atomic.Bool
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{
		DisablePathMTUDiscovery:        !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
		EnableDatagrams:                !options.UDPDisabled,
		InitialStreamReceiveWindow:     hysteria.DefaultStreamReceiveWindow,
		MaxStreamReceiveWindow:         hysteria.DefaultStreamReceiveWindow,
		InitialConnectionReceiveWindow: hysteria.DefaultConnReceiveWindow,
		MaxConnectionReceiveWindow:     hysteria.DefaultConnReceiveWindow,
		MaxIdleTimeout:                 hysteria.DefaultMaxIdleTimeout,
		KeepAlivePeriod:                hysteria.DefaultKeepAlivePeriod,
	}
	qtls.ApplyQUICOptions(quicConfig, options.QUICOptions)
	if len(options.TLSConfig.NextProtos()) == 0 {
		options.TLSConfig.SetNextProtos([]string{http3.NextProtoH3})
	}
	bbrProfile := congestion_meta2.ProfileStandard
	if options.BBRProfile != "" {
		var err error
		bbrProfile, err = congestion_meta2.ParseProfile(options.BBRProfile)
		if err != nil {
			return nil, err
		}
	}
	if options.RealmOptions != nil && len(options.ServerPorts) > 0 {
		return nil, E.New("realm and port hopping are mutually exclusive")
	}
	if options.RealmOptions != nil {
		switch options.RealmOptions.PunchFamily {
		case "", realm.PunchFamilyV4, realm.PunchFamilyV6:
		default:
			return nil, E.New("realm: invalid punch_family: ", options.RealmOptions.PunchFamily)
		}
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = geckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = geckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > geckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	var controlClient *realm.ControlClient
	if options.RealmOptions != nil {
		var err error
		controlClient, err = realm.NewControlClient(options.RealmOptions.ServerURL, options.RealmOptions.Token, options.RealmOptions.HTTPClient)
		if err != nil {
			return nil, E.Cause(err, "create control client")
		}
	}
	var serverPorts []uint16
	if len(options.ServerPorts) > 0 {
		var err error
		serverPorts, err = hysteria.ParsePorts(options.ServerPorts)
		if err != nil {
			return nil, err
		}
	}
	return &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddr:         options.ServerAddress,
		serverPorts:        serverPorts,
		hopInterval:        options.HopInterval,
		hopIntervalMax:     options.HopIntervalMax,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		geckoPassword:      options.GeckoPassword,
		geckoMinPacketSize: options.GeckoMinPacketSize,
		geckoMaxPacketSize: options.GeckoMaxPacketSize,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		bbrProfile:         bbrProfile,
		realmOptions:       options.RealmOptions,
		controlClient:      controlClient,
	}, nil
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	conn := c.conn
	if conn != nil && conn.active() {
		c.connAccess.Unlock()
		return conn, nil
	}
	pending := c.pending
	if pending != nil {
		c.connAccess.Unlock()
		select {
		case <-pending.done:
			return pending.conn, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// A pending offer is shared by concurrent callers. Do not derive offerCtx
	// from the foreground request ctx: a timed-out request must stop waiting for
	// the shared result, but it must not tear down the background QUIC dial that
	// may still be reused by later requests. The connection attempt is owned by
	// the client lifetime context instead.
	offerCtx := c.ctx
	if offerCtx == nil {
		offerCtx = context.Background()
	}
	offerCtx, cancel := common.ContextWithCancelCause(offerCtx)
	pending = &clientOffer{
		done:   make(chan struct{}),
		cancel: cancel,
	}
	c.pending = pending
	c.connAccess.Unlock()

	go c.completeOffer(pending, offerCtx)

	select {
	case <-pending.done:
		return pending.conn, pending.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) completeOffer(pending *clientOffer, offerCtx context.Context) {
	conn, err := c.offerNew(offerCtx)
	pending.cancel(nil)

	discardErr := err
	shouldDiscard := false
	c.connAccess.Lock()
	if pending.discarded {
		shouldDiscard = true
		if pending.cause != nil {
			discardErr = pending.cause
		}
		pending.err = discardErr
	} else {
		pending.conn = conn
		pending.err = err
		if err == nil {
			c.conn = conn
		}
	}
	if c.pending == pending {
		c.pending = nil
	}
	close(pending.done)
	c.connAccess.Unlock()

	if shouldDiscard && conn != nil {
		conn.closeWithError(discardErr)
	}
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	if c.realmOptions != nil {
		return c.offerNewRealm(ctx)
	}
	dialCtx := ctx
	hopCtx := c.ctx
	if hopCtx == nil {
		hopCtx = context.Background()
	}
	firstDial := true
	dialFunc := func(serverAddr M.Socksaddr) (net.PacketConn, error) {
		currentCtx := hopCtx
		if firstDial {
			// The initial socket open belongs to the shared offer. Later port hops
			// belong to the live client connection and must outlive any one caller.
			currentCtx = dialCtx
			firstDial = false
		}
		udpConn, err := c.dialer.DialContext(currentCtx, "udp", serverAddr)
		if err != nil {
			return nil, err
		}
		var packetConn net.PacketConn
		packetConn = bufio.NewUnbindPacketConn(udpConn)
		if c.geckoPassword != "" {
			packetConn = NewGeckoConn(packetConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize)
		} else if c.salamanderPassword != "" {
			packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
		}
		return packetConn, nil
	}
	var (
		packetConn net.PacketConn
		err        error
	)
	if len(c.serverPorts) == 0 {
		packetConn, err = dialFunc(c.serverAddr)
	} else {
		packetConn, err = hysteria.NewHopPacketConn(dialFunc, c.serverAddr, c.serverPorts, c.hopInterval, c.hopIntervalMax)
	}
	if err != nil {
		return nil, err
	}
	return c.authenticateAndWrap(ctx, packetConn, c.serverAddr)
}

type realmFamilyConn struct {
	family         string
	ipv4           bool
	conn           net.PacketConn
	localAddresses []netip.AddrPort
}

// offerNewRealm 是住宅面建连入口。打洞成功但握手失败时，换新 nonce 重新
// /connect 改走中继（见 realm_relay_fallback.go）。
func (c *Client) offerNewRealm(ctx context.Context) (*clientQUICConnection, error) {
	conn, fallback, err := c.offerNewRealmPunch(ctx, true)
	if fallback == nil {
		return conn, err
	}
	relayConn, relayErr := c.offerNewRealmRelay(ctx, fallback)
	if relayErr != nil {
		c.realmWarn("realm: relay fallback after handshake failure failed: ", relayErr)
		// 与打洞失败的回退同一约束：回退失败返回原错误，原文不改。
		return nil, err
	}
	return relayConn, nil
}

// realmRelayFallback 是「打洞成功、握手失败」后改走中继所需的上下文。
type realmRelayFallback struct {
	localAddresses []netip.AddrPort
}

// offerNewRealmPunch 打洞并握手。allowRelay=false 只试直连（走中继期间的后台
// 直连重试，见 realm_direct_probe.go）：不走偏好期、打洞失败不回退、握手失败不给回退上下文。
func (c *Client) offerNewRealmPunch(ctx context.Context, allowRelay bool) (*clientQUICConnection, *realmRelayFallback, error) {
	obs := c.newDialObserver()
	defer obs.Finish()
	families, err := c.realmOpenFamilies(ctx)
	if err != nil {
		obs.Failed("stun", err)
		return nil, nil, err
	}
	surviving, localAddresses, err := c.realmDiscoverFamilies(ctx, families)
	if err != nil {
		obs.Failed("stun", err)
		return nil, nil, err
	}
	obs.STUNDiscovered(localAddresses)
	closeSurviving := func() {
		for _, family := range surviving {
			_ = family.conn.Close()
		}
	}
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		closeSurviving()
		obs.Failed("rendezvous", err)
		return nil, nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, localAddresses, localMetadata)
	if err != nil {
		closeSurviving()
		obs.Failed("rendezvous", err)
		return nil, nil, E.Cause(err, "realm connect")
	}
	obs.RendezvousDone(response.Addresses, response.PunchMetadata)
	if failures, prefer := c.relayFallback.preferRelay(time.Now()); allowRelay && prefer {
		if len(response.Relay) > 0 {
			c.realmWarn("realm: ", failures, " consecutive handshake failures, using relay without punching")
			// 打洞 socket 先留着：中继报到失败时还能接着打洞，不至于在中继坏掉时一直卡在偏好期里。
			conn, joined, relayErr := c.realmDialRelay(ctx, response, obs)
			if joined {
				closeSurviving()
				return conn, nil, relayErr
			}
		} else {
			c.realmWarn("realm: ", failures, " consecutive handshake failures but relay list is empty, punching anyway")
		}
	}
	winner, result, err := c.realmRacePunch(ctx, surviving, response.Addresses, response.PunchMetadata, obs)
	if err != nil {
		obs.Failed("punch", err)
		if !allowRelay {
			return nil, nil, err
		}
		// ★中继回退（RELAY_FALLBACK_DESIGN.md §3.1）：对称 NAT 下打洞必败，
		// 改由客户端与节点各自主动出站连中继、按 nonce 对接。
		//
		// 🔴 这条路径原先**缺失** —— 六协议里只有 hy2 走 squic 这份老客户端
		// 实现，其余五协议走 kernel transport/realm 的 PunchTraced（那边一直
		// 有回退）。2026-08-06 蜂窝实测用 hy2 配置反复看不到任何 relay 尝试，
		// 根因就是这里，不是中继或会合面的问题。
		//
		// 🔴 三条硬约束（与 kernel transport/realm 侧逐条对齐）：
		//  1. 只在会合面下发了 relay 时触发；空则一行不执行，老会合面行为不变。
		//  2. 复用打洞用的 socket 继续握手 —— hy2 服务端按源地址解复用，
		//     换 socket 收到的字节进不了协议栈。
		//  3. 回退失败时返回**原打洞错误**，错误原文一字不改（既有归类依赖它）。
		if len(response.Relay) == 0 {
			c.realmWarn("realm: punch failed and relay list is empty, not falling back to relay")
			return nil, nil, err
		}
		conn, joined, relayErr := c.realmDialRelay(ctx, response, obs)
		if !joined {
			return nil, nil, err
		}
		return conn, nil, relayErr
	}
	obs.PunchSucceeded(winner.family, result)
	sourcePort := M.SocksaddrFromNet(winner.conn.LocalAddr()).Port
	conn, err := c.realmHandshake(ctx, winner.conn, M.SocksaddrFromNetIP(result.PeerAddr), winner.family, obs)
	if err != nil {
		failures := c.relayFallback.handshakeFailed(time.Now())
		c.realmWarn("realm: handshake failed after punch (", failures, " consecutive, family ", winner.family, ", source port ", sourcePort, "): ", err)
		if !allowRelay {
			return nil, nil, err
		}
		if len(response.Relay) == 0 {
			c.realmWarn("realm: relay list is empty, not falling back to relay")
			return nil, nil, err
		}
		c.realmWarn("realm: falling back to relay with a fresh rendezvous")
		return nil, &realmRelayFallback{localAddresses: localAddresses}, err
	}
	// 握手成功不清零失败计数：要等直连验证通过（见 realm_direct_verify.go）。
	return conn, nil, nil
}

// offerNewRealmRelay 换新 nonce 重新 /connect，跳过打洞直接走中继。
// 是一次独立的建连：单独一条观测记录，nonce 与节点侧那条对得上。
func (c *Client) offerNewRealmRelay(ctx context.Context, fallback *realmRelayFallback) (*clientQUICConnection, error) {
	obs := c.newDialObserver()
	defer obs.Finish()
	obs.STUNDiscovered(fallback.localAddresses)
	localMetadata, err := realm.GeneratePunchMetadata()
	if err != nil {
		obs.Failed("rendezvous", err)
		return nil, E.Cause(err, "generate punch metadata")
	}
	response, err := c.controlClient.Connect(ctx, c.realmOptions.RealmID, fallback.localAddresses, localMetadata)
	if err != nil {
		obs.Failed("rendezvous", err)
		return nil, E.Cause(err, "realm connect")
	}
	obs.RendezvousDone(response.Addresses, response.PunchMetadata)
	if len(response.Relay) == 0 {
		err = E.New("relay list is empty")
		obs.Failed("punch", err)
		return nil, err
	}
	conn, joined, err := c.realmDialRelay(ctx, response, obs)
	if !joined {
		obs.Failed("punch", err)
	}
	return conn, err
}

// realmDialRelay 在新 socket 上向中继报到并握手。joined 报告是否已与节点对接：
// 未对接时调用方按各自约束处理（打洞失败的回退要返回原打洞错误）。
func (c *Client) realmDialRelay(ctx context.Context, response *realm.ConnectResponse, obs dialObserver) (*clientQUICConnection, bool, error) {
	// 打洞 socket 已关或仍在给打洞用，中继需要一只新的。
	relayConn, err := c.dialer.ListenPacket(ctx, M.SocksaddrFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		obs.RelaySettled("", err)
		return nil, false, err
	}
	relayAddr, err := realm.RaceRelayJoin(ctx, relayConn, response.Relay, response.PunchMetadata.Nonce)
	if err != nil {
		obs.RelaySettled("", err)
		_ = relayConn.Close()
		return nil, false, err
	}
	obs.RelaySettled(relayAddr.String(), nil)
	c.realmWarn("realm: joined relay ", relayAddr)
	conn, err := c.realmHandshake(ctx, relayConn, M.SocksaddrFromNetIP(relayAddr), "relay", obs)
	if err != nil {
		c.realmWarn("realm: handshake via relay ", relayAddr, " failed: ", err)
	}
	return conn, true, err
}

// realmHandshake 在打洞或中继得到的 socket 上加混淆、做 QUIC 握手与认证。
func (c *Client) realmHandshake(ctx context.Context, rawConn net.PacketConn, peerAddr M.Socksaddr, family string, obs dialObserver) (*clientQUICConnection, error) {
	packetConn := rawConn
	if c.geckoPassword != "" {
		packetConn = NewGeckoConn(packetConn, []byte(c.geckoPassword), c.geckoMinPacketSize, c.geckoMaxPacketSize)
	} else if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	conn, err := c.authenticateAndWrap(ctx, packetConn, peerAddr)
	if err != nil {
		obs.Failed("handshake", err)
		return nil, err
	}
	obs.HandshakeDone()
	conn.family = family
	c.attachStallWatch(conn, family)
	c.watchIdleTimeout(conn, family)
	if family == "relay" {
		c.probeDirectWhileRelayed(conn)
	} else {
		c.verifyDirect(conn)
	}
	return conn, nil
}

func (c *Client) realmOpenFamilies(ctx context.Context) ([]*realmFamilyConn, error) {
	type familySpec struct {
		family string
		ipv4   bool
		addr   M.Socksaddr
	}
	specs := []familySpec{
		{realm.PunchFamilyV4, true, M.SocksaddrFrom(netip.IPv4Unspecified(), 0)},
		{realm.PunchFamilyV6, false, M.SocksaddrFrom(netip.IPv6Unspecified(), 0)},
	}
	// punch_family 限定时只开该族的 socket，下游 STUN / 上报 / 打洞随之只走这一族。
	if only := c.realmOptions.PunchFamily; only != "" {
		specs = common.Filter(specs, func(spec familySpec) bool {
			return spec.family == only
		})
	}
	conns := make([]*realmFamilyConn, len(specs))
	listenErrs := make([]error, len(specs))
	var wg sync.WaitGroup
	for i, spec := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, listenErr := c.dialer.ListenPacket(ctx, spec.addr)
			if listenErr != nil {
				listenErrs[i] = E.Cause(listenErr, spec.family)
				return
			}
			conns[i] = &realmFamilyConn{family: spec.family, ipv4: spec.ipv4, conn: conn}
		}()
	}
	wg.Wait()
	var families []*realmFamilyConn
	var errs []error
	for i, family := range conns {
		if family != nil {
			families = append(families, family)
			continue
		}
		errs = append(errs, listenErrs[i])
	}
	if len(families) == 0 {
		return nil, E.Cause(E.Errors(errs...), "listen UDP for realm")
	}
	return families, nil
}

// realmFamilyDiscoverGrace:一个地址族先拿到 STUN 反射地址后,最多再等另一族这么久
// (见 realmDiscoverFamilies;取值与 kernel transport/realm familyDiscoverGrace 一致)。
const realmFamilyDiscoverGrace = 300 * time.Millisecond

func (c *Client) realmDiscoverFamilies(ctx context.Context, families []*realmFamilyConn) ([]*realmFamilyConn, []netip.AddrPort, error) {
	var needIPv4, needIPv6 bool
	for _, family := range families {
		if family.ipv4 {
			needIPv4 = true
		} else {
			needIPv6 = true
		}
	}
	stunServers, err := realm.ResolveSTUNServers(ctx, c.realmOptions.STUNServers, c.realmOptions.Resolver, needIPv4, needIPv6)
	if err != nil {
		for _, family := range families {
			_ = family.conn.Close()
		}
		return nil, nil, E.Cause(err, "resolve STUN servers")
	}
	type discoverResult struct {
		idx   int
		addrs []netip.AddrPort
		err   error
	}
	// ★各地址族并发探测,但**不等最慢的那一族**:某一族先拿到反射地址后,另一族最多再等
	// realmFamilyDiscoverGrace;到点没结果就取消它(cancel ctx + 把读 deadline 拨到现在让
	// ReadFrom 立刻返回),按"该族不可用"处理。
	//
	// 🔴 与 kernel transport/realm discoverFamilies 逐行对齐(e2ada7f,09-20)。当时只修了那边,
	// 漏了 hy2 这份老客户端实现 —— 而住宅面恰恰走 hy2。后果:策略下发 v6 STUN 后,"有 v6 地址
	// 但 v6 出不去"的设备(ULA-only / 运营商 v6 黑洞)每次连接都陪 v6 族跑满 STUN 重试
	// (0.5+2+4s),realm-cn-01 实测 v4-only 3.8s → v4+v6 8.1s。10-14 给 (ANY,JP) 加 v6 STUN
	// 后日本区 hy2 用户已暴露在这个代价下;(ANY,ANY) 加 v6 前必须先有本修复。
	// 纯 v4 设备(v6 发包即 ENETUNREACH)与双栈正常设备(两族几百毫秒内都回)行为不变。
	resultCh := make(chan discoverResult, len(families))
	cancels := make([]context.CancelFunc, len(families))
	for i, family := range families {
		familyCtx, cancel := context.WithCancel(ctx)
		cancels[i] = cancel
		go func() {
			servers := make([]netip.AddrPort, 0, len(stunServers))
			for _, server := range stunServers {
				if server.Addr().Is4() == family.ipv4 {
					servers = append(servers, server)
				}
			}
			addrs, discoverErr := realm.Discover(familyCtx, family.conn, servers)
			resultCh <- discoverResult{idx: i, addrs: addrs, err: discoverErr}
		}()
	}
	results := make([]discoverResult, len(families))
	received := make([]bool, len(families))
	var grace <-chan time.Time
	for done := 0; done < len(families); {
		select {
		case r := <-resultCh:
			results[r.idx] = r
			received[r.idx] = true
			done++
			if r.err == nil && grace == nil && done < len(families) {
				grace = time.After(realmFamilyDiscoverGrace)
			}
		case <-grace:
			grace = nil
			for i, family := range families {
				if !received[i] {
					cancels[i]()
					_ = family.conn.SetReadDeadline(time.Now())
				}
			}
		}
	}
	for _, cancel := range cancels {
		cancel()
	}
	var surviving []*realmFamilyConn
	var union []netip.AddrPort
	var errs []error
	for i, family := range families {
		result := results[i]
		if result.err != nil {
			errs = append(errs, E.Cause(result.err, family.family))
			_ = family.conn.Close()
			continue
		}
		family.localAddresses = result.addrs
		surviving = append(surviving, family)
		union = append(union, result.addrs...)
	}
	if len(surviving) == 0 {
		return nil, nil, E.Cause(E.Errors(errs...), "realm STUN discovery")
	}
	return surviving, union, nil
}

func (c *Client) realmRacePunch(
	ctx context.Context,
	families []*realmFamilyConn,
	peerAddresses []netip.AddrPort,
	metadata realm.PunchMetadata,
	obs dialObserver,
) (*realmFamilyConn, realm.PunchResult, error) {
	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()
	out := make(chan realm.PunchOutcome[*realmFamilyConn], len(families))
	for _, family := range families {
		go func() {
			peers := make([]netip.AddrPort, 0, len(peerAddresses))
			for _, peer := range peerAddresses {
				if peer.Addr().Is4() == family.ipv4 {
					peers = append(peers, peer)
				}
			}
			obs.PunchAttempted(family.family, peers)
			punchResult, punchErr := realm.Punch(raceCtx, family.conn, peers, metadata)
			out <- realm.PunchOutcome[*realmFamilyConn]{Family: family, IPv4: family.ipv4, Result: punchResult, Err: punchErr}
		}()
	}
	// ★v4 先打通时给 v6 一个让步窗口(见 realm.DefaultV6PreferGrace);本出口的 v4 连接
	// 刚因僵死被关过,窗口放大(见 v6PreferGrace)。
	winner, ok, failures := realm.SelectPunchWinner(out, len(families), c.v6PreferGrace())
	if ok {
		for _, family := range families {
			if family != winner.Family {
				_ = family.conn.Close()
			}
		}
		return winner.Family, winner.Result, nil
	}
	var errs []error
	for _, failure := range failures {
		errs = append(errs, E.Cause(failure.Err, failure.Family.family))
	}
	for _, family := range families {
		_ = family.conn.Close()
	}
	return nil, realm.PunchResult{}, E.Cause(E.Errors(errs...), "realm punch")
}

func (c *Client) authenticateAndWrap(ctx context.Context, packetConn net.PacketConn, peerAddr M.Socksaddr) (*clientQUICConnection, error) {
	var quicConn *quic.Conn
	http3Transport, err := qtls.CreateTransport(packetConn, &quicConn, peerAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	handshakeTimeout := c.tlsConfig.HandshakeTimeout()
	if handshakeTimeout <= 0 {
		handshakeTimeout = defaultHandshakeTimeout
	}
	authCtx, authCancel := context.WithTimeout(ctx, handshakeTimeout)
	defer authCancel()
	response, err := http3Transport.RoundTrip(request.WithContext(authCtx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		timeFunc := ntp.TimeFuncFromContext(c.ctx)
		if timeFunc == nil {
			timeFunc = time.Now
		}
		quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(
			congestion_meta2.DefaultClock{TimeFunc: timeFunc},
			congestion.ByteCount(quicConn.Config().InitialPacketSize),
			c.bbrProfile,
		))
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	conn.streams.Add(1)
	clientConn := &clientConn{
		Stream:      stream,
		destination: destination,
		release:     sync.OnceFunc(func() { conn.streams.Add(-1) }),
	}
	if conn.stall != nil {
		clientConn.stall = &streamStall{watch: conn.stall}
	}
	return clientConn, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	})
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.closed.Store(true)
	c.connAccess.Lock()
	conn := c.conn
	c.conn = nil
	pending := c.pending
	if pending != nil {
		pending.discarded = true
		pending.cause = err
	}
	c.connAccess.Unlock()

	if pending != nil {
		pending.cancel(err)
	}
	if conn != nil {
		conn.closeWithError(err)
	}
	return nil
}

type clientOffer struct {
	done      chan struct{}
	cancel    func(error)
	conn      *clientQUICConnection
	err       error
	discarded bool
	cause     error
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
	// 僵死检测(仅 realm 连接,非 realm 为 nil),见 realm_stall.go。
	stall *stallWatch
	// realm 连接的地址族("v4"/"v6"/"relay",非 realm 为空)。
	family string
	// 未关闭的 TCP 流数,中继切回直连后据此排空,见 realm_direct_probe.go。
	streams atomic.Int32
	// 直连(v4/v6)验证通过时关闭,中继连接为 nil,见 realm_direct_verify.go。
	verified chan struct{}
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
	stall          *streamStall // 仅 realm 连接
	release        func()       // 归还所属连接的流计数,只生效一次
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, qtls.WrapError(err)
	}
	if c.stall != nil {
		c.stall.readStarted.Store(true)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, qtls.WrapError(err)
	}
	// 收到响应(含 remote error)= 服务端收到了这条流,连接是活的。
	if c.stall != nil {
		c.stall.responseReceived()
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		if c.stall != nil {
			c.stall.requestSent()
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, qtls.WrapError(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	if c.release != nil {
		c.release()
	}
	if c.stall != nil {
		c.stall.stop()
	}
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
