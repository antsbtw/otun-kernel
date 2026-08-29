// Package netbind is the probe app's "network-binding dialer"
// (PROBE_APP_REQUIREMENT.md §3): an N.Dialer whose every socket — the realm
// punch/relay UDP sockets, the rendezvous control-channel TCP connection, and
// (optionally) DNS lookups — is handed to a caller-supplied Binder at creation
// time, BEFORE any traffic flows. On Android the shell implements Binder with
// android.net.Network.bindSocket(fd), forcing the socket onto an explicitly
// requested network (TRANSPORT_CELLULAR / TRANSPORT_WIFI via
// ConnectivityManager.requestNetwork) even while the other network is up.
//
// 探针的可信性依赖强绑定：如果绑定失败还静默落回默认网络，测出来的就是
// 「假蜂窝」样本（同型于 gen_204 假判据教训）。所以本包 fail-closed —— Binder
// 返回错误则 socket 创建失败，绝不带着错误的网络继续探测。
//
// 用法（探针入口，下一里程碑）：
//
//	d := netbind.NewDialer(binder)        // binder 由 Android 壳实现
//	cfg := realm.Config{
//	    Dialer:     d,                    // punch + relay 的全部 UDP socket
//	    HTTPClient: d.HTTPClient(insecure), // 会合面 control 通道
//	    Resolver:   d.Resolver(),         // STUN 域名解析（生产全 IP，兜底用）
//	    ...
//	}
//
// binder == nil 时各方法与内核现有的「无 Dialer 兜底路径」行为一致（裸
// net.ListenUDP / net.Dialer），便于在 Linux 上跑同一套探针代码。
//
// gomobile 兼容性：Binder 只用 int64 + error，可直接被 gomobile 绑定导出。
// Android 侧的典型实现（壳里写，不在本包）：
//
//	ParcelFileDescriptor pfd = ParcelFileDescriptor.fromFd((int) fd); // dup，共享同一 socket
//	network.bindSocket(pfd.getFileDescriptor());                      // 绑定作用于 socket 本体
//	pfd.close();                                                      // 关掉 dup 不影响原 fd
package netbind

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"syscall"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// Binder receives the raw socket fd right after the socket is created and
// before it is used. Implementations bind it to the chosen network (Android:
// Network.bindSocket). Returning an error aborts the socket — fail-closed,
// never probe over the wrong network.
type Binder interface {
	BindFD(fd int64) error
}

// Dialer implements sing's N.Dialer (DialContext + ListenPacket). Every socket
// it creates passes through the Binder. The zero value / nil-binder form is
// equivalent to the kernel's no-Dialer fallback (plain sockets, no binding).
type Dialer struct {
	binder Binder
}

// NewDialer wraps binder into a network-binding N.Dialer. binder may be nil
// (plain sockets — Linux 上跑探针逻辑时用).
func NewDialer(binder Binder) *Dialer {
	return &Dialer{binder: binder}
}

// control is the net.Dialer / net.ListenConfig Control hook: it runs on the
// created-but-unconnected socket and hands the fd to the Binder.
func (d *Dialer) control(_, _ string, c syscall.RawConn) error {
	if d.binder == nil {
		return nil
	}
	var bindErr error
	if err := c.Control(func(fd uintptr) {
		bindErr = d.binder.BindFD(int64(fd))
	}); err != nil {
		return err
	}
	if bindErr != nil {
		return E.Cause(bindErr, "netbind: bind socket to network")
	}
	return nil
}

// ListenPacket opens a UDP socket bound to the chosen network. Mirrors the
// kernel fallback `net.ListenUDP("udp", addr)` semantics (address literal
// decides the family), so swapping this in changes binding only, not behavior.
func (d *Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: d.control}
	return lc.ListenPacket(ctx, "udp", destination.String())
}

// DialContext dials network/destination with the socket bound before connect.
// Domain destinations are resolved through the bound Resolver first — the
// default system resolver would leak the DNS query onto the default network
// and may even answer with a different CDN edge than the probed network sees.
func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialString(ctx, network, destination.String())
}

// dialString is DialContext over a plain "host:port" (also the shape
// http.Transport.DialContext wants).
func (d *Dialer) dialString(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	nd := net.Dialer{Control: d.control}
	if _, ipErr := netip.ParseAddr(host); ipErr == nil || d.binder == nil {
		// IP 字面量直接拨；nil-binder 时也走系统解析（与裸 net.Dialer 等价）。
		return nd.DialContext(ctx, network, address)
	}
	addrs, err := d.Resolver()(ctx, host, true, true)
	if err != nil {
		return nil, E.Cause(err, "netbind: resolve ", host)
	}
	var errs []error
	for _, addr := range addrs {
		conn, dialErr := nd.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		errs = append(errs, dialErr)
	}
	return nil, E.Cause(E.Errors(errs...), "netbind: dial ", host)
}

// Resolver returns a realm.Config.Resolver-shaped resolver:
//   - IP 字面量短路返回（生产 STUN 全是 IP:port，这是主路径）；
//   - 域名走 pure-Go DNS，其 UDP/TCP socket 同样经 Binder 绑定 —— DNS 走错
//     网络会解出另一张网的视角，探测数据即失真。
func (d *Dialer) Resolver() func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			nd := net.Dialer{Control: d.control}
			return nd.DialContext(ctx, network, address)
		},
	}
	return func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
		if addr, err := netip.ParseAddr(host); err == nil {
			if (addr.Is4() || addr.Is4In6()) && !ipv4 || addr.Is6() && !addr.Is4In6() && !ipv6 {
				return nil, E.New("netbind: address family of ", host, " not requested")
			}
			return []netip.Addr{addr}, nil
		}
		network := "ip"
		switch {
		case ipv4 && !ipv6:
			network = "ip4"
		case !ipv4 && ipv6:
			network = "ip6"
		}
		return r.LookupNetIP(ctx, network, host)
	}
}

// HTTPClient returns an *http.Client for the rendezvous control channel whose
// TCP connections are bound to the chosen network. insecureTLS skips
// certificate verification — the production rendezvous runs on a bare-IP
// self-signed cert (enum API 的 rendezvous_insecure=true 即此含义)。
func (d *Dialer) HTTPClient(insecureTLS bool) *http.Client {
	transport := &http.Transport{
		DialContext:       d.dialString,
		ForceAttemptHTTP2: true,
	}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport}
}
