package netbind_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/netbind"
	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/transport/realm"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

// recordingBinder 记录经手的每个 fd —— 单测里替代 Android 侧的
// Network.bindSocket，断言「socket 确实在使用前交到了 Binder 手上」。
type recordingBinder struct {
	mu  sync.Mutex
	fds []int64
	err error // 非 nil 时模拟绑定失败（fail-closed 路径）
}

func (b *recordingBinder) BindFD(fd int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.fds = append(b.fds, fd)
	return nil
}

func (b *recordingBinder) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.fds)
}

func (b *recordingBinder) allPositive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, fd := range b.fds {
		if fd <= 0 {
			return false
		}
	}
	return true
}

func loopbackAddr(port uint16) M.Socksaddr {
	return M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), port)
}

// UDP socket 经 Binder 且可用（自发自收证明绑定钩子没破坏 socket）。
func TestListenPacketBindsAndWorks(t *testing.T) {
	binder := &recordingBinder{}
	d := netbind.NewDialer(binder)

	conn, err := d.ListenPacket(context.Background(), loopbackAddr(0))
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()
	if binder.count() != 1 || !binder.allPositive() {
		t.Fatalf("binder must see exactly the one socket fd, got %d (positive=%v)", binder.count(), binder.allPositive())
	}

	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := conn.WriteTo([]byte("ping"), peer.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, _, err := peer.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("peer read: n=%d err=%v", n, err)
	}
}

// TCP 拨号经 Binder 且数据可通。
func TestDialContextBindsAndWorks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		_, _ = c.Write([]byte("hello"))
		_ = c.Close()
	}()

	binder := &recordingBinder{}
	d := netbind.NewDialer(binder)
	addr := ln.Addr().(*net.TCPAddr)
	conn, err := d.DialContext(context.Background(), "tcp", loopbackAddr(uint16(addr.Port)))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if binder.count() != 1 || !binder.allPositive() {
		t.Fatalf("binder must see the dial socket fd, got %d", binder.count())
	}
	buf := make([]byte, 8)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("read: n=%d err=%v", n, err)
	}
}

// 绑定失败必须让 socket 创建失败（fail-closed）——静默落回默认网络会产出
// 「假蜂窝」探测样本，比失败更糟。
func TestBindFailureFailsClosed(t *testing.T) {
	d := netbind.NewDialer(&recordingBinder{err: E.New("no such network")})
	if _, err := d.ListenPacket(context.Background(), loopbackAddr(0)); err == nil {
		t.Fatal("ListenPacket must fail when the binder fails")
	}
	if _, err := d.DialContext(context.Background(), "tcp", loopbackAddr(9)); err == nil {
		t.Fatal("DialContext must fail when the binder fails")
	}
}

// nil binder = 与内核无 Dialer 兜底等价：能开 socket，不 panic。
func TestNilBinderPlainSockets(t *testing.T) {
	d := netbind.NewDialer(nil)
	conn, err := d.ListenPacket(context.Background(), loopbackAddr(0))
	if err != nil {
		t.Fatalf("ListenPacket with nil binder: %v", err)
	}
	_ = conn.Close()
}

// Resolver：IP 字面量短路 + 家族过滤（生产 STUN 全 IP，这是主路径）。
func TestResolverIPLiteral(t *testing.T) {
	resolve := netbind.NewDialer(&recordingBinder{}).Resolver()
	addrs, err := resolve(context.Background(), "203.0.113.7", true, true)
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("v4 literal: addrs=%v err=%v", addrs, err)
	}
	if _, err := resolve(context.Background(), "203.0.113.7", false, true); err == nil {
		t.Fatal("v4 literal with ipv4=false must be rejected")
	}
	addrs, err = resolve(context.Background(), "2001:db8::1", false, true)
	if err != nil || len(addrs) != 1 {
		t.Fatalf("v6 literal: addrs=%v err=%v", addrs, err)
	}
}

// 集成断言（本包存在的意义）：把 netbind 挂进 realm.PunchTraced 的真实调用，
// 证明打洞路径的【每一只】socket —— v4/v6 family UDP + 会合面 control TCP ——
// 都经过了 Binder。realm 未注册所以最终在 rendezvous 阶段失败（预期，不需要
// 真节点），但失败前 socket 已全部开出：STUN 已应答、control 已通 HTTP。
func TestRealmPunchSocketsAllPassBinder(t *testing.T) {
	stunAddr := realmtest.STUN(t)
	rvURL, _ := realmtest.Rendezvous(t, "test-token")

	binder := &recordingBinder{}
	d := netbind.NewDialer(binder)
	cfg := realm.Config{
		ServerURL:   rvURL,
		Token:       "test-token",
		STUNServers: []string{stunAddr.String()},
		Resolver:    realmtest.Resolver,
		Dialer:      d,
		HTTPClient:  d.HTTPClient(false),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := realm.PunchTraced(ctx, cfg, "netbind-test-realm", nil)
	if err == nil {
		t.Fatal("punch against a rendezvous with no registered node must fail")
	}

	// v4 family UDP 必有；v6 family 视机器而定；control TCP 必有 ⇒ 下限 2。
	// 关键不是精确数量，而是「HTTP 走了我们的 client、UDP 走了我们的 Dialer」。
	if binder.count() < 2 {
		t.Fatalf("binder saw only %d sockets; realm punch must route ALL sockets (UDP families + control TCP) through it", binder.count())
	}
	if !binder.allPositive() {
		t.Fatal("binder received an invalid fd")
	}
}
