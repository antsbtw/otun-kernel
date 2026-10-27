package group

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// fakeOutbound：测速时 up=true 就回 204，否则拨号失败。
type fakeOutbound struct {
	adapter.Outbound
	tag string
	up  atomic.Bool
}

func (o *fakeOutbound) Tag() string       { return o.tag }
func (o *fakeOutbound) Network() []string { return []string{N.NetworkTCP, N.NetworkUDP} }

func (o *fakeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !o.up.Load() {
		return nil, E.New(o.tag, " down")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		if _, err := http.ReadRequest(bufio.NewReader(server)); err != nil {
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
	}()
	return client, nil
}

// fakeOutboundManager：urlTest 只用 Outbound(tag) 按名字取节点。
type fakeOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
}

func (m *fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, o := range m.outbounds {
		if o.Tag() == tag {
			return o, true
		}
	}
	return nil, false
}

func newFailoverGroup(t *testing.T, strikes int, outbounds ...adapter.Outbound) *URLTestGroup {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	g, err := NewURLTestGroup(ctx, &fakeOutboundManager{outbounds: outbounds}, log.NewNOPFactory().Logger(), outbounds, "http://probe.test/generate_204", 0, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	g.failoverStrikes = strikes
	return g
}

func selectedTag(g *URLTestGroup) string {
	if g.selectedOutboundTCP == nil {
		return ""
	}
	return g.selectedOutboundTCP.Tag()
}

func TestFailoverStaysOnPrimaryUntilTwoConsecutiveFailures(t *testing.T) {
	primary := &fakeOutbound{tag: "primary"}
	backup := &fakeOutbound{tag: "backup"}
	primary.up.Store(true)
	backup.up.Store(true)
	g := newFailoverGroup(t, 2, primary, backup)

	// 还没测速：拨号用第一个（primary）。
	if o, _ := g.Select(N.NetworkTCP); o.Tag() != "primary" {
		t.Fatalf("before any check: got %s, want primary", o.Tag())
	}

	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("both up: got %s, want primary", got)
	}

	// 第一次失败：不切。
	primary.up.Store(false)
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("after 1 failure: got %s, want primary", got)
	}

	// 中间测通一次：计数清零，再失败一次仍不切。
	primary.up.Store(true)
	g.CheckOutbounds(true)
	primary.up.Store(false)
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("failure count should reset after success: got %s", got)
	}

	// 连续第二次失败：切到 backup。
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "backup" {
		t.Fatalf("after 2 consecutive failures: got %s, want backup", got)
	}

	// primary 恢复：不切回。
	primary.up.Store(true)
	g.CheckOutbounds(true)
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "backup" {
		t.Fatalf("primary recovered: got %s, want to stay on backup", got)
	}

	// backup 连续失败两次：回到 primary。
	backup.up.Store(false)
	g.CheckOutbounds(true)
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("backup failed twice: got %s, want primary", got)
	}
}

func TestFailoverPrimaryDownAtStart(t *testing.T) {
	primary := &fakeOutbound{tag: "primary"}
	backup := &fakeOutbound{tag: "backup"}
	backup.up.Store(true)
	g := newFailoverGroup(t, 2, primary, backup)

	// 启动时 primary 第一次就测不通：仍留在 primary，等第二次。
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("1st failure at start: got %s, want primary", got)
	}
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "backup" {
		t.Fatalf("2nd failure at start: got %s, want backup", got)
	}
}

func TestFailoverIgnoresLatency(t *testing.T) {
	primary := &fakeOutbound{tag: "primary"}
	backup := &fakeOutbound{tag: "backup"}
	primary.up.Store(true)
	backup.up.Store(true)
	g := newFailoverGroup(t, 2, primary, backup)
	g.CheckOutbounds(true)
	// 人为让 backup 的记录比 primary 快很多：主备模式不看延迟。
	g.history.StoreURLTestHistory("primary", &adapter.URLTestHistory{Delay: 900})
	g.history.StoreURLTestHistory("backup", &adapter.URLTestHistory{Delay: 10})
	g.performUpdateCheck()
	if got := selectedTag(g); got != "primary" {
		t.Fatalf("latency should not matter: got %s", got)
	}
}

func TestNonFailoverModeUnchanged(t *testing.T) {
	primary := &fakeOutbound{tag: "primary"}
	backup := &fakeOutbound{tag: "backup"}
	primary.up.Store(true)
	backup.up.Store(true)
	g := newFailoverGroup(t, 0, primary, backup)
	g.CheckOutbounds(true)
	primary.up.Store(false)
	g.CheckOutbounds(true)
	if got := selectedTag(g); got != "backup" {
		t.Fatalf("plain urltest should switch after one failure: got %s", got)
	}
}
