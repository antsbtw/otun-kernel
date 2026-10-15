package hysteria2

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/realm"
)

func newTestWatch() (*stallWatch, *atomic.Int32) {
	var dead atomic.Int32
	w := &stallWatch{}
	w.onDead = func(int) { dead.Add(1) }
	return w, &dead
}

// 连续 3 条流无响应、期间整条连接零响应 → 判僵死,且只触发一次。
func TestStallWatchDeclaresDeadAfterConsecutiveStalls(t *testing.T) {
	w, dead := newTestWatch()
	t0 := time.Now()
	w.noteStall(t0)
	w.noteStall(t0)
	if dead.Load() != 0 {
		t.Fatal("must not declare dead before threshold")
	}
	w.noteStall(t0)
	w.noteStall(t0)
	if dead.Load() != 1 {
		t.Fatalf("onDead calls = %d, want exactly 1", dead.Load())
	}
}

// 某条流请求发出之后连接收到过响应(别的流活着)→ 这条慢流不计;响应还会清零计数。
func TestStallWatchIgnoresSlowStreamOnLiveConnection(t *testing.T) {
	w, dead := newTestWatch()
	requestAt := time.Now()
	w.noteStall(requestAt)
	w.noteStall(requestAt)
	time.Sleep(2 * time.Millisecond)
	w.noteResponse() // 另一条流拿到了响应
	w.noteStall(requestAt)
	w.noteStall(requestAt)
	w.noteStall(requestAt)
	if dead.Load() != 0 {
		t.Fatal("stalls of requests sent before a later response must not count")
	}
	// 响应之后新发的请求再连续无响应,才重新计数
	later := time.Now().Add(time.Millisecond)
	w.noteStall(later)
	w.noteStall(later)
	w.noteStall(later)
	if dead.Load() != 1 {
		t.Fatalf("want dead after 3 fresh stalls, got %d", dead.Load())
	}
}

// 读方没开始读时不计(响应可能只是没人读);已收到响应的流不计。
func TestStreamStallSkipsUnreadAndResponded(t *testing.T) {
	w, dead := newTestWatch()
	unread := &streamStall{watch: w}
	responded := &streamStall{watch: w}
	responded.readStarted.Store(true)
	responded.responded.Store(true)
	for _, s := range []*streamStall{unread, responded} {
		for i := 0; i < 3; i++ {
			if s.responded.Load() || !s.readStarted.Load() {
				continue
			}
			w.noteStall(time.Now())
		}
	}
	if dead.Load() != 0 {
		t.Fatal("unread / responded streams must never count as stalls")
	}
}

// v4 连接僵死后进入 v6 偏好期,让步窗口放大;偏好期外是默认窗口。
func TestV6PreferGraceAfterV4Stall(t *testing.T) {
	c := &Client{}
	if got := c.v6PreferGrace(); got != realm.DefaultV6PreferGrace {
		t.Fatalf("default grace = %v", got)
	}
	c.preferV6Until.Store(time.Now().Add(time.Minute).UnixNano())
	if got := c.v6PreferGrace(); got != stalledV6PreferGrace {
		t.Fatalf("grace after v4 stall = %v, want %v", got, stalledV6PreferGrace)
	}
	c.preferV6Until.Store(time.Now().Add(-time.Second).UnixNano())
	if got := c.v6PreferGrace(); got != realm.DefaultV6PreferGrace {
		t.Fatalf("expired prefer window must fall back, got %v", got)
	}
}
