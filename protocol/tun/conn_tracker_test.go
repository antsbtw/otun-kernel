package tun

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
)

// recordStack 在 Close 时检查 App 侧连接是否已经收到 EOF —— 即 FIN 是否在拆栈之前发出。
type recordStack struct {
	peer          net.Conn
	peerClosedRun bool
}

func (s *recordStack) Start() error { return nil }

func (s *recordStack) Close() error {
	_ = s.peer.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_, err := s.peer.Read(make([]byte, 1))
	s.peerClosedRun = err == io.EOF
	return nil
}

// K1 验收的内核侧：Inbound.Close 必须先关 TUN 入站连接、等待，再拆协议栈。
func TestInboundCloseClosesConnectionsBeforeStack(t *testing.T) {
	appSide, kernelSide := net.Pipe()
	defer appSide.Close()
	stack := &recordStack{peer: appSide}
	inbound := &Inbound{
		tunStack: stack,
		logger:   log.NewNOPFactory().Logger(),
	}
	onClose, ok := inbound.connTracker.track(kernelSide, nil)
	if !ok || onClose == nil {
		t.Fatal("track rejected connection before close")
	}

	start := time.Now()
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if !stack.peerClosedRun {
		t.Fatal("tun connection was not closed before stack shutdown")
	}
	if elapsed := time.Since(start); elapsed < tunConnDrainDelay {
		t.Fatalf("stack closed after %v, want drain delay >= %v", elapsed, tunConnDrainDelay)
	}
}

func TestInboundCloseWithoutConnectionsSkipsDelay(t *testing.T) {
	appSide, kernelSide := net.Pipe()
	defer appSide.Close()
	defer kernelSide.Close()
	inbound := &Inbound{
		tunStack: &recordStack{peer: appSide},
		logger:   log.NewNOPFactory().Logger(),
	}
	start := time.Now()
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed >= tunConnDrainDelay {
		t.Fatalf("close without connections took %v, want no drain delay", elapsed)
	}
}

func TestTunConnTrackerRemovesFinishedConnections(t *testing.T) {
	var tracker tunConnTracker
	_, conn := net.Pipe()
	var gotErr error
	called := 0
	onClose, ok := tracker.track(conn, func(err error) {
		called++
		gotErr = err
	})
	if !ok {
		t.Fatal("track rejected connection")
	}
	onClose(io.EOF)
	onClose(io.EOF) // 路由层个别路径可能重复回调，不得 panic 或错删
	if tracker.conns.Len() != 0 {
		t.Fatalf("tracked %d connections after close, want 0", tracker.conns.Len())
	}
	if called != 2 || gotErr != io.EOF {
		t.Fatalf("original onClose called %d times with %v", called, gotErr)
	}
	if closed := tracker.closeAll(); closed != 0 {
		t.Fatalf("closeAll closed %d finished connections", closed)
	}
}

func TestTunConnTrackerRejectsAfterClose(t *testing.T) {
	var tracker tunConnTracker
	tracker.closeAll()
	appSide, kernelSide := net.Pipe()
	defer appSide.Close()
	var gotErr error
	onClose, ok := tracker.track(kernelSide, func(err error) { gotErr = err })
	if ok || onClose != nil {
		t.Fatal("track accepted connection after closeAll")
	}
	if gotErr != net.ErrClosed {
		t.Fatalf("onClose got %v, want net.ErrClosed", gotErr)
	}
	_ = appSide.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := appSide.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("rejected connection not closed: %v", err)
	}
}

// closeAll 在锁外关连接：Close 同步回调 onClose（拿同一把锁）时不得死锁。
func TestTunConnTrackerCloseAllWithSynchronousCallback(t *testing.T) {
	var tracker tunConnTracker
	var onClose func(error)
	conn := &callbackConn{onClose: func() { onClose(net.ErrClosed) }}
	onClose, _ = tracker.track(conn, nil)
	done := make(chan int, 1)
	go func() { done <- tracker.closeAll() }()
	select {
	case closed := <-done:
		if closed != 1 {
			t.Fatalf("closed %d, want 1", closed)
		}
	case <-time.After(time.Second):
		t.Fatal("closeAll deadlocked on synchronous onClose")
	}
	if tracker.conns.Len() != 0 {
		t.Fatalf("tracked %d connections after closeAll, want 0", tracker.conns.Len())
	}
}

type callbackConn struct {
	net.Conn
	onClose func()
}

func (c *callbackConn) Close() error {
	c.onClose()
	return nil
}
