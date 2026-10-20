package hysteria2

import (
	"sync"
	"testing"
)

func newTestQUICConnection() *clientQUICConnection {
	return &clientQUICConnection{
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
}

func TestSwapConnOnlyReplacesExpected(t *testing.T) {
	relay, direct, other := newTestQUICConnection(), newTestQUICConnection(), newTestQUICConnection()
	c := &Client{conn: relay}
	if !c.swapConn(relay, direct) || c.conn != direct {
		t.Fatal("swap from current relay to direct failed")
	}
	// 中继在探测期间已被替换：不得覆盖新连接。
	c.conn = other
	if c.swapConn(relay, direct) || c.conn != other {
		t.Fatal("swapped over a connection that replaced the relay")
	}
	c.conn = relay
	c.closed.Store(true)
	if c.swapConn(relay, direct) {
		t.Fatal("swapped after client closed")
	}
}

func TestQUICConnectionIdleTracksStreamsAndUDP(t *testing.T) {
	conn := newTestQUICConnection()
	if !conn.idle() {
		t.Fatal("fresh connection not idle")
	}
	conn.streams.Add(1)
	stream := &clientConn{release: sync.OnceFunc(func() { conn.streams.Add(-1) })}
	if conn.idle() {
		t.Fatal("idle with an open stream")
	}
	// Close 可能被调多次（路由层与 copy 两侧），计数只能减一次。
	stream.release()
	stream.release()
	if got := conn.streams.Load(); got != 0 {
		t.Fatalf("streams = %d after double release, want 0", got)
	}
	conn.udpConnMap[1] = &udpPacketConn{}
	if conn.idle() {
		t.Fatal("idle with an open UDP session")
	}
	delete(conn.udpConnMap, 1)
	if !conn.idle() {
		t.Fatal("not idle after streams and UDP sessions ended")
	}
}
