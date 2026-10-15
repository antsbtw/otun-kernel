package hysteria2

// realm_stall.go —— realm(住宅面)连接的「僵死」检测 + v4 僵死后的 v6 偏好。
//
// ★背景(2026-10-15 中国移动 iPhone 真机,BACKEND_REPLY_2026-10-14 §3.2):
//   jp-02 上一条 v4 的 QUIC 连接在节点侧一直活着(旧流陆续关闭到 03:59),但 03:54:18 之后
//   **一条新流都没到节点**;客户端 7 分钟没有重新打洞,04:01 连接终于断掉、重打洞碰巧落到
//   v6 才恢复。保活 PING 是小包能过,所以 QUIC 空闲超时(30s)永远不触发;而新流的请求
//   过不去 —— 连接对内核来说"活着",对用户来说是死的。
//
// 判据:hy2 每条 TCP 流发出请求后,服务端拨通目标就回一个 TCP 响应(成功或 remote error
//   都算 —— 都证明服务端收到了这条流)。所以:
//   - 一条流请求发出后 streamStallTimeout 内没收到响应 = 一次「无响应」;
//   - 只有当**这条请求发出之后整条连接一个响应都没收到**才计数 —— 单个目标慢不会误判,
//     连接上只要还有别的流拿到响应,计数就清零;
//   - 连续 stallStreamsToDeclareDead 次 → 判定僵死,关闭连接;下一次拨号重新打洞
//     (v4/v6 重新竞速)。
//   - 读方还没开始读时不计(响应可能只是没人读),避免把"应用没读"当成"连接死了"。
//
// 只对 realm 连接启用(Client.realmOptions != nil):标准 hy2 行为不变。

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/realm"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// 流请求发出后等服务端响应的时限。服务端拨目标通常 <2s,跨境 RTT 200-300ms,留足余量。
	streamStallTimeout = 8 * time.Second
	// 连续这么多条流无响应(且期间整条连接零响应)即判僵死。
	stallStreamsToDeclareDead = 3
	// v4 连接僵死后,这段时间内本出口打洞时 v6 的让步窗口放大到 stalledV6PreferGrace。
	preferV6Window       = 10 * time.Minute
	stalledV6PreferGrace = 2 * time.Second
)

// stallWatch 挂在 clientQUICConnection 上,记录这条连接的流响应情况。
type stallWatch struct {
	access       sync.Mutex
	lastResponse time.Time
	stalled      int
	// onDead 由 Client 注入:关闭连接 + 记日志 + (v4 时)进入 v6 偏好期。只会被调用一次。
	onDead   func(stalled int)
	deadOnce sync.Once
}

func (w *stallWatch) noteResponse() {
	w.access.Lock()
	w.lastResponse = time.Now()
	w.stalled = 0
	w.access.Unlock()
}

// noteStall 记一次无响应;requestAt 之后连接收到过任何响应则不计。返回是否已判僵死。
func (w *stallWatch) noteStall(requestAt time.Time) {
	w.access.Lock()
	if w.lastResponse.After(requestAt) {
		w.access.Unlock()
		return
	}
	w.stalled++
	stalled := w.stalled
	w.access.Unlock()
	if stalled >= stallStreamsToDeclareDead && w.onDead != nil {
		w.deadOnce.Do(func() { w.onDead(stalled) })
	}
}

// streamStall 挂在单条 clientConn 上。
type streamStall struct {
	watch       *stallWatch
	readStarted atomic.Bool
	responded   atomic.Bool
	// Write(发请求)与 Read/Close 在不同 goroutine,timer 必须原子读写。
	timer atomic.Pointer[time.Timer]
}

func (s *streamStall) requestSent() {
	requestAt := time.Now()
	s.timer.Store(time.AfterFunc(streamStallTimeout, func() {
		if s.responded.Load() || !s.readStarted.Load() {
			return
		}
		s.watch.noteStall(requestAt)
	}))
}

func (s *streamStall) responseReceived() {
	s.responded.Store(true)
	s.stop()
	s.watch.noteResponse()
}

func (s *streamStall) stop() {
	if timer := s.timer.Load(); timer != nil {
		timer.Stop()
	}
}

// attachStallWatch 给新建的 realm 连接挂上僵死检测。family:"v4"/"v6"/"relay"。
func (c *Client) attachStallWatch(conn *clientQUICConnection, family string) {
	watch := &stallWatch{}
	watch.onDead = func(stalled int) {
		if c.logger != nil {
			c.logger.Warn("realm: connection stalled (", stalled, " streams without response, family ", family, "), closing to re-punch")
		}
		if family == "v4" {
			c.preferV6Until.Store(time.Now().Add(preferV6Window).UnixNano())
		}
		conn.closeWithError(E.New("realm: connection stalled"))
	}
	conn.stall = watch
}

// v6PreferGrace:打洞时 v4 先通后给 v6 的让步窗口。本出口的 v4 连接最近僵死过 → 放大。
func (c *Client) v6PreferGrace() time.Duration {
	if until := c.preferV6Until.Load(); until != 0 && time.Now().UnixNano() < until {
		return stalledV6PreferGrace
	}
	return realm.DefaultV6PreferGrace
}
