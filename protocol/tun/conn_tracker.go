package tun

import (
	"net"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
)

// tunConnDrainDelay 是关完 TUN 入站连接后、拆协议栈前的等待时间：
// 给 FIN 经 tunLoop + NAT 写回 utun 留出余量（需求 K1 要求 100~200ms）。
const tunConnDrainDelay = 150 * time.Millisecond

// tunConnTracker 登记 TUN 入站的全部 TCP 连接，供 Inbound.Close 在拆栈**之前**
// 从 App 一侧正常关闭它们（CLIENT_REQ_2026-10-20 K1）。
//
// 🔴 为什么必须在拆栈前关：Box.Close 先关 inbound、后关 outbound。原顺序下
// App 侧连接要等出站死掉、connectionCopy 结束才被关，那时 tunLoop 已停、NAT
// 表已拆，FIN 送不回 App —— apsd 这类只收不发的连接会卡在死连接上 2~7 分钟。
//
// 🔴 只做正常 Close，不在 NAT 层手搓 RST：
//   - system 栈下 conn 是本进程从监听端口 accept 的系统 socket，Close 由系统
//     TCP 栈生成序号正确的 FIN；
//   - gvisor 栈下 Close 落到 gvisor endpoint，FIN/RST 由 gvisor 状态机生成，
//     只要发生在 GVisor.Close 的 Attach(nil) 之前，链路仍然挂着，包能写出。
//
// NAT 不跟踪序号，手搓的 RST 会被系统按 RFC 5961 判为序号不对，只换来 challenge ACK。
type tunConnTracker struct {
	access  sync.Mutex
	conns   list.List[net.Conn]
	closing bool
}

// track 登记 conn，返回包装后的 onClose（连接结束时移除登记）。
// 已进入关闭流程时直接关掉 conn，返回 ok=false，调用方不应再路由它。
func (t *tunConnTracker) track(conn net.Conn, onClose N.CloseHandlerFunc) (N.CloseHandlerFunc, bool) {
	t.access.Lock()
	if t.closing {
		t.access.Unlock()
		_ = conn.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return nil, false
	}
	element := t.conns.PushBack(conn)
	t.access.Unlock()
	return func(err error) {
		t.access.Lock()
		// list.Remove 对已移除的元素是空操作，onClose 被调多次也安全。
		t.conns.Remove(element)
		t.access.Unlock()
		if onClose != nil {
			onClose(err)
		}
	}, true
}

// closeAll 关闭全部已登记连接并拒绝之后的新连接，返回关闭的条数。
// 在锁外关：Close 会经路由层回调 onClose，回调里要拿同一把锁。
func (t *tunConnTracker) closeAll() int {
	t.access.Lock()
	t.closing = true
	conns := make([]net.Conn, 0, t.conns.Len())
	for element := t.conns.Front(); element != nil; element = element.Next() {
		conns = append(conns, element.Value)
	}
	t.access.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return len(conns)
}
