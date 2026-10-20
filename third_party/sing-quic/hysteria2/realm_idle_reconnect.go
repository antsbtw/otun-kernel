package hysteria2

import (
	"context"
	"errors"

	"github.com/sagernet/quic-go"
)

// 住宅面 QUIC 连接因空闲超时关闭后主动重连（CLIENT_REQ_2026-10-20 K3）。
//
// ★ 现场：出口最后收到手机的包 → 手机换端口重连约 76s。其中 30s 是 MaxIdleTimeout，
// 之后要等有新流才惰性拨号（offer）。推送这类只收不发的连接不开新流，
// 隧道就一直没有连接，节点的下行无处可去。
//
// ★ KeepAlivePeriod（10s）远小于 MaxIdleTimeout（30s），连接活着时不会空闲超时；
// 一旦空闲超时，说明路径已死 —— 立刻重连不会误伤正常连接。
//
// 🔴 只对空闲超时重连，其余关闭原因都不管：主动关闭（CloseWithError、僵死检测）
// 各有自己的后续；对端关闭时立刻重拨可能形成循环。只重连一次，失败后回到惰性拨号，
// 不在这里重试 —— 重试节奏归 offer 自身（含 K2 的中继回退）。

// watchIdleTimeout 在 conn 关闭后判断是否因空闲超时，是则主动发起一次 offer。
func (c *Client) watchIdleTimeout(conn *clientQUICConnection, family string) {
	go idleReconnect(conn.quicConn.Context(), func() bool {
		if c.closed.Load() || (c.ctx != nil && c.ctx.Err() != nil) {
			return false
		}
		c.connAccess.Lock()
		defer c.connAccess.Unlock()
		// 已被替换（或 CloseWithError 清空）的旧连接不触发重连。
		return c.conn == conn
	}, func() {
		c.realmWarn("realm: connection idle timeout (family ", family, "), reconnecting proactively")
		offerCtx := c.ctx
		if offerCtx == nil {
			offerCtx = context.Background()
		}
		if _, err := c.offer(offerCtx); err != nil {
			c.realmWarn("realm: proactive reconnect failed: ", err)
		}
	})
}

// idleReconnect 等 connCtx 结束；若 cause 是空闲超时且 shouldReconnect 成立，调用 reconnect。
func idleReconnect(connCtx context.Context, shouldReconnect func() bool, reconnect func()) {
	<-connCtx.Done()
	var idleErr *quic.IdleTimeoutError
	if !errors.As(context.Cause(connCtx), &idleErr) {
		return
	}
	if !shouldReconnect() {
		return
	}
	reconnect()
}
