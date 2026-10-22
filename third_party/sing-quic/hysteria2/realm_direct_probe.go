package hysteria2

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// 走中继期间后台重试直连，成功后切回（CLIENT_REQ_2026-10-20 K2 第 3 条）。
//
// ★ 为什么要主动切回：中继多一跳、占中继带宽；而 K2 的中继偏好期只在**重拨**时
// 才到期重试直连，中继连接只要不断就一直用下去。
//
// ★ 切换方式：直连握手成功、且验证通过（见 realm_direct_verify.go）后把 c.conn 换成直连 —— 之后的新流、新 UDP 会话都走直连；
// 中继连接上的现有流不打断，等它们全部结束（或 relayDrainMax 封顶）再关。
// 推送这类长连接会让中继多留一阵，但不会被切换打断。
//
// 🔴 探测只试直连（offerNewRealmPunch allowRelay=false），失败不回退中继、不另起一条中继。
// 直连握手失败或验证失败照常计入 relayFallback，偏好期随之延长；验证通过才清零。
const (
	directProbeInitial = time.Minute
	directProbeMax     = 10 * time.Minute
	relayDrainPoll     = 5 * time.Second
	relayDrainMax      = 10 * time.Minute
)

// probeDirectWhileRelayed 为中继连接挂后台直连探测。中继连接关闭、被替换或 Client 关闭时退出。
func (c *Client) probeDirectWhileRelayed(relayConn *clientQUICConnection) {
	ctx, cancel := context.WithCancel(relayConn.quicConn.Context())
	if c.ctx != nil {
		stop := context.AfterFunc(c.ctx, cancel)
		go func() {
			<-ctx.Done()
			stop()
		}()
	}
	go func() {
		defer cancel()
		backoff := directProbeInitial
		for {
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if !c.isCurrentConn(relayConn) {
				return
			}
			c.realmWarn("realm: on relay, retrying direct")
			direct, _, err := c.offerNewRealmPunch(ctx, false)
			if err != nil {
				backoff = min(backoff*2, directProbeMax)
				c.realmWarn("realm: direct retry failed, next in ", backoff, ": ", err)
				continue
			}
			// 握手成功不切：逐流掐断的网络里握手能完成、连接随即死掉（见 realm_direct_verify.go）。
			// 验证失败已由 verifyDirect 计数并关闭直连。
			if !awaitDirectVerified(ctx, direct) {
				backoff = min(backoff*2, directProbeMax)
				c.realmWarn("realm: direct retry unverified, staying on relay, next in ", backoff)
				continue
			}
			if !c.swapConn(relayConn, direct) {
				// 探测期间中继已被替换（断线重拨等），这条直连用不上。
				direct.closeWithError(E.New("realm: relay replaced during direct retry"))
				return
			}
			c.realmWarn("realm: new streams switched from relay to direct (family ", direct.family, "), draining relay")
			c.drainConn(relayConn)
			return
		}
	}()
}

func (c *Client) isCurrentConn(conn *clientQUICConnection) bool {
	if c.closed.Load() {
		return false
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	return c.conn == conn && conn.active()
}

// swapConn 在当前连接仍是 old 时换成 next，返回是否换成功。
func (c *Client) swapConn(old, next *clientQUICConnection) bool {
	if c.closed.Load() {
		return false
	}
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.conn != old {
		return false
	}
	c.conn = next
	return true
}

// drainConn 等 conn 上的流与 UDP 会话全部结束（或 relayDrainMax 到期）后关闭它。
func (c *Client) drainConn(conn *clientQUICConnection) {
	deadline := time.Now().Add(relayDrainMax)
	ticker := time.NewTicker(relayDrainPoll)
	defer ticker.Stop()
	for {
		if conn.idle() || time.Now().After(deadline) {
			conn.closeWithError(E.New("realm: switched to direct"))
			return
		}
		select {
		case <-conn.quicConn.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

// idle 报告连接上是否已没有未关闭的 TCP 流和 UDP 会话。
func (c *clientQUICConnection) idle() bool {
	if c.streams.Load() > 0 {
		return false
	}
	c.udpAccess.RLock()
	defer c.udpAccess.RUnlock()
	return len(c.udpConnMap) == 0
}
