package hysteria2

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// 直连「验证」：握手成功不等于直连可用（KR1 验证回报 用例 4b，2026-10-21）。
//
// ★ 现场：中间设备在每条新 UDP 流开始约 0.2s 后将其掐断。QUIC 握手 + 认证在 0.2s 内
// 完成 → 判直连成功 → 连接随即死掉，要等 30s 空闲超时才发现。原实现以「握手成功」为准：
//   - 后台直连探测据此把新流从**正常工作的中继**切到死路上；
//   - 每次握手成功都把失败计数与中继偏好期清零，空闲超时重连又握手成功、又清零，
//     永远进不了偏好期。实测断网 3 分 17 秒。
//
// ★ 判据：握手后先等 directVerifySettle（避开握手收尾那段时间里到达的包），此后只要
// 收到对端任何一个包就算直连可用。不需要额外发包：quic-go 在最后一次收包后
// KeepAlivePeriod（10s）发保活 PING，对端必回 ACK，健康的空闲连接也会在 ~10s 内收到包。
//
// ★ 结果：
//   - 验证通过：才清零失败计数（relayFallback.handshakeSucceeded）；后台探测才切回直连。
//   - directVerifyDeadline 内一个包都没收到：按直连失败计数（偏好期照常生效）、关闭连接；
//     若它是当前连接，立即重连（不等 30s 空闲超时）。
//   - 验证前连接因其它原因关闭（被替换、Client 关闭等）：不计数。
const (
	directVerifySettle   = 2 * time.Second
	directVerifyDeadline = 15 * time.Second
	directVerifyPoll     = 500 * time.Millisecond
)

type directVerifyResult int

const (
	directVerified directVerifyResult = iota
	directUnverified
	directClosed
)

// waitDirectVerified 等 settle 之后 packets() 再增长。ctx 结束（连接关闭）返回 directClosed。
func waitDirectVerified(ctx context.Context, packets func() uint64, settle, deadline, poll time.Duration) directVerifyResult {
	settleTimer := time.NewTimer(settle)
	defer settleTimer.Stop()
	select {
	case <-ctx.Done():
		return directClosed
	case <-settleTimer.C:
	}
	base := packets()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	deadlineTimer := time.NewTimer(deadline - settle)
	defer deadlineTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return directClosed
		case <-ticker.C:
			if packets() > base {
				return directVerified
			}
		case <-deadlineTimer.C:
			if packets() > base {
				return directVerified
			}
			return directUnverified
		}
	}
}

// verifyDirect 给新建的直连（v4/v6）挂上验证。
func (c *Client) verifyDirect(conn *clientQUICConnection) {
	conn.verified = make(chan struct{})
	go func() {
		result := waitDirectVerified(conn.quicConn.Context(), func() uint64 {
			return conn.quicConn.ConnectionStats().PacketsReceived
		}, directVerifySettle, directVerifyDeadline, directVerifyPoll)
		switch result {
		case directVerified:
			close(conn.verified)
			if c.relayFallback.handshakeSucceeded() {
				c.realmWarn("realm: direct connection verified (family ", conn.family, "), switched back from relay")
			}
		case directUnverified:
			failures := c.relayFallback.handshakeFailed(time.Now())
			c.realmWarn("realm: direct connection received nothing within ", directVerifyDeadline, " after handshake (", failures, " consecutive, family ", conn.family, "), closing")
			current := c.isCurrentConn(conn)
			conn.closeWithError(E.New("realm: direct connection unverified"))
			if current {
				c.reconnectProactively()
			}
		}
	}()
}

// awaitDirectVerified 等直连验证结果；ctx 结束时关闭直连。
func awaitDirectVerified(ctx context.Context, conn *clientQUICConnection) bool {
	select {
	case <-conn.verified:
		return true
	case <-conn.quicConn.Context().Done():
		return false
	case <-ctx.Done():
		conn.closeWithError(E.Cause(ctx.Err(), "realm: direct verify canceled"))
		return false
	}
}
