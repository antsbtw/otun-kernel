package hysteria2

import (
	"context"
	"time"

	"github.com/sagernet/quic-go"
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
// ★ 判据：握手后先等 directVerifySettle，此后出现**新的 RTT 样本**才算直连可用。
// quic-go 只在对端 ACK 新确认了我方最大包号、且其中有 ack-eliciting 包时才更新 RTT
// （sent_packet_handler.ReceivedAck），所以新样本 = 我方 settle 之后发出的包到了对端。
//
// 🔴 不能用「收到对端的包」：逐流掐断只断客户端→节点，节点收不到 ACK 会一直重传，
// 客户端照样收包（复测 2026-10-22：4b 断网 ~11 分钟，验证全被重传包满足）。重传包里的
// ACK 只确认断流前的旧包，不产生新样本。
//
// 不额外发包（服务端解析不了的数据报会关掉整条连接，空流请求会在节点留错误日志）：
//   - 有流量的连接：我方的流数据被 ACK 即产生样本；只收不发的连接每
//     MaxNonAckElicitingAcks（19）个纯 ACK 包会带一个 PING。
//   - 空闲连接：两侧 KeepAlivePeriod 都是 10s，计时从「最后一次收包」起算，收到对方的
//     PING 会推迟自己的那次，所以两侧 PING 严格交替。握手后第一轮若是节点先发，客户端
//     要到第二轮（~20s + RTT）才发出 PING。directVerifyDeadline 取 25s 覆盖两轮，
//     且仍小于 MaxIdleTimeout（30s）。
//
// ★ 结果：
//   - 验证通过：才清零失败计数（relayFallback.handshakeSucceeded）；后台探测才切回直连。
//   - directVerifyDeadline 内没有新的 RTT 样本：按直连失败计数（偏好期照常生效）、关闭连接；
//     若它是当前连接，立即重连（比 30s 空闲超时早）。
//   - 验证前连接因其它原因关闭（被替换、Client 关闭等）：不计数。
const (
	directVerifySettle   = 2 * time.Second
	directVerifyDeadline = 25 * time.Second
	directVerifyPoll     = 500 * time.Millisecond
)

type directVerifyResult int

const (
	directVerified directVerifyResult = iota
	directUnverified
	directClosed
)

// rttSample 是 RTT 统计的快照；任一字段变化即有新样本（三者同时不变需要新样本与旧值逐 ns 相等）。
type rttSample struct {
	latest, smoothed, deviation time.Duration
}

func quicRTTSample(conn *quic.Conn) rttSample {
	stats := conn.ConnectionStats()
	return rttSample{stats.LatestRTT, stats.SmoothedRTT, stats.MeanDeviation}
}

// waitDirectVerified 等 settle 之后出现新的 RTT 样本。ctx 结束（连接关闭）返回 directClosed。
func waitDirectVerified(ctx context.Context, sample func() rttSample, settle, deadline, poll time.Duration) directVerifyResult {
	settleTimer := time.NewTimer(settle)
	defer settleTimer.Stop()
	select {
	case <-ctx.Done():
		return directClosed
	case <-settleTimer.C:
	}
	base := sample()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	deadlineTimer := time.NewTimer(deadline - settle)
	defer deadlineTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return directClosed
		case <-ticker.C:
			if sample() != base {
				return directVerified
			}
		case <-deadlineTimer.C:
			if sample() != base {
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
		result := waitDirectVerified(conn.quicConn.Context(), func() rttSample {
			return quicRTTSample(conn.quicConn)
		}, directVerifySettle, directVerifyDeadline, directVerifyPoll)
		switch result {
		case directVerified:
			close(conn.verified)
			if c.relayFallback.handshakeSucceeded() {
				c.realmWarn("realm: direct connection verified (family ", conn.family, "), switched back from relay")
			}
		case directUnverified:
			failures := c.relayFallback.handshakeFailed(time.Now())
			c.realmWarn("realm: direct connection got no ack for our packets within ", directVerifyDeadline, " after handshake (", failures, " consecutive, family ", conn.family, "), closing")
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
