package hysteria2

import (
	"sync"
	"time"
)

// 住宅面「打洞成功、握手失败」改走中继（CLIENT_REQ_2026-10-20 K2，问题单 I1）。
//
// ★ 现场：10-20 08:00–08:09 中间设备在每条新 UDP 流开始约 0.2s 后将其掐断。
// 打洞包在前 0.2s 双向都通 → 打洞成功 → QUIC 握手超时（15s）。原代码只在
// 打洞失败时才试中继，握手失败直接返回，8 分钟里换端口重试几十次，一次也没走中继。
//
// ★ 策略：
//  1. 打洞成功但握手失败：本次拨号内立刻换新 nonce 重新 /connect、走中继。
//     不复用原 nonce —— 节点在每次 /connect 时都会无条件去中继报到，但只等
//     relayJoinWindow（25s）；打洞 + 15s 握手超时之后可能已经不在了。
//  2. 连续直连握手失败 ≥ relayPreferThreshold 次：之后一段时间内的拨号跳过
//     打洞直接走中继，时长按 relayPreferBackoff 起翻倍、封顶 relayPreferMaxBackoff；
//     到期后的下一次拨号重新试直连，验证通过即清零，失败则下一档。
//  3. 直连握手成功后 directVerifyDeadline 内一个包都没收到，同样计一次失败
//     （见 realm_direct_verify.go）。
//
// 🔴 只有**直连**验证通过才清零。中继握手成功不清零：否则每次中继连接断了重拨
// 都要先在直连上白等 15s 握手超时，正是要消除的那段不通。
const (
	relayPreferThreshold  = 2
	relayPreferBackoff    = time.Minute
	relayPreferMaxBackoff = 10 * time.Minute
)

type relayFallbackState struct {
	access   sync.Mutex
	failures int
	backoff  time.Duration
	until    time.Time
}

// handshakeFailed 记一次直连失败（握手失败或验证失败），返回当前连续失败次数。
func (s *relayFallbackState) handshakeFailed(now time.Time) int {
	s.access.Lock()
	defer s.access.Unlock()
	s.failures++
	if s.failures >= relayPreferThreshold {
		if s.backoff == 0 {
			s.backoff = relayPreferBackoff
		} else {
			s.backoff = min(s.backoff*2, relayPreferMaxBackoff)
		}
		s.until = now.Add(s.backoff)
	}
	return s.failures
}

// handshakeSucceeded 记一次直连验证通过并清零，返回此前是否处于中继偏好期。
func (s *relayFallbackState) handshakeSucceeded() bool {
	s.access.Lock()
	defer s.access.Unlock()
	wasRelay := s.backoff != 0
	s.failures = 0
	s.backoff = 0
	s.until = time.Time{}
	return wasRelay
}

// preferRelay 报告本次拨号是否应跳过打洞直接走中继，以及当前连续失败次数。
func (s *relayFallbackState) preferRelay(now time.Time) (int, bool) {
	s.access.Lock()
	defer s.access.Unlock()
	return s.failures, now.Before(s.until)
}

func (c *Client) realmWarn(args ...any) {
	if c.logger != nil {
		c.logger.Warn(args...)
	}
}
