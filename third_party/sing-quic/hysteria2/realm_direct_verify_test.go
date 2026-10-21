package hysteria2

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testVerifySettle   = 50 * time.Millisecond
	testVerifyDeadline = 300 * time.Millisecond
	testVerifyPoll     = 10 * time.Millisecond
)

// 逐流掐断：握手收尾期间有包，之后一个都没有 → 判未验证。
func TestDirectVerifyRejectsConnectionDeadAfterHandshake(t *testing.T) {
	var packets atomic.Uint64
	packets.Store(12)
	go func() {
		time.Sleep(testVerifySettle / 5)
		packets.Add(3) // 握手收尾的包落在 settle 之内，不算数
	}()
	result := waitDirectVerified(context.Background(), packets.Load, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directUnverified {
		t.Fatalf("result = %v, want directUnverified", result)
	}
}

// settle 之后收到包（保活 ACK 或数据）→ 判验证通过，且不必等到 deadline。
func TestDirectVerifyAcceptsPacketAfterSettle(t *testing.T) {
	var packets atomic.Uint64
	go func() {
		time.Sleep(testVerifySettle + 30*time.Millisecond)
		packets.Add(1)
	}()
	start := time.Now()
	result := waitDirectVerified(context.Background(), packets.Load, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directVerified {
		t.Fatalf("result = %v, want directVerified", result)
	}
	if elapsed := time.Since(start); elapsed >= testVerifyDeadline {
		t.Fatalf("verified only after %v; should not wait for the deadline", elapsed)
	}
}

// 验证前连接因其它原因关闭 → 不计成功也不计失败。
func TestDirectVerifyConnectionClosed(t *testing.T) {
	var packets atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(testVerifySettle+20*time.Millisecond, cancel)
	result := waitDirectVerified(ctx, packets.Load, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directClosed {
		t.Fatalf("result = %v, want directClosed", result)
	}
}
