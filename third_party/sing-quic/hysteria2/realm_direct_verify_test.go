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

// fakeRTT 模拟 RTT 统计：newSample 产生一个新样本。
type fakeRTT struct {
	samples atomic.Int64
}

func (f *fakeRTT) newSample() { f.samples.Add(1) }

func (f *fakeRTT) sample() rttSample {
	return rttSample{latest: time.Duration(f.samples.Load())}
}

// 握手收尾期间有样本，之后再没有 → 判未验证。
func TestDirectVerifyRejectsConnectionDeadAfterHandshake(t *testing.T) {
	var rtt fakeRTT
	go func() {
		time.Sleep(testVerifySettle / 5)
		rtt.newSample() // 落在 settle 之内，不算数
	}()
	result := waitDirectVerified(context.Background(), rtt.sample, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directUnverified {
		t.Fatalf("result = %v, want directUnverified", result)
	}
}

// settle 之后有新样本 → 判验证通过，且不必等到 deadline。
func TestDirectVerifyAcceptsSampleAfterSettle(t *testing.T) {
	var rtt fakeRTT
	go func() {
		time.Sleep(testVerifySettle + 30*time.Millisecond)
		rtt.newSample()
	}()
	start := time.Now()
	result := waitDirectVerified(context.Background(), rtt.sample, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directVerified {
		t.Fatalf("result = %v, want directVerified", result)
	}
	if elapsed := time.Since(start); elapsed >= testVerifyDeadline {
		t.Fatalf("verified only after %v; should not wait for the deadline", elapsed)
	}
}

// 验证前连接因其它原因关闭 → 不计成功也不计失败。
func TestDirectVerifyConnectionClosed(t *testing.T) {
	var rtt fakeRTT
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(testVerifySettle+20*time.Millisecond, cancel)
	result := waitDirectVerified(ctx, rtt.sample, testVerifySettle, testVerifyDeadline, testVerifyPoll)
	if result != directClosed {
		t.Fatalf("result = %v, want directClosed", result)
	}
}
