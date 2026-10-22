package hysteria2

import (
	"testing"
	"time"
)

func TestRelayFallbackPrefersRelayAfterThreshold(t *testing.T) {
	var s relayFallbackState
	now := time.Now()
	if failures := s.handshakeFailed(now); failures != 1 {
		t.Fatalf("failures = %d, want 1", failures)
	}
	if _, prefer := s.preferRelay(now); prefer {
		t.Fatal("prefer relay after a single failure")
	}
	if failures := s.handshakeFailed(now); failures != relayPreferThreshold {
		t.Fatalf("failures = %d, want %d", failures, relayPreferThreshold)
	}
	if failures, prefer := s.preferRelay(now.Add(relayPreferBackoff - time.Second)); !prefer || failures != 2 {
		t.Fatalf("preferRelay = (%d, %v), want (2, true)", failures, prefer)
	}
	if _, prefer := s.preferRelay(now.Add(relayPreferBackoff)); prefer {
		t.Fatal("still prefer relay after backoff expired; direct must be retried")
	}
}

// 偏好期到期后重试直连又失败：下一档翻倍，封顶 relayPreferMaxBackoff。
func TestRelayFallbackBackoffDoublesAndCaps(t *testing.T) {
	var s relayFallbackState
	now := time.Now()
	s.handshakeFailed(now)
	want := relayPreferBackoff
	for i := 0; i < 8; i++ {
		s.handshakeFailed(now)
		if s.backoff != want {
			t.Fatalf("round %d: backoff = %v, want %v", i, s.backoff, want)
		}
		if _, prefer := s.preferRelay(now.Add(want - time.Millisecond)); !prefer {
			t.Fatalf("round %d: not preferring relay inside backoff", i)
		}
		want = min(want*2, relayPreferMaxBackoff)
	}
	if s.backoff != relayPreferMaxBackoff {
		t.Fatalf("backoff = %v, want cap %v", s.backoff, relayPreferMaxBackoff)
	}
}

func TestRelayFallbackDirectSuccessResets(t *testing.T) {
	var s relayFallbackState
	now := time.Now()
	if s.handshakeSucceeded() {
		t.Fatal("reported switch back from relay without ever preferring relay")
	}
	s.handshakeFailed(now)
	if s.handshakeSucceeded() {
		t.Fatal("reported switch back from relay below threshold")
	}
	s.handshakeFailed(now)
	s.handshakeFailed(now)
	if !s.handshakeSucceeded() {
		t.Fatal("direct success after relay preference not reported as switch back")
	}
	if failures, prefer := s.preferRelay(now); prefer || failures != 0 {
		t.Fatalf("after reset preferRelay = (%d, %v), want (0, false)", failures, prefer)
	}
	// 清零后重新计数：再失败一次不应立刻进入偏好期，退避也从头开始。
	s.handshakeFailed(now)
	if _, prefer := s.preferRelay(now); prefer {
		t.Fatal("prefer relay after a single failure following reset")
	}
	s.handshakeFailed(now)
	if s.backoff != relayPreferBackoff {
		t.Fatalf("backoff after reset = %v, want %v", s.backoff, relayPreferBackoff)
	}
}
