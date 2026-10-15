package hysteria2

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"testing"

	realmtrace "github.com/sagernet/sing-box/transport/realm"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// 收集摘要 sink 的输出(生产 App 走的就是这条出口)。
func captureSummaries(t *testing.T) func() []realmtrace.Summary {
	t.Helper()
	var (
		access sync.Mutex
		got    []realmtrace.Summary
	)
	realmtrace.SetSummarySink(func(s realmtrace.Summary) {
		access.Lock()
		got = append(got, s)
		access.Unlock()
	})
	t.Cleanup(func() { realmtrace.SetSummarySink(nil) })
	return func() []realmtrace.Summary {
		access.Lock()
		defer access.Unlock()
		return append([]realmtrace.Summary(nil), got...)
	}
}

func newTestOptions() *squic.Options {
	opts := &squic.Options{STUNServers: []string{"74.125.250.129:19302"}}
	attachProbeDialObserver(opts, "egress-jp-02-hy2")
	return opts
}

func testMetadata() (squic.PunchMetadata, string) {
	var m squic.PunchMetadata
	for i := range m.Nonce {
		m.Nonce[i] = byte(0xa0 + i)
	}
	return m, hex.EncodeToString(m.Nonce[:])
}

// 没有订阅摘要、探针开关也没开 → 每次建连拿到 nil 观测器(零开销,旧 App 行为不变)。
func TestDialObserverNilWithoutSink(t *testing.T) {
	realmtrace.SetSummarySink(nil)
	if obs := newTestOptions().NewDialObserver(); obs != nil {
		t.Fatalf("expected nil observer when no sink registered, got %T", obs)
	}
}

// 正常建连:摘要带 nonce、inner_protocol=hysteria2、outcome=success,且每次建连恰好一条。
func TestDialObserverSuccessEmitsSummaryWithNonce(t *testing.T) {
	summaries := captureSummaries(t)
	opts := newTestOptions()
	metadata, nonceHex := testMetadata()
	peer := netip.MustParseAddrPort("[2406:da14::1]:51820")

	for attempt := 0; attempt < 2; attempt++ {
		obs := opts.NewDialObserver()
		if obs == nil {
			t.Fatal("observer must be created once a summary sink is registered")
		}
		obs.STUNDiscovered([]netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:5000")})
		obs.RendezvousDone([]netip.AddrPort{peer}, metadata)
		obs.PunchAttempted("v6", []netip.AddrPort{peer})
		obs.PunchSucceeded("v6", squic.PunchResult{PeerAddr: peer, Type: squic.PunchHello})
		obs.HandshakeDone()
		obs.Finish()
	}
	got := summaries()
	if len(got) != 2 {
		t.Fatalf("want exactly one summary per dial attempt (2), got %d", len(got))
	}
	s := got[0]
	if s.Nonce != nonceHex {
		t.Fatalf("punch_nonce = %q, want %q", s.Nonce, nonceHex)
	}
	if s.Protocol != "hysteria2" || s.Outcome != realmtrace.OutcomeSuccess || s.FailStage != "" {
		t.Fatalf("unexpected summary: %+v", s)
	}
}

// 打洞失败 + 中继救回:fail_stage 仍为 punch(真实卡点),relay_used=true(附加事实)。
func TestDialObserverPunchFailedRelayRescued(t *testing.T) {
	summaries := captureSummaries(t)
	obs := newTestOptions().NewDialObserver()
	metadata, _ := testMetadata()
	obs.RendezvousDone(nil, metadata)
	obs.Failed("punch", errors.New("realm punch: v4: punch timeout: context deadline exceeded"))
	obs.RelaySettled("18.142.249.56:51830", nil)
	obs.HandshakeDone()
	obs.Finish()
	got := summaries()
	if len(got) != 1 {
		t.Fatalf("want 1 summary, got %d", len(got))
	}
	if got[0].FailStage != realmtrace.FailStagePunch || !got[0].RelayUsed {
		t.Fatalf("want fail_stage=punch + relay_used, got %+v", got[0])
	}
}

// 会合面就失败:fail_stage=rendezvous,且仍输出一条(失败也要可见)。
func TestDialObserverRendezvousFailure(t *testing.T) {
	summaries := captureSummaries(t)
	obs := newTestOptions().NewDialObserver()
	obs.Failed("rendezvous", errors.New("realm connect: EOF"))
	obs.Finish()
	got := summaries()
	if len(got) != 1 || got[0].FailStage != realmtrace.FailStageRendezvous || got[0].Outcome != realmtrace.OutcomeFailed {
		t.Fatalf("unexpected summaries: %+v", got)
	}
}
