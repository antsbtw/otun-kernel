package realm

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// resetSinks 清掉进程级 sink。sink 是全局状态，每个用例必须自己收尾，
// 否则会污染同包内其它用例（尤其是 probe_session_test 里依赖「默认关」的断言）。
func resetSinks(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		SetSummarySink(nil)
		SetTraceSink(nil)
	})
}

// 生产默认：没注册 sink、没设环境变量时 Session 返回 nil —— 零影响的基石。
func TestSessionNilWhenNoSinkAndNoEnv(t *testing.T) {
	resetSinks(t)
	if got := Session("r", "tuic"); got != nil {
		t.Fatalf("Session should be nil when telemetry is off, got %+v", got)
	}
}

// 注册 sink 即开启埋点 —— App 里设不了环境变量，这是生产路径唯一的开关。
func TestSessionEnabledBySink(t *testing.T) {
	resetSinks(t)
	SetSummarySink(func(Summary) {})
	if got := Session("r", "tuic"); got == nil {
		t.Fatal("Session should create a Trace once a sink is registered")
	}
}

// 注销后回到关闭态：对应用户关掉「发送诊断数据」。
func TestSinkUnregister(t *testing.T) {
	resetSinks(t)
	SetSummarySink(func(Summary) {})
	SetSummarySink(nil)
	if TraceSinkEnabled() {
		t.Fatal("sink should be disabled after unregistering")
	}
	if got := Session("r", "tuic"); got != nil {
		t.Fatal("Session should be nil again after unregistering")
	}
}

// 🔴 核心回归：logger 为 nil 时 sink 仍必须收到埋点。
// 生产壳侧完全可能不配 logger，若 sink 派发被挡在 log==nil 早退之后，
// 埋点会在生产环境静默消失 —— 而单测若总是传 logger 就永远发现不了。
func TestEmitDispatchesToSinkWithNilLogger(t *testing.T) {
	resetSinks(t)
	var got []Summary
	SetSummarySink(func(s Summary) { got = append(got, s) })

	trace := NewTrace("egress-nj-01", "tuic")
	trace.Fail(FailStagePunch, errors.New("no candidate reachable"))
	Emit(nil, trace)

	if len(got) != 1 {
		t.Fatalf("want exactly 1 summary with nil logger, got %d", len(got))
	}
	if got[0].FailStage != FailStagePunch {
		t.Errorf("fail_stage = %q, want %q", got[0].FailStage, FailStagePunch)
	}
	if got[0].RealmID != "egress-nj-01" || got[0].Protocol != "tuic" {
		t.Errorf("realm/protocol not carried: %+v", got[0])
	}
	if got[0].TunnelEstablished {
		t.Error("tunnel_established must stay false on a failed attempt")
	}
}

// 中继救回时的正交语义：fail_stage 仍是 punch（打洞确实失败了），
// 同时 relay_used=true。两个口径不能互相覆盖 —— 这是契约 Q2 的判定依据。
func TestSummaryRelayOrthogonalToFailStage(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	trace := NewTrace("egress-nj-01", "vmess")
	trace.Fail(FailStagePunch, errors.New("punch timeout"))
	trace.RelayEstablished("203.0.113.7:9000")
	Emit(nil, trace)

	if got.FailStage != FailStagePunch {
		t.Errorf("fail_stage = %q, want punch to survive relay rescue", got.FailStage)
	}
	if !got.RelayUsed {
		t.Error("relay_used must be true after RelayEstablished")
	}
}

// 隐私边界：摘要必须不含 IP 级字段。这条用例是那条边界的护栏 ——
// 日后有人往 Summary 加 relay_addr / local_srflx，这里会立刻红。
func TestSummaryCarriesNoAddresses(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	trace := NewTrace("egress-nj-01", "trojan")
	trace.RelayEstablished("203.0.113.7:9000")
	trace.Punch.PeerAddrMatched = "198.51.100.4:41234"
	trace.Punch.LocalSrflx = []string{"198.51.100.9:5555"}
	Emit(nil, trace)

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"203.0.113.7", "198.51.100.4", "198.51.100.9"} {
		if strings.Contains(string(encoded), leaked) {
			t.Errorf("summary leaked address %q: %s", leaked, encoded)
		}
	}
}

// 完整 Trace sink 仍拿得到细节（探针用），与摘要 sink 互不影响。
func TestTraceSinkReceivesFullTrace(t *testing.T) {
	resetSinks(t)
	var got *Trace
	SetTraceSink(func(tr *Trace) { got = tr })

	trace := NewTrace("egress-sg-02", "reality")
	trace.Fail(FailStageHandshake, errors.New("tls: bad record"))
	Emit(nil, trace)

	if got == nil {
		t.Fatal("trace sink received nothing")
	}
	if got.FailStage != FailStageHandshake {
		t.Errorf("fail_stage = %q, want handshake", got.FailStage)
	}
}

// nil Trace（埋点未开）不得触发任何回调 —— 否则会凭空造出一条假埋点。
func TestEmitNilTraceDoesNotDispatch(t *testing.T) {
	resetSinks(t)
	called := false
	SetSummarySink(func(Summary) { called = true })
	Emit(nil, nil)
	if called {
		t.Fatal("nil trace must not reach the sink")
	}
}
