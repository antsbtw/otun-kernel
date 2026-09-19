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

// ---- B4 契约字段（2026-09-18）----------------------------------------------

// 契约字段名与取值：JSON 形状是**跨端契约**，改名即破约，故逐字段钉死。
// 🔴 这里断言的是 JSON tag 而非 Go 字段名：App 侧解析的是前者，
// 改 Go 字段名不会破坏它们，改 tag 会 —— 护栏必须挡在真正的破约面上。
func TestSummaryContractFieldNames(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	trace := NewTrace("egress-nj-01", "reality")
	trace.Punch.NATTypeGuess = NATTypeSymmetric
	trace.Nonce = "0123456789abcdef0123456789abcdef"
	trace.HandshakeDone()
	Emit(nil, trace)

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"inner_protocol", "nat_type", "punch_nonce",
		"outcome", "kernel_tunnel_ready_ms", "relay_used",
	} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("契约字段 %q 缺失: %s", key, encoded)
		}
	}
	// 旧名不得残留 —— 同名即同义的反面：旧名还在就等于两套口径并存。
	for _, stale := range []string{"protocol", "nat_type_guess", "tunnel_ready_ms"} {
		if _, ok := decoded[stale]; ok {
			t.Errorf("旧字段名 %q 不该再出现: %s", stale, encoded)
		}
	}
	if decoded["inner_protocol"] != "reality" {
		t.Errorf("inner_protocol 应为 reality(非 vless-reality), 实得 %v", decoded["inner_protocol"])
	}
}

// outcome 由 fail_stage 派生：空 = success，非空 = failed。
//
// 🔴 中继救回的那一行是本用例的重点：fail_stage 仍是 punch,故 outcome=failed,
// 但 relay_used=true。两个口径不合并——合并会让「打洞成功率」与「连接成功率」
// 互相污染(见 Trace.RelayUsed 注释)。后端按 relay_used 单独统计「被救回」。
func TestSummaryOutcomeDerivation(t *testing.T) {
	resetSinks(t)
	for _, tc := range []struct {
		name    string
		prepare func(*Trace)
		want    string
	}{
		{"握手完成即 success", func(tr *Trace) { tr.HandshakeDone() }, OutcomeSuccess},
		{"失败带 fail_stage", func(tr *Trace) { tr.Fail(FailStagePunch, errors.New("boom")) }, OutcomeFailed},
		{"中继救回仍记 failed", func(tr *Trace) {
			tr.Fail(FailStagePunch, errors.New("no hole"))
			tr.RelayEstablished("203.0.113.7:9000")
		}, OutcomeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got Summary
			SetSummarySink(func(s Summary) { got = s })
			trace := NewTrace("r", "tuic")
			tc.prepare(trace)
			Emit(nil, trace)
			if got.Outcome != tc.want {
				t.Errorf("outcome = %q, want %q (fail_stage=%q)", got.Outcome, tc.want, got.FailStage)
			}
		})
	}
}

// nat_type 未判定时**留空**,不发 "unknown"(后端 2026-09-18 拍板)。
// 同一件事两种表达会逼 App 侧既判空又判串,那是自造分叉。
func TestSummaryNATTypeUnknownStaysEmpty(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	trace := NewTrace("r", "trojan")
	trace.Punch.NATTypeGuess = NATTypeUnknown
	trace.HandshakeDone()
	Emit(nil, trace)

	if got.NATTypeGuess != "" {
		t.Errorf("nat_type 未判定应留空, 实得 %q", got.NATTypeGuess)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "nat_type") {
		t.Errorf("未判定时不该输出 nat_type 字段: %s", encoded)
	}
}

// kernel_tunnel_ready_ms 只在隧道真建起来时有值。
//
// 🔴 失败时留 nil 而非 0:0 会被统计成「秒开」,比缺字段坏得多。
func TestSummaryKernelTunnelReadyMs(t *testing.T) {
	resetSinks(t)

	t.Run("成功有值", func(t *testing.T) {
		var got Summary
		SetSummarySink(func(s Summary) { got = s })
		trace := NewTrace("r", "vmess")
		trace.HandshakeDone()
		Emit(nil, trace)
		if got.KernelTunnelReadyMs == nil {
			t.Fatal("隧道建立后 kernel_tunnel_ready_ms 不应为 nil")
		}
	})

	t.Run("失败留空", func(t *testing.T) {
		var got Summary
		SetSummarySink(func(s Summary) { got = s })
		trace := NewTrace("r", "vmess")
		trace.Fail(FailStageHandshake, errors.New("nope"))
		Emit(nil, trace)
		if got.KernelTunnelReadyMs != nil {
			t.Errorf("未就绪却给了 kernel_tunnel_ready_ms = %d", *got.KernelTunnelReadyMs)
		}
	})
}

// punch_nonce 是双端 join 键,必须原样带出 —— 缺它双端数据只能按时间窗猜。
// 它是随机数不是地址,不违反隐私边界(见 Summary.Nonce 注释)。
func TestSummaryCarriesPunchNonce(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	const nonce = "0123456789abcdef0123456789abcdef"
	trace := NewTrace("r", "shadowsocks")
	trace.Nonce = nonce
	trace.HandshakeDone()
	Emit(nil, trace)

	if got.Nonce != nonce {
		t.Errorf("punch_nonce = %q, want %q", got.Nonce, nonce)
	}
}

// 🔴 直连打洞成功时 relay_used 必须仍以 false **出现在 JSON 里**。
//
// 这是 omitempty 的经典陷阱:bool 零值会让字段整个消失,而前端判空用 assertNull
// 口径,字段消失会被读成"没有数据",与"没用中继"是两回事 —— 正是契约 §2
// ⚠️「没这条事件 ≠ relay_used=false」要避免的混淆。加字段时若顺手抄了
// omitempty,本用例是唯一能抓住它的护栏。
func TestSummaryRelayUsedPresentWhenFalse(t *testing.T) {
	resetSinks(t)
	var got Summary
	SetSummarySink(func(s Summary) { got = s })

	trace := NewTrace("r", "reality")
	trace.HandshakeDone() // 直连打洞成功,从未用中继
	Emit(nil, trace)

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	relayUsed, ok := decoded["relay_used"]
	if !ok {
		t.Fatalf("relay_used 在直连成功时消失了(omitempty 陷阱): %s", encoded)
	}
	if relayUsed != false {
		t.Errorf("relay_used = %v, want false", relayUsed)
	}
}
