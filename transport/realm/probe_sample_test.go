package realm_test

// probe_sample_test.go —— T5 验收：五协议各出一条真实 trace，字段同构。
//
// ★ 这不是单测「trace 结构体能不能填」（probe_trace_test.go 已覆盖），
// 而是走**真实打洞路径**（loopback 会合面 + STUN）产出 trace，
// 证明 fail_stage 归因在真路径上正确、六行字段结构一致。
//
// 🔴 断言「字段同构」是本轮的核心验收：横向比较的前提是同一指标同一把尺子。
// 若某协议少了 stun_ms 或 fail_stage 语义不同，面板那几行就不可比。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/transport/realm"
	"github.com/sagernet/sing/common/logger"
)

// captureLogger 收集 Emit 输出的埋点行。
type captureLogger struct {
	logger.Logger
	mu    sync.Mutex
	lines []string
}

func (c *captureLogger) Info(args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	parts := make([]string, 0, len(args))
	for _, a := range args {
		parts = append(parts, fmt.Sprint(a))
	}
	c.lines = append(c.lines, strings.Join(parts, ""))
}

// traceLine 取出唯一一条埋点行并解析。
func (c *captureLogger) traceLine(t *testing.T) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var found string
	for _, line := range c.lines {
		if strings.Contains(line, realm.ProbeTraceLogPrefix) {
			found = line
		}
	}
	if found == "" {
		t.Fatalf("未捕获到埋点行，收到 %d 行日志：%v", len(c.lines), c.lines)
	}
	idx := strings.Index(found, "{")
	if idx < 0 {
		t.Fatalf("埋点行没有 JSON 体：%q", found)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(found[idx:]), &out); err != nil {
		t.Fatalf("埋点行 JSON 解析失败：%v\n原文：%s", err, found)
	}
	return out
}

// TestProbeTraceRealPathFiveProtocols 让五个协议名各走一次真实打洞并产出 trace。
//
// 这里直接调 PunchTraced（overlay 之下那一层）—— 因为五个 overlay 对
// punch 阶段用的是**同一个函数**，punch 及之前的阶段本来就同源；
// overlay 之上的差异（handshake 终点）由各自的 e2e 测试覆盖。
func TestProbeTraceRealPathFiveProtocols(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	t.Setenv(realm.ProbeTraceEnv, "1")

	protocols := []string{"reality", "trojan", "vmess", "shadowsocks", "tuic"}

	const token = "sample-token"
	stun := realmtest.STUN(t)
	rvURL, _ := realmtest.Rendezvous(t, token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 收集五条 trace，逐条比对字段集合是否一致。
	var keysets []map[string]bool
	for _, proto := range protocols {
		t.Run(proto, func(t *testing.T) {
			cap := &captureLogger{Logger: logger.NOP()}
			cfg := realm.Config{
				ServerURL:   rvURL,
				Token:       token,
				STUNServers: []string{stun.String()},
				Resolver:    realmtest.Resolver,
				HTTPClient:  &http.Client{},
				Logger:      cap,
			}
			realmID := "sample-" + proto
			trace := realm.Session(realmID, proto)
			if trace == nil {
				t.Fatal("埋点已开启，Session 不该返回 nil")
			}
			_, err := realm.PunchTraced(ctx, cfg, realmID, trace)
			if err == nil {
				t.Fatal("节点未注册，本用例预期打洞失败（考察 fail_stage 归因）")
			}
			realm.Emit(cap, trace)

			out := cap.traceLine(t)
			// 归因必须正确：节点没注册 → 会合面 404 → rendezvous + not_assigned。
			if out["fail_stage"] != string(realm.FailStageRendezvous) {
				t.Errorf("fail_stage = %v, want rendezvous", out["fail_stage"])
			}
			if out["error_code"] != realm.ErrCodeNotAssigned {
				t.Errorf("error_code = %v, want %s（「没分配」不是「凭证错」）",
					out["error_code"], realm.ErrCodeNotAssigned)
			}
			if out["tunnel_established"] != false {
				t.Errorf("tunnel_established = %v, want false", out["tunnel_established"])
			}
			if out["protocol"] != proto {
				t.Errorf("protocol = %v, want %s", out["protocol"], proto)
			}
			stages, _ := out["stages"].(map[string]any)
			if stages["stun_ms"] == nil {
				t.Error("走到 rendezvous 说明 STUN 完成，stun_ms 不该缺")
			}
			if stages["total_ms"] == nil {
				t.Error("失败也必须有 total_ms")
			}

			keys := map[string]bool{}
			for k := range out {
				keys[k] = true
			}
			keysets = append(keysets, keys)

			pretty, _ := json.Marshal(out)
			t.Logf("TRACE 样本 [%s]：%s", proto, pretty)
		})
	}

	// 🔴 字段同构断言：五条 trace 的顶层字段集合必须完全一致。
	if len(keysets) == len(protocols) {
		for i := 1; i < len(keysets); i++ {
			for k := range keysets[0] {
				if !keysets[i][k] {
					t.Errorf("协议 %s 缺字段 %q —— 字段不同构就不能横向比较",
						protocols[i], k)
				}
			}
			for k := range keysets[i] {
				if !keysets[0][k] {
					t.Errorf("协议 %s 多出字段 %q —— 字段不同构就不能横向比较",
						protocols[i], k)
				}
			}
		}
	}
}

// TestProbeTraceDisabledByDefault 是生产安全阀：不设环境变量时
// Session 必须返回 nil，一行埋点日志都不该出现。
//
// 🔴 这条防的是「埋点默认开着」—— 那会让每个用户每次连接都输出
// 含反射地址/对端地址的 JSON，既是噪音也是隐私面。
func TestProbeTraceDisabledByDefault(t *testing.T) {
	os.Unsetenv(realm.ProbeTraceEnv)
	if realm.ProbeTraceEnabled() {
		t.Fatal("未设环境变量时埋点必须是关闭的")
	}
	if tr := realm.Session("any", "any"); tr != nil {
		t.Errorf("埋点关闭时 Session 必须返回 nil，得到 %v", tr)
	}
	// nil trace 走 Emit 不该产生任何输出。
	cap := &captureLogger{Logger: logger.NOP()}
	realm.Emit(cap, nil)
	realm.HandshakeDoneAndEmit(cap, nil)
	realm.FailAndEmit(cap, nil, realm.FailStagePunch, context.Canceled)
	if len(cap.lines) != 0 {
		t.Errorf("埋点关闭时不该有任何输出，得到：%v", cap.lines)
	}
}

// TestProbeTraceEnvOnlyAcceptsOne 守住「只认 1」的语义。
func TestProbeTraceEnvOnlyAcceptsOne(t *testing.T) {
	for _, v := range []string{"0", "true", "yes", "on", ""} {
		t.Setenv(realm.ProbeTraceEnv, v)
		if realm.ProbeTraceEnabled() {
			t.Errorf("%s=%q 不该开启埋点", realm.ProbeTraceEnv, v)
		}
	}
	t.Setenv(realm.ProbeTraceEnv, "1")
	if !realm.ProbeTraceEnabled() {
		t.Errorf("%s=1 应当开启埋点", realm.ProbeTraceEnv)
	}
}
