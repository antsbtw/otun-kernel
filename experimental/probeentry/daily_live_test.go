//go:build daily_live

// 日常测试:六协议连通性 + 埋点出口(sink)是否真的送达。
//
// ★ 为什么这两件事要放在**同一个**测试里:
// 它们是两条独立的失败面,而且互相看不见 ——
//   - 协议通了但 sink 不响 → 线上一片正常,却收不到任何 fail_stage,
//     residential 归因重新变成瞎猜(这正是本轮补 sink 之前的状态);
//   - sink 响了但协议不通 → 数据来了,但全是失败。
//
// 分开跑就会出现「各自都绿、合起来不工作」的经典盲区,所以一次跑完、一起判。
//
// 🔴 sink 这一半是本文件的**独有价值**:probeentry 自己注入 Trace 并直接读回,
// 那条路**绕开了 sink**。也就是说探针全绿**不能**证明生产 App 收得到埋点 ——
// 生产走的是 overlay → Emit → dispatch → sink 这条链。本文件注册一个真 sink,
// 验的就是那条生产链路。
//
// 隔离手段(与 relay_e2e_live_test.go 同源):
//   - build tag `daily_live`:默认编译不到,CI 与生产二进制里一行都没有;
//   - 全部参数走环境变量,仓里不留任何 token。
//
// 跑法(realm 用**基名**,各协议后缀由本测试按 <base>-<proto> 派生):
//
//	OTUN_E2E_URL=https://54.255.172.86:9443 \
//	OTUN_E2E_TOKEN=... OTUN_E2E_REALM=egress-nj-01 OTUN_E2E_UUID=... \
//	go test -tags daily_live -run TestDailyLive -v ./experimental/probeentry/
//
// 只跑部分协议:OTUN_E2E_PROTOCOLS=tuic,trojan
package probeentry

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	realmlib "github.com/sagernet/sing-box/transport/realm"
)

// dailyProtocols 是默认要过的六协议。hy2 放最后:它的 trace 形态与另外五个不同
// (无 handshake_ms、tunnel_established 恒 false),排在最后便于读日志时对照。
var dailyProtocols = []string{"trojan", "shadowsocks", "vmess", "tuic", "reality", "hysteria2"}

// realmSuffix 是各协议在会合面上的 realm 后缀。派生规则 <base>-<proto>
// 与 Spec.RealmID 的注释一致;写死在这里是为了让「基名一个环境变量」就能跑全六个,
// 而不是让人手抄六行。
var realmSuffix = map[string]string{
	"trojan":      "trojan",
	"shadowsocks": "ss",
	"vmess":       "vmess",
	"tuic":        "tuic",
	"reality":     "reality",
	"hysteria2":   "hy2",
}

func dailyEnv(t *testing.T) (url, token, base, uuid string) {
	t.Helper()
	url = os.Getenv("OTUN_E2E_URL")
	token = os.Getenv("OTUN_E2E_TOKEN")
	base = os.Getenv("OTUN_E2E_REALM")
	uuid = os.Getenv("OTUN_E2E_UUID")
	if url == "" || token == "" || base == "" || uuid == "" {
		t.Skip("需要 OTUN_E2E_URL / OTUN_E2E_TOKEN / OTUN_E2E_REALM / OTUN_E2E_UUID")
	}
	return
}

// sinkRecorder 收集生产链路(overlay → Emit → dispatch)送出来的摘要。
// 并发安全:六协议顺序跑,但打洞内部多 family 并发,Emit 可能来自任意协程。
type sinkRecorder struct {
	access sync.Mutex
	got    []realmlib.Summary
}

func (r *sinkRecorder) add(s realmlib.Summary) {
	r.access.Lock()
	defer r.access.Unlock()
	r.got = append(r.got, s)
}

func (r *sinkRecorder) snapshot() []realmlib.Summary {
	r.access.Lock()
	defer r.access.Unlock()
	return append([]realmlib.Summary(nil), r.got...)
}

// TestDailyLive 是日常测试的主入口:六协议各跑一次,同时验埋点出口。
//
// 判定分两层,**分别报告**——这正是本测试的立意:
//  1. 协议层:每个协议 success(经隧道真实往返 2xx)。失败只标记该协议,不中断其余。
//  2. 出口层:sink 至少收到一条摘要,且字段自洽。
//
// 🔴 不因为某个协议不通就 Fatal:六协议里挂一个是常态(节点可能没配全),
// 一次跑完拿到完整画面,比第一个失败就停更有用。
func TestDailyLive(t *testing.T) {
	url, token, base, uuid := dailyEnv(t)

	protocols := dailyProtocols
	if v := os.Getenv("OTUN_E2E_PROTOCOLS"); v != "" {
		protocols = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				protocols = append(protocols, p)
			}
		}
	}

	// ★ 注册真 sink —— 这一步就是「出口是否成功」的被测对象本身。
	//   注册即开启(生产 App 同款语义),测试结束注销,不污染同包其它用例。
	rec := &sinkRecorder{}
	realmlib.SetSummarySink(rec.add)
	t.Cleanup(func() { realmlib.SetSummarySink(nil) })

	// 🔴 judge 留空即走 Spec 的可信默认(youtube 200)。
	//    刻意**不**用 generate_204 之类:那类端点在中国移动恒真,会把不通判成通
	//    ——假 success 比没有数据更坏(见 spec.go judgeURL 的注释)。
	judgeURL := os.Getenv("OTUN_E2E_JUDGE")

	type outcome struct {
		proto     string
		success   bool
		failStage string
		err       string
		totalMS   int64
	}
	var results []outcome

	for _, proto := range protocols {
		suffix, ok := realmSuffix[proto]
		if !ok {
			t.Errorf("未知协议 %q(realmSuffix 没有它的后缀,请先补映射)", proto)
			continue
		}
		spec := &Spec{
			Protocol:           proto,
			RealmID:            base + "-" + suffix,
			ServerURL:          url,
			Token:              token,
			UUID:               uuid,
			JudgeURL:           judgeURL,
			Insecure:           true,
			RendezvousInsecure: true,
		}
		if sni := os.Getenv("OTUN_E2E_SNI"); sni != "" {
			spec.SNI = sni
		}
		if m := os.Getenv("OTUN_E2E_SS_METHOD"); m != "" && proto == "shadowsocks" {
			spec.Method = m
		}

		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		res := RunProbe(ctx, spec, nil)
		cancel()

		results = append(results, outcome{
			proto: proto, success: res.Success,
			failStage: res.FailStage, err: res.Err, totalMS: res.TotalMS,
		})
		if res.Success {
			t.Logf("✅ %-11s success  judge=%d  %dms", proto, res.JudgeStatus, res.TotalMS)
		} else {
			t.Errorf("🔴 %-11s 不通  fail_stage=%q err=%s", proto, res.FailStage, res.Err)
		}
	}

	// ---- 第 1 层汇总:协议连通性 ----
	var okCount int
	for _, r := range results {
		if r.success {
			okCount++
		}
	}
	t.Logf("── 协议连通性:%d/%d 通 ──", okCount, len(results))
	for _, r := range results {
		if !r.success {
			t.Logf("   ✗ %s: fail_stage=%q", r.proto, r.failStage)
		}
	}

	// ---- 第 2 层:埋点出口 ----
	// 🔴 这一段与协议是否全通**无关**:即便协议全挂,sink 也应该收到失败摘要
	//    ——「连不上」本身就是最该被上报的事实。所以这里不 skip、不放水。
	summaries := rec.snapshot()
	t.Logf("── 埋点出口:sink 收到 %d 条摘要 ──", len(summaries))

	if len(summaries) == 0 {
		t.Errorf("🔴 出口失败:跑了 %d 个协议,sink 一条摘要都没收到。"+
			"生产 App 将拿不到任何 fail_stage —— 这正是补 sink 之前的状态,说明链路断了。"+
			"注意 hy2 走 sing-quic,默认不产出摘要,若只跑 hy2 属预期。", len(results))
		return
	}

	for i, s := range summaries {
		t.Logf("   [%d] realm=%s proto=%s fail_stage=%q relay_used=%v nat=%q established=%v",
			i, s.RealmID, s.Protocol, s.FailStage, s.RelayUsed, s.NATTypeGuess, s.TunnelEstablished)

		// 字段自洽性:realm/protocol 必须有值,否则后端无法分组。
		if s.RealmID == "" || s.Protocol == "" {
			t.Errorf("🔴 摘要 [%d] 缺 realm_id/protocol,后端无法分组", i)
		}
		// 🔴 内容红线:摘要**结构上**不该出现任何 IP。这里再兜一次 ——
		//    单测护栏挡的是字段新增,这里挡的是真实数据里意外混入地址。
		for _, f := range []string{s.RealmID, s.Protocol, string(s.FailStage), s.ErrorCode, string(s.NATTypeGuess)} {
			if looksLikeAddress(f) {
				t.Errorf("🔴 摘要 [%d] 字段疑似含地址:%q —— 违反内容红线", i, f)
			}
		}
	}
}

// looksLikeAddress 粗判一个字段是否像 IP:port / IP。
// 只做粗判:摘要里所有合法取值都是短枚举词(punch/symmetric/tuic…),
// 出现点号+数字就足够可疑,宁可误报也不放过。
func looksLikeAddress(v string) bool {
	if v == "" || !strings.Contains(v, ".") {
		return false
	}
	digits := 0
	for _, r := range v {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 4
}
