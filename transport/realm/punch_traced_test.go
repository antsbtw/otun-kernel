package realm_test

// punch_traced_test.go —— PunchTraced 的验收测试。
//
// 🔴 本文件存在的唯一理由：证明 **trace 为 nil 时 PunchTraced 与埋点前的 Punch
// 行为完全一致**（硬约束 4）。埋点能进主线的前提就是这条 ——
// 一旦 nil 路径有任何行为差异，生产路径（用户手机上的内核）就被埋点改变了。
//
// 用外部测试包（realm_test）而非包内测试：调用面与真实调用方一致，
// 避免不小心依赖包内未导出符号而测出「只有测试能过」的假绿。

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/protocol/realmtest"
	"github.com/sagernet/sing-box/transport/realm"
)

// baseConfig 是一份指向 loopback 会合面 + loopback STUN 的可用配置。
func baseConfig(t *testing.T) (realm.Config, string) {
	t.Helper()
	const token = "punch-traced-token"
	stun := realmtest.STUN(t)
	rvURL, _ := realmtest.Rendezvous(t, token)
	return realm.Config{
		ServerURL:   rvURL,
		Token:       token,
		STUNServers: []string{stun.String()},
		Resolver:    realmtest.Resolver,
		HTTPClient:  &http.Client{},
		Logger:      realmtest.Logger(),
	}, "no-such-node"
}

// TestPunchTracedNilTraceMatchesPunch 是本轮最重要的一条：同一份配置分别走
// Punch 和 PunchTraced(nil)，两者必须给出**同样的错误原文**。
//
// 用「打不通」的场景做对照是刻意的：成功路径两边都返回 nil error，区分不出差异；
// 失败路径才会暴露错误包装、socket 清理顺序上的不一致。
func TestPunchTracedNilTraceMatchesPunch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	cfg, realmID := baseConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, errPlain := realm.Punch(ctx, cfg, realmID)
	_, errTraced := realm.PunchTraced(ctx, cfg, realmID, nil)

	if errPlain == nil || errTraced == nil {
		t.Fatalf("两边都应失败（节点未注册）：plain=%v traced=%v", errPlain, errTraced)
	}
	if errPlain.Error() != errTraced.Error() {
		t.Errorf("nil trace 改变了错误原文：\n  Punch       = %q\n  PunchTraced = %q",
			errPlain.Error(), errTraced.Error())
	}
}

// TestPunchTracedNilTraceParameterValidation 覆盖三个入参校验分支 ——
// 它们在 trace 赋值之前 return，最容易被埋点改动误伤。
func TestPunchTracedNilTraceParameterValidation(t *testing.T) {
	cfg, _ := baseConfig(t)
	ctx := context.Background()

	cases := []struct {
		name    string
		mutate  func(realm.Config) realm.Config
		realmID string
	}{
		{"空 realmID", func(c realm.Config) realm.Config { return c }, ""},
		{"无 STUN 服务器", func(c realm.Config) realm.Config { c.STUNServers = nil; return c }, "x"},
		{"无 resolver", func(c realm.Config) realm.Config { c.Resolver = nil; return c }, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.mutate(cfg)
			_, errPlain := realm.Punch(ctx, c, tc.realmID)
			_, errTraced := realm.PunchTraced(ctx, c, tc.realmID, nil)
			if errPlain == nil || errTraced == nil {
				t.Fatalf("两边都应失败：plain=%v traced=%v", errPlain, errTraced)
			}
			if errPlain.Error() != errTraced.Error() {
				t.Errorf("nil trace 改变了错误原文：Punch=%q PunchTraced=%q",
					errPlain.Error(), errTraced.Error())
			}
			// 入参校验失败时连 trace 都不该被写（此时 trace 非 nil 也一样）。
			tr := realm.NewTrace(tc.realmID, "test")
			_, _ = realm.PunchTraced(ctx, c, tc.realmID, tr)
			if tr.FailStage != "" {
				t.Errorf("入参校验阶段不该产生 fail_stage，得到 %q", tr.FailStage)
			}
		})
	}
}

// TestPunchTracedFailStageRendezvous：节点没注册 → 会合面 404 →
// fail_stage=rendezvous，error_code=not_assigned（「没分配」不是「凭证错」）。
func TestPunchTracedFailStageRendezvous(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	cfg, realmID := baseConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tr := realm.NewTrace(realmID, "test")
	_, err := realm.PunchTraced(ctx, cfg, realmID, tr)
	if err == nil {
		t.Fatal("未注册的 realmID 应当失败")
	}
	if tr.FailStage != realm.FailStageRendezvous {
		t.Errorf("fail_stage = %q, want %q（原文：%v）", tr.FailStage, realm.FailStageRendezvous, err)
	}
	if tr.TunnelEstablished {
		t.Error("失败时 tunnel_established 必须为 false")
	}
	// STUN 阶段已经走完，耗时必须记上 —— 否则面板看不出「卡在会合面之前还是之后」。
	if tr.Stages.STUNMs == nil {
		t.Error("走到 rendezvous 说明 STUN 已完成，stun_ms 不该为空")
	}
	if tr.Stages.TotalMs == nil {
		t.Error("失败也必须有 total_ms")
	}
}

// TestPunchTracedFailStageSTUN：STUN 指向一个不回包的地址 → fail_stage=stun。
// 这条同时验证「归类在错误发生的那一层」—— 不是靠上层猜错误原文。
func TestPunchTracedFailStageSTUN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	cfg, realmID := baseConfig(t)
	// 192.0.2.0/24 是 RFC5737 TEST-NET-1，保证无人应答。
	cfg.STUNServers = []string{"192.0.2.1:3478"}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	tr := realm.NewTrace(realmID, "test")
	_, err := realm.PunchTraced(ctx, cfg, realmID, tr)
	if err == nil {
		t.Fatal("STUN 无应答应当失败")
	}
	if tr.FailStage != realm.FailStageSTUN {
		t.Errorf("fail_stage = %q, want %q（原文：%v）", tr.FailStage, realm.FailStageSTUN, err)
	}
	if tr.Stages.STUNMs != nil {
		t.Error("STUN 阶段失败时不该记 stun_ms（该阶段没走完）")
	}
	if tr.Stages.TotalMs == nil {
		t.Error("失败也必须有 total_ms")
	}
}

// TestPunchTracedFailAlwaysHasStage 是「失败时 fail_stage 必非空」的把关：
// 任何一条失败路径，只要 PunchTraced 返回了 error，trace 就必须给出归因。
// 🔴 fail_stage 为空的失败会在面板上变成「不明原因」，等于没埋点。
func TestPunchTracedFailAlwaysHasStage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	cfgOK, _ := baseConfig(t)

	cfgBadURL := cfgOK
	cfgBadURL.ServerURL = "://not-a-url"

	cfgBadSTUN := cfgOK
	cfgBadSTUN.STUNServers = []string{"192.0.2.1:3478"}

	cases := []struct {
		name string
		cfg  realm.Config
	}{
		{"会合面 URL 非法", cfgBadURL},
		{"STUN 无应答", cfgBadSTUN},
		{"节点未注册", cfgOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := realm.NewTrace("probe-target", "test")
			_, err := realm.PunchTraced(ctx, tc.cfg, "probe-target", tr)
			if err == nil {
				t.Skip("该场景本次未失败，跳过")
			}
			if tr.FailStage == "" {
				t.Errorf("失败了却没有 fail_stage（原文：%v）", err)
			}
			if tr.ErrorCode == "" {
				t.Errorf("失败了却没有 error_code（原文：%v）", err)
			}
			if tr.ErrorMsg == "" || !strings.Contains(err.Error(), strings.SplitN(tr.ErrorMsg, ":", 2)[0]) {
				t.Errorf("error_msg %q 与实际错误 %q 不一致", tr.ErrorMsg, err.Error())
			}
		})
	}
}
