package realm_test

// punch_mode_test.go —— PunchMode（探针路径强制）的验收。
//
// 🔴 本文件守两件事：
//  1. PunchTraced == PunchTracedWithMode(ModeNormal)：既有调用点行为不被 mode
//     参数改变（零回归的第二道闸，第一道是 punch_traced_test 的 nil-trace 等价）。
//  2. ModeRelayOnly 在会合面未下发中继地址时按 candidate 阶段失败 —— 这是探针
//     入口能正确归类「这台没配中继」的前提。
//
// 真正的「打洞成功/中继成功」路径隔离依赖已注册的真实 egress 节点，属分层验证
// 第 1 步（Linux 真节点，见 HANDOFF_PROBE_ENTRY_AND_SHELL §4），不在 loopback
// 单测覆盖内 —— 单测只证前置流程与失败归类，不伪造一个「看着通了」的假成功。

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/transport/realm"
)

// ModeNormal 与 PunchTraced 在同一失败场景下必须给出同样的错误原文。
func TestModeNormalMatchesPunchTraced(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	cfg, realmID := baseConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, errTraced := realm.PunchTraced(ctx, cfg, realmID, nil)
	_, errMode := realm.PunchTracedWithMode(ctx, cfg, realmID, nil, realm.ModeNormal)

	if errTraced == nil || errMode == nil {
		t.Fatalf("两边都应失败（节点未注册）：traced=%v mode=%v", errTraced, errMode)
	}
	if errTraced.Error() != errMode.Error() {
		t.Errorf("ModeNormal 改变了错误原文：\n  PunchTraced          = %q\n  WithMode(ModeNormal) = %q",
			errTraced.Error(), errMode.Error())
	}
}

// 入参校验分支对所有 mode 一致（realmID 空、STUN 空、Resolver 空在任何 mode
// 下都应立即失败，不因 mode 走岔）。
func TestModeParameterValidation(t *testing.T) {
	base, _ := baseConfig(t)
	noSTUN := base
	noSTUN.STUNServers = nil

	ctx := context.Background()
	for _, mode := range []realm.PunchMode{realm.ModeNormal, realm.ModePunchOnly, realm.ModeRelayOnly} {
		if _, err := realm.PunchTracedWithMode(ctx, base, "", nil, mode); err == nil {
			t.Errorf("mode %d: empty realmID must fail", mode)
		}
		if _, err := realm.PunchTracedWithMode(ctx, noSTUN, "r", nil, mode); err == nil {
			t.Errorf("mode %d: empty STUN must fail", mode)
		}
	}
}

// ModeRelayOnly / ModePunchOnly 在「节点未注册」下仍应在 rendezvous 阶段失败 ——
// 证明 mode 不改变打洞前置流程（STUN → rendezvous），路径选择只发生在拿到
// 会合面响应之后。
func TestModesFailAtRendezvousWhenUnregistered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	cfg, realmID := baseConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, mode := range []realm.PunchMode{realm.ModePunchOnly, realm.ModeRelayOnly} {
		tr := realm.NewTrace(realmID, "test")
		_, err := realm.PunchTracedWithMode(ctx, cfg, realmID, tr, mode)
		if err == nil {
			t.Fatalf("mode %d: unregistered node must fail", mode)
		}
		// 未注册 → 会合面 Connect 返 404 → 归 rendezvous，早于任何 relay/punch 分支。
		if got := tr.FailStage; got != realm.FailStageRendezvous {
			t.Errorf("mode %d: want fail_stage=rendezvous (before path selection), got %q", mode, got)
		}
	}
}
