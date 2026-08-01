//go:build otun_probe_trace

package hysteria2

// probe_dial_observer.go —— 把 sing-quic 的发起端打洞观测接口（realm.DialObserver）
// 接到 kernel 既有的 transport/realm.Trace 上，让 hy2 也产出七阶段埋点与 nonce。
//
// ★ 为什么 hy2 需要这一层，另外五协议不需要：
// 五协议的打洞编排在 kernel 自己的 transport/realm.PunchTraced 里，埋点直接内联；
// hy2 的编排在 sing-quic 的 Client.offerNewRealm 内部，kernel 一行都插不进去 ——
// 这正是 probe_trace.go 顶部注释里记的 D3 缺口。fork 加了 DialObserver 回调口子后，
// 本文件做的就是"把回调翻译成 Trace 方法调用"，不重复实现任何埋点逻辑。
//
// ★ 三层隔离，缺一不可（本文件顶部的 //go:build otun_probe_trace 是第一层）：
//  1. 构建标签 otun_probe_trace —— 生产构建不带此 tag，本文件**根本不参与编译**，
//     所以上游 sing-quic 没有 DialObserver 类型也不会报错。
//  2. go.probe.mod 的 replace —— 探针构建才把 sing-quic 指向带钩子的 fork。
//  3. OTUN_PROBE_TRACE 环境变量 —— 运行期开关，未开时 Trace 为 nil，全链路 no-op。
// 生产客户端三层全不沾：go.mod 一字未动、不带 tag、开关默认关。
//
// 设计约束与 transport/realm 埋点一致：
//   - 只记录，不改变任何控制流；
//   - Trace 为 nil 时所有方法是 no-op（nil-receiver 安全）；
//   - 不推断结论，只记事实。

import (
	"net/netip"

	realmtrace "github.com/sagernet/sing-box/transport/realm"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// probeDialObserver 实现 squic.DialObserver，把回调翻成 Trace 调用。
//
// 🔴 trace 可以为 nil（埋点未开）——所有方法都靠 Trace 的 nil-receiver no-op 语义
// 保持安全，本类型自身不做判空分支，与 transport/realm 的既有惯例一致。
type probeDialObserver struct {
	trace *realmtrace.Trace
}

// STUNDiscovered 对应阶段 [1]：反射地址发现完毕。
//
// serversUsed 传配置里的 STUN 列表：与 transport/realm.PunchTraced 同样的取舍 ——
// "实际哪台 STUN 回了包"的映射在 squic 内部不导出，宁可少记一个字段，
// 也不编造一个看着精确的假值。这里 squic 侧连列表都不回传，故传 nil。
func (o probeDialObserver) STUNDiscovered(localAddresses []netip.AddrPort) {
	o.trace.STUNDone(localAddresses, nil)
}

// RendezvousDone 对应阶段 [2][3]：会合面换址完毕，且拿到双方共用的 metadata。
//
// ★ metadata 是会合面下发的那份（squic 侧已保证传的是 response.PunchMetadata），
// 也就是实际打洞包用的 nonce、接收端记录的那个 —— 双端 join 靠它。
func (o probeDialObserver) RendezvousDone(peerAddresses []netip.AddrPort, metadata squic.PunchMetadata) {
	o.trace.RendezvousDone(peerAddresses)
	o.trace.NonceNegotiated(metadata)
	o.trace.CandidatesComputed(peerAddresses)
}

// PunchAttempted 对应阶段 [4]：某个地址族开始发 Hello。
//
// squic 侧每 family 调一次，与 HelloSent 的"一轮发送"语义对齐（多 family 并发时
// Trace 内部有锁，计数安全）。
func (o probeDialObserver) PunchAttempted(family string, candidates []netip.AddrPort) {
	o.trace.CandidatesComputed(candidates)
	o.trace.HelloSent()
}

// PunchSettled 对应阶段 [5]：打洞落定。
//
// mode 传空与 transport/realm.PunchTraced 一致 —— punch/direct 是**节点侧配置**，
// 客户端无从得知，由 prober 填。内核不编造自己观测不到的事实。
func (o probeDialObserver) PunchSettled(family string, result squic.PunchResult, err error) {
	if err != nil {
		o.trace.Fail(realmtrace.FailStagePunch, err)
		return
	}
	o.trace.PunchDone(result, family, "")
}

var _ squic.DialObserver = probeDialObserver{}
