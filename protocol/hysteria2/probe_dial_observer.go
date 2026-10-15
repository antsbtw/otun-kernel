package hysteria2

// probe_dial_observer.go —— 把 sing-quic 发起端建连观测接口(realm.DialObserver)翻译成
// kernel 既有的 transport/realm.Trace,让住宅面 hy2 也产出 punch_nonce / fail_stage 等摘要。
//
// ★ 为什么 hy2 需要这一层,另外五协议不需要:
// 五协议的打洞编排在 kernel 自己的 transport/realm.PunchTraced 里,埋点直接内联;
// hy2 的编排在 sing-quic 的 Client.offerNewRealm 内部,kernel 一行都插不进去
// (probe_trace.go 顶部记的 D3 缺口)。本文件只做"回调 → Trace 方法",不重复实现埋点逻辑。
//
// ★ 2026-10-15 进生产构建(原先 //go:build otun_probe_trace + go.probe.mod 的 fork 才有):
// 10-15 中国移动真机遥测里 hy2 的 punch_nonce / fail_stage 全 null —— 发版 Libbox 根本不带
// 这条数据源,双端 join 只能靠时间 + IP 猜。B4 契约(2026-09-18 路线 B)本就要求生产连接
// 产出这些字段且 inner_protocol 含 hysteria2。钩子已进树内 sing-quic(realm.DialObserver)。
//
// 零开销保证:realmtrace.Session 只在「探针开关开」或「App 订阅了摘要 sink」时返回非 nil;
// 否则 NewDialObserver 返回 nil,sing-quic 侧全部 no-op。旧 App 不订阅 = 行为不变。
//
// 设计约束与 transport/realm 埋点一致:只记录,不改控制流;不推断结论,只记事实。
// 每次建连一个 Trace(NewDialObserver 每次 offer 调一次),Finish 时输出恰好一次。

import (
	"net/netip"

	realmtrace "github.com/sagernet/sing-box/transport/realm"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
	"github.com/sagernet/sing/common/logger"
)

type probeDialObserver struct {
	trace       *realmtrace.Trace
	logger      logger.Logger
	stunServers []string
}

func (o *probeDialObserver) STUNDiscovered(localAddresses []netip.AddrPort) {
	o.trace.STUNDone(localAddresses, o.stunServers)
}

// RendezvousDone:metadata 是会合面下发的那份,即打洞包实际用的 nonce、节点侧记录的那个 —— 双端 join 靠它。
func (o *probeDialObserver) RendezvousDone(peerAddresses []netip.AddrPort, metadata squic.PunchMetadata) {
	o.trace.RendezvousDone(peerAddresses)
	o.trace.NonceNegotiated(metadata)
	o.trace.CandidatesComputed(peerAddresses)
}

func (o *probeDialObserver) PunchAttempted(_ string, _ []netip.AddrPort) {
	o.trace.HelloSent()
}

// PunchSucceeded:mode 传空同 transport/realm.PunchTraced —— punch/direct 是节点侧配置,客户端观测不到。
func (o *probeDialObserver) PunchSucceeded(family string, result squic.PunchResult) {
	o.trace.PunchDone(result, family, "")
}

func (o *probeDialObserver) RelaySettled(relayAddr string, err error) {
	if err != nil {
		o.trace.RelayFailed(err)
		return
	}
	o.trace.RelayEstablished(relayAddr)
}

func (o *probeDialObserver) HandshakeDone() {
	o.trace.HandshakeDone()
}

func (o *probeDialObserver) Failed(stage string, err error) {
	o.trace.Fail(realmtrace.FailStage(stage), err)
}

func (o *probeDialObserver) Finish() {
	realmtrace.Emit(o.logger, o.trace)
}

var _ squic.DialObserver = (*probeDialObserver)(nil)

// attachProbeDialObserver 给 realmOptions 挂上「每次建连新建一个 Trace」的观测器工厂。
func attachProbeDialObserver(realmOptions *squic.Options, realmID string) {
	if realmOptions == nil {
		return
	}
	log := realmOptions.Logger
	stunServers := realmOptions.STUNServers
	realmOptions.NewDialObserver = func() squic.DialObserver {
		trace := realmtrace.Session(realmID, "hysteria2")
		if trace == nil {
			return nil
		}
		return &probeDialObserver{trace: trace, logger: log, stunServers: stunServers}
	}
}
