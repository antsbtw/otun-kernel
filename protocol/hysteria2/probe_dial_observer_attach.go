//go:build otun_probe_trace

package hysteria2

// probe_dial_observer_attach.go —— 探针构建下把观测器挂进 realm.Options。
//
// 分成独立文件（而非并进 probe_dial_observer.go）是为了让"挂载"与"翻译逻辑"
// 各自单一职责：本文件只管接线与开关判定，翻译在 probe_dial_observer.go。

import (
	realmtrace "github.com/sagernet/sing-box/transport/realm"
	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// attachProbeDialObserver 在埋点开启时给 realmOptions 挂上观测器。
//
// 🔴 Session 未开启埋点时返回 nil Trace，此时**不挂**观测器：挂一个只会 no-op 的
// 观测器虽然行为等价，但会让 squic 侧每次打洞多走四个空回调。开关关 = 零开销。
func attachProbeDialObserver(realmOptions *squic.Options, realmID string) {
	if realmOptions == nil {
		return
	}
	trace := realmtrace.Session(realmID, "hysteria2")
	if trace == nil {
		return
	}
	realmOptions.DialObserver = probeDialObserver{trace: trace, logger: realmOptions.Logger}
}
