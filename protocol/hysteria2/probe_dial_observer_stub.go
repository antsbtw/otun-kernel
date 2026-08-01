//go:build !otun_probe_trace

package hysteria2

// probe_dial_observer_stub.go —— 生产构建（不带 otun_probe_trace tag）下的空实现。
//
// 生产 go.mod 走上游 sing-quic，realm.Options 里根本没有 DialObserver 字段，
// 所以这里不能碰 realmOptions 的任何埋点字段——空函数即可，调用点无需判条件编译。
// 这是三层隔离的第一层（见 probe_dial_observer.go 顶部说明）。

import squic "github.com/sagernet/sing-quic/hysteria2/realm"

func attachProbeDialObserver(_ *squic.Options, _ string) {}
