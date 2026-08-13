package libbox

import "github.com/sagernet/sing-box/experimental/probeentry"

// probe.go —— 把探针入口(experimental/probeentry)通过 libbox 这个既有 gomobile
// 绑定面暴露给安卓壳(otun-probe-android),复用现有 aar 构建管线,不新增 gomobile
// target。生产 App 不调这些符号,多带一个只读入口无副作用。
//
// gomobile 约束:参数/返回值只用 string + 自定义接口(方法签名也只用可绑定类型)。
// ProbeBinder.BindFD(int64) error 满足;ProbeRun(string, ProbeBinder) string 满足。

// ProbeBinder 是安卓壳实现的网络绑定回调:拿到 socket fd 后绑到指定 Network
// (Network.bindSocket)。返回非 nil error → 该 socket fail-closed(不静默落回
// 默认网络)。gomobile 会为它生成 Java 接口,壳侧实现即可。
type ProbeBinder interface {
	BindFD(fd int64) error
}

// ProbeRun 执行一次探测。specJSON 是枚举 API 的 per_protocol 条目 + 探测控制字段
// (protocol/path/judge_url/…,见 probeentry.Spec);binder 可为 null(不绑定网络,
// 调试用)。返回一个 JSON 序列化的 probeentry.Result(即使 spec 解析失败也返回
// 一个带 err 的 Result,壳侧只需解析一种结构)。
//
// 单次语义:轮询 N 次由壳侧循环(每次独立 ProbeRun),入口不藏循环 —— 可复现、
// 可中断,契合探针「手动指定、逐次可比」的目标。
func ProbeRun(specJSON string, binder ProbeBinder) string {
	return probeentry.RunProbeJSON(specJSON, probeBinderAdapter{binder})
}

// probeBinderAdapter 把 gomobile 接口 ProbeBinder 适配成 probeentry.Binder
// (= netbind.Binder)。null binder(壳侧不传)→ 适配器内层为 nil,RunProbe 侧
// 按「不绑定」处理。
type probeBinderAdapter struct {
	inner ProbeBinder
}

func (a probeBinderAdapter) BindFD(fd int64) error {
	if a.inner == nil {
		return nil
	}
	return a.inner.BindFD(fd)
}
