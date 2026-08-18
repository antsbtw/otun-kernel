package libbox

// telemetry.go —— 把 realm 埋点摘要经 libbox 既有 gomobile 绑定面交给壳侧。
//
// ★ 这是 BLOCKING_QUESTIONS_TELEMETRY_2026-08-18 Q1 的落点：
// 埋点本身（七阶段 fail_stage / nat_type_guess / relay_used）内核**早已实现**，
// 缺的一直是「生产 App 怎么拿到」—— 之前唯一的出口是打一行 JSON 到 stdout，
// 那对 prober 成立，对跑在 VPN extension 里的 App 不成立。本文件补上出口。
//
// ★ 职责边界（刻意划死）：
// 内核只把**事实**交出去，一次一条，同步回调。上报、重试、落盘缓冲、
// 遵守用户的「发送诊断数据」开关 —— 全在壳侧。理由见 transport/realm/probe_sink.go：
// 内核自己发网络请求会绕开壳的代理/绑定策略，那是另一类事故。
//
// gomobile 约束:回调接口的方法签名只能用可绑定类型(string/int64/bool/error/接口)。
// 所以这里**不**把 Summary 结构体直接绑出去 —— 结构体字段里的 *int64 绑不了，
// 而且每加一个字段就要改 Java/Swift 侧签名。改为传一行 JSON:
// 壳侧按需解析,内核加字段不破坏绑定面(与 ProbeRun 返回 JSON 同一手法)。

import (
	"encoding/json"

	"github.com/sagernet/sing-box/transport/realm"
)

// TelemetrySink 是壳侧实现的埋点接收口。
//
// OnRealmAttempt 在**每次 realm 连接尝试收尾时**被调用一次（成功或失败都调），
// summaryJSON 是一个 realm.Summary 的 JSON 对象，字段见契约 §2.3：
//
//	{"realm_id","protocol","fail_stage","error_code",
//	 "tunnel_established","relay_used","nat_type_guess","total_ms"}
//
// 🔴 不含任何 IP / 候选地址 —— 摘要的取舍标准是「能回答『卡在哪一步』，
// 但不描述『你是谁、在哪』」。需要 IP 级细节的是探针，走 ProbeRun，那是受控环境。
//
// 🔴 tunnel_established 不等于连接可用，别拿它当成功率分子：
// 内核只能证明隧道建起来了，能不能真正跑流量得由上层真实往返判定。
//
// 🔴 实现必须**立即返回**（入队即走）：回调跑在用户的连接路径上，
// 在里面做网络 I/O 或加锁等待会直接拖慢连接。
type TelemetrySink interface {
	OnRealmAttempt(summaryJSON string)
}

// SetTelemetrySink 注册埋点出口；传 null 注销。
//
// ★ 注册即开启，注销即关闭 —— 这正是 Q1.2 要的「旁路可关，而非靠分支隔离」。
// 未注册时内核连 Trace 都不创建，生产路径逐字节不变（见 realm.Session）。
// 用户关掉「发送诊断数据」时，壳侧调 SetTelemetrySink(null) 即可，
// 不需要重启内核，也不需要任何配置字段。
func SetTelemetrySink(sink TelemetrySink) {
	if sink == nil {
		realm.SetSummarySink(nil)
		return
	}
	realm.SetSummarySink(func(summary realm.Summary) {
		encoded, err := json.Marshal(summary)
		if err != nil {
			// 序列化失败就丢弃：埋点是旁路，绝不能因为它自身出错而影响连接，
			// 更不该为了报告一个 marshal 错误再造一条假埋点。
			return
		}
		sink.OnRealmAttempt(string(encoded))
	})
}
