package realm

// probe_sink.go —— 埋点的**进程内出口**（生产客户端用）。
//
// ★ 为什么需要这个文件：
// 在此之前埋点只有一条出口 —— Emit() 打一行 JSON 到日志，供 prober 抓 stdout。
// 那条路对**探针**成立（prober 是父进程，读得到子进程的流），对**生产 App 不成立**：
// iOS/安卓的内核跑在 VPN extension 进程里，壳侧拿不到它的 stdout，
// 让 App 去 grep 自己的日志更是荒唐。埋点契约要的 fail_stage 卡在这里 ——
// 卡的从来不是「埋点没实现」，而是「实现了但没有出口」。
//
// 本文件补的就是那个出口：一个进程内回调。Emit 之外**新增**一条旁路，
// 不动既有日志行（prober 仍照常工作），也不动任何调用点。
//
// ★ 为什么是回调而不是让 kernel 直接上报：
// 上报要 HTTP 客户端、要重试、要落盘缓冲、要遵守用户的「不发送诊断数据」开关 ——
// 这些全是**壳侧**的职责（壳知道用户设置、知道端点、有网络栈）。内核只负责
// 「把事实交出去」。内核自己发网络请求还会绕开壳的代理/绑定策略，
// 那是另一类事故（见 [realm-client-punch-pitfalls] 里 TUN 抢 socket 的教训）。
//
// 🔴 隐私边界（与 probe_session.go 的默认关同源）：
// 完整 Trace 含反射地址、对端地址、候选列表 —— 那是**网络身份**，不该默认离开设备。
// 所以本文件提供两级：
//   - SetTraceSink：完整 Trace，探针/内部构建用；
//   - SetSummarySink：只给契约 P0 要的那几个字段（fail_stage / relay_used / …），
//     不含任何 IP。生产 App 接后者。
// 这正是 BLOCKING_QUESTIONS Q1.3「能否只暴露 fail_stage」的答案：能，且已划好线。

import "sync"

// Summary 是可安全上报的埋点摘要 —— 契约 §2.3 的 P0 字段集。
//
// 🔴 刻意**不含** local_srflx / peer_candidates / peer_addr_matched / relay_addr：
// 那些是 IP 级信息。摘要的取舍标准是「能回答『卡在哪一步』，但不描述『你是谁、在哪』」。
// 需要 IP 级细节的场景（探针）走 SetTraceSink 拿完整 Trace，那是受控环境。
type Summary struct {
	RealmID string `json:"realm_id,omitempty"`

	// Protocol 是内层协议，契约字段名 inner_protocol，取值六选一：
	// hysteria2 / tuic / reality / shadowsocks / trojan / vmess。
	//
	// 🔴 JSON tag 是 inner_protocol 而非 protocol（约定一：同名即同义）：
	// App 侧遥测里 protocol 恒为 "realm"（外层），与这里的内层协议是两件事，
	// 同名必串台。Go 字段名保留 Protocol 不动 —— 它与 Trace.Protocol 同源，
	// 改名会波及探针侧一片无关代码，而契约约束的是线上字段名。
	//
	// ⚠️ hysteria2 本期产不出：它的打洞编排在 vendored sing-quic 内部，
	// 不走 overlay 的 SessionOr 路径，Trace 恒 nil（见 probeentry/hysteria2.go）。
	// 这是数据源缺口，非出口缺口。本期实际可产出五值。
	Protocol string `json:"inner_protocol,omitempty"`

	// FailStage 是契约 P0 唯一必需字段：连接卡在哪一阶段。空 = 未失败。
	// 六值：rendezvous / stun / candidate / punch / handshake / first_byte。
	FailStage FailStage `json:"fail_stage,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`

	// Outcome 是给 App 的**判读结论**：success / failed，由 FailStage 是否为空派生。
	//
	// 🔴 它不是 TunnelEstablished 的同义词，两者刻意都保留：
	// outcome=success 表示这次尝试没有卡在任何阶段（含被中继救回的情形 ——
	// 那时 fail_stage 仍是 punch，故 outcome=failed）；TunnelEstablished 表示
	// 隧道确实建起来了。中继救回时二者会不一致，那正是要看见的事实。
	// 派生字段冗余但值得：App 侧不必重新实现「空 fail_stage 算成功」这条规则，
	// 免得两边口径漂移（约定一的同型风险）。
	// 🔴 同 RelayUsed 不带 omitempty：outcome 恒为 success/failed 二选一，
	// 没有"空"这个合法取值。带 omitempty 只会在派生逻辑出 bug 时把字段藏掉，
	// 让 App 侧看到"缺字段"而非"错值"——错误被静默是更坏的失败模式。
	Outcome string `json:"outcome"`

	// TunnelEstablished 只代表隧道建起来了，**不代表可用**。
	// 与 Emit 的注释同源：内核永远不自报 ok，别把它当成功率分子。
	TunnelEstablished bool `json:"tunnel_established"`

	// RelayUsed 回答契约 Q2：这条连接最终是不是靠中继救回来的。
	// 与 FailStage 正交 —— 中继救回时 fail_stage 仍是 punch（打洞确实失败了）。
	// 🔴 只给布尔不给 relay_addr：地址是拓扑信息，判定中继是否有效不需要它。
	// 若日后要按中继台分组，应由会合面下发一个稳定短名（relay_id），
	// 而不是让客户端把 IP 上报上来再反查 —— 见 Q2.2「请勿在客户端重新拼接」。
	//
	// 🔴 **不带 omitempty**（B4 契约 §2）：契约定义它是 proto3 bool，恒存在、缺省 false。
	// 带上 omitempty 时「直连打洞成功」会让字段整个消失，而前端判空用的是
	// assertNull 口径 —— 那会把"没用中继"读成"没有数据"，正是契约那条
	// ⚠️「没这条事件 ≠ relay_used=false」要避免的混淆。字段恒在，
	// "有没有数据"由**事件是否到达**回答，不由字段在不在回答。
	RelayUsed bool `json:"relay_used"`

	// NATTypeGuess 是判断「中继是否救回了对称 NAT 用户」的关键维度（契约 §5 第 6 条）。
	// cone/symmetric 是**线索非结论**，由多个 STUN 反射地址是否一致推断。
	//
	// 🔴 未判定时**留空**，不发 "unknown"（后端 2026-09-18 拍板）：
	// 契约 §2 定「空串 = 内核未能判定」。若再给一个字面量 "unknown"，
	// 同一件事就有两种表达，App 侧必须同时判空和判串——那是给自己造分叉。
	// 故 omitempty 保留，且 summarize 不把 NATTypeUnknown 翻译成字符串输出。
	NATTypeGuess NATTypeGuess `json:"nat_type,omitempty"`

	// Nonce 是本次打洞的 nonce（32 hex）——★双端 join 键，与节点侧
	// obs_punch_trace_egress.nonce / 中继日志同键，缺它双端数据只能按时间窗猜。
	//
	// 🔴 它是随机数不是地址：可安全上报，不违反本文件的隐私边界。
	Nonce string `json:"punch_nonce,omitempty"`

	// KernelTunnelReadyMs 是内核视角的隧道就绪耗时。
	//
	// 🔴 名字带 kernel_ 前缀是约定一的直接产物：内核视角的就绪与 App 侧
	// tunnel_ready 实测差约 10s，同名必串台，故不叫 tunnel_ready_ms。
	//
	// 🔴 取 Stages.TotalMs 而非 Stages.HandshakeMs：后者是**握手这一段**的耗时
	// （stageDone 从 stageStart 起算），不是「从开始到就绪」。HandshakeDone 里
	// TotalMs = msSince(t.start) 才是就绪落点。施工单原文写「取 HandshakeDone
	// 的落点毫秒」，落点正是 TotalMs——按 HandshakeMs 取会少算前面所有阶段。
	//
	// 失败时为 nil（omitempty 不出字段）：没就绪就没有就绪耗时，
	// 给 0 会被统计成「秒开」，比缺字段坏得多。
	KernelTunnelReadyMs *int64 `json:"kernel_tunnel_ready_ms,omitempty"`

	// TotalMs 是本次尝试的总耗时，用于区分「秒失败」与「熬到超时」。
	// 与 KernelTunnelReadyMs 在成功时同值，失败时只有它有值——保留两者是因为
	// 「失败熬了多久」和「成功多快就绪」是两个不同的问题。
	TotalMs *int64 `json:"total_ms,omitempty"`

	// EgressCountry 恒为空：内核不可知出口国，App 另有来源（契约 §2）。
	// 保留字段是为了让 JSON 形状与契约一致，App 侧不必为「内核少一个字段」做特判。
	EgressCountry string `json:"egress_country,omitempty"`
}

// OutcomeSuccess / OutcomeFailed 是 Summary.Outcome 的两个取值。
const (
	OutcomeSuccess = "success"
	OutcomeFailed  = "failed"
)

// summarize 从完整 Trace 抽取可上报字段。调用方须持有 t.access。
func (t *Trace) summarize() Summary {
	summary := Summary{
		RealmID:           t.RealmID,
		Protocol:          t.Protocol,
		FailStage:         t.FailStage,
		Outcome:           outcomeOf(t.FailStage),
		ErrorCode:         t.ErrorCode,
		TunnelEstablished: t.TunnelEstablished,
		RelayUsed:         t.RelayUsed,
		Nonce:             t.Nonce,
		TotalMs:           t.Stages.TotalMs,
	}

	// NATTypeUnknown 不外送：契约定「空 = 未判定」，见字段注释。
	if t.Punch.NATTypeGuess != NATTypeUnknown {
		summary.NATTypeGuess = t.Punch.NATTypeGuess
	}

	// 只有隧道真建起来了才有「就绪耗时」。没建起来时留 nil，
	// 不要把失败的总耗时冒充成就绪耗时。
	if t.TunnelEstablished {
		summary.KernelTunnelReadyMs = t.Stages.TotalMs
	}

	return summary
}

// outcomeOf 由 FailStage 派生判读结论。空 FailStage = 没卡在任何阶段 = success。
//
// 🔴 中继救回的连接在这里是 failed：那时 fail_stage 仍是 punch（打洞确实失败，
// 是真实卡点），relay_used=true 才是「最终连上了」的证据。两个口径不合并 ——
// 合并会让「打洞成功率」和「连接成功率」互相污染，见 Trace.RelayUsed 的注释。
func outcomeOf(stage FailStage) string {
	if stage == "" {
		return OutcomeSuccess
	}
	return OutcomeFailed
}

// sinks 保存进程级回调。用 RWMutex 而非 atomic：设置发生在启动期（一次），
// 读发生在每次连接收尾（低频），读写比悬殊但都不在热路径上，
// 用最直白的同步原语即可，不值得为此上 atomic.Value 的复杂度。
var sinks struct {
	access  sync.RWMutex
	trace   func(*Trace)
	summary func(Summary)
}

// SetTraceSink 注册完整 Trace 的进程内出口。传 nil 注销。
//
// 🔴 含 IP 级信息，仅供探针/受控构建使用。生产 App 请用 SetSummarySink。
//
// 回调在**连接收尾的调用协程**上同步执行：实现方必须快速返回（入队即走），
// 阻塞会拖慢用户的连接路径。内核不替你起 goroutine —— 那样会把「回调何时执行、
// 能否被取消」这类语义藏进内核，壳侧反而更难控制。
func SetTraceSink(fn func(*Trace)) {
	sinks.access.Lock()
	defer sinks.access.Unlock()
	sinks.trace = fn
}

// SetSummarySink 注册摘要出口（生产客户端用）。传 nil 注销。
//
// 注册它即等于打开生产埋点：无需 OTUN_PROBE_TRACE 环境变量
// —— App 里没人能设环境变量，这正是 Q1.2「旁路可关而非分支隔离」的落法。
// 要关就注销（传 nil），对应用户关掉「发送诊断数据」。
//
// 同上：回调同步执行，请勿在其中做网络 I/O。
func SetSummarySink(fn func(Summary)) {
	sinks.access.Lock()
	defer sinks.access.Unlock()
	sinks.summary = fn
}

// TraceSinkEnabled 报告是否有任一出口已注册 —— 用于让生产路径在「注册了 sink」时
// 也创建 Trace（否则 Session 只认环境变量，App 永远拿不到埋点）。
//
// 导出是因为 overlay/tuic 需要它：tuic 惰性打洞，在 overlay 层就要决定
// 走哪条 punchFn，不能等到 Session 才判。
func TraceSinkEnabled() bool {
	sinks.access.RLock()
	defer sinks.access.RUnlock()
	return sinks.trace != nil || sinks.summary != nil
}

// dispatch 把一条已完成的 Trace 送到已注册的出口。trace 为 nil 时无操作。
//
// ★ 摘要在**持锁状态下**抽取，完整 Trace 则原样交出：
// 前者保证读到的是一致快照；后者的并发安全由 Trace 自己的方法（含 MarshalJSON）
// 负责，接收方只要不越过导出方法直接摸字段就是安全的。
func dispatch(trace *Trace) {
	if trace == nil {
		return
	}
	sinks.access.RLock()
	traceFn, summaryFn := sinks.trace, sinks.summary
	sinks.access.RUnlock()
	if traceFn == nil && summaryFn == nil {
		return
	}
	if summaryFn != nil {
		trace.access.Lock()
		summary := trace.summarize()
		trace.access.Unlock()
		summaryFn(summary)
	}
	if traceFn != nil {
		traceFn(trace)
	}
}
