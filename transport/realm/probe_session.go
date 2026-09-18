package realm

// probe_session.go —— 埋点的开关与串联入口（kernel 侧新增，probe 分支没有）。
//
// ★ 为什么 kernel 需要开关，而旧探针内核不需要：
// 旧的 antsbtw/sing-box probe 分支是**探针专用分支**，`offerNewRealm` 里
// 无条件 `realm.NewTrace(...)` 是安全的 —— 那个二进制只跑在探针上。
// 🔴 但本仓是**生产客户端**（用户手机上跑的就是它）。无条件埋点意味着
// 每个用户每次连接都多一行含反射地址/对端地址的 JSON 日志 —— 既是噪音也是隐私面。
// 所以这里加一道显式开关，默认关；关掉时 Session 返回 nil，
// 而 nil *Trace 的所有方法都是 no-op（见 probe_trace.go），生产路径零影响。
//
// ★ 开关选环境变量而非配置字段，是刻意的：
// 配置字段会进入 option.RealmOptions 的公开契约，用户配置可能误开；
// 环境变量只有启动进程的人（prober）能设，生产配置面**一个字段都不用加**。

import (
	"encoding/json"
	"os"

	"github.com/sagernet/sing/common/logger"
)

// ProbeTraceEnv 是打开埋点的环境变量名。值为 "1" 时开启。
//
// 🔴 只认 "1"：不接受 true/yes/on 之类的宽松取值，避免「设了个 0 反而开了」
// 这类经典事故。开关的语义必须一眼可判。
const ProbeTraceEnv = "OTUN_PROBE_TRACE"

// ProbeTraceEnabled 报告本进程是否开启埋点。
func ProbeTraceEnabled() bool {
	return os.Getenv(ProbeTraceEnv) == "1"
}

// Session 在埋点开启时创建一个 Trace，否则返回 nil。
//
// 返回 nil 是正常路径而非错误：调用方**不需要判空**，直接把它交给
// PunchTraced 和 trace.XxxDone() 即可 —— nil receiver 全是 no-op。
// 这正是让「生产路径零改动」成立的设计。
//
// ★ 两个开启条件（2026-08-18 增补第二个）：
//  1. OTUN_PROBE_TRACE=1 —— 探针进程用，只有起进程的人能设；
//  2. 注册了进程内 sink（SetSummarySink/SetTraceSink）—— 生产 App 用，
//     因为 App 里没人能设环境变量。见 probe_sink.go 的立意。
//
// 两者都没有时仍返回 nil，生产默认路径逐字节不变。
func Session(realmID string, protocol string) *Trace {
	if !ProbeTraceEnabled() && !TraceSinkEnabled() {
		return nil
	}
	return NewTrace(realmID, protocol)
}

// SessionOr 是探针入口的 trace 选择器:injected 非 nil 时用它(探针把 trace 回填
// 进结构化结果,不走 env/日志行);否则回到 env 驱动的 Session(生产未开埋点即
// nil,零影响)。五个 overlay 的 Dial 用它统一「探针注入 vs 生产 env」两条来源。
func SessionOr(injected *Trace, realmID string, protocol string) *Trace {
	if injected != nil {
		return injected
	}
	return Session(realmID, protocol)
}

// Emit 把埋点以单行 JSON 输出，前缀固定便于 prober 精确提取。
// trace 为 nil（未开启埋点）时什么都不做。
//
// 🔴 tunnel_established 不等于 ok。内核只能证明隧道建起来了；
// 是否真的可用必须由 prober 经隧道做真实往返（2xx）判定 ——
// 这条是吸取遥测假 success 教训后定下的，内核侧永远不要自报 ok。
//
// 输出走 logger.Info：prober 读的是子进程的 stderr/stdout 合并流，
// sing-box 的日志默认写到那里，前缀 OTUN_PROBE_TRACE_V1 保证可精确切分。
// ★ 两条出口，互不依赖（2026-08-18 增补 sink）：
//   - 日志行：prober 抓 stdout 用，行为逐字节不变；
//   - 进程内 sink：生产 App 用，见 probe_sink.go。
//
// 🔴 sink 的派发**不能**放在 `log == nil` 的早退之后 —— 生产壳侧完全可能
// 传 logger.NOP() 或不配日志，那时埋点照样必须送达。两条出口各判各的前置条件。
func Emit(log logger.Logger, trace *Trace) {
	if trace == nil {
		return
	}
	dispatch(trace)
	if log == nil {
		return
	}
	encoded, err := json.Marshal(trace)
	if err != nil {
		return
	}
	log.Info(ProbeTraceLogPrefix, " ", string(encoded))
}

// HandshakeDoneAndEmit 是五个 overlay 的统一收尾：记握手完成 + 输出。
//
// ★ 抽成一个函数而不是让每个 overlay 各写两行，是为了**尺子的一致性由代码结构
// 保证，而不是靠纪律**（这正是本轮埋点的立身之本）。五个协议共用这一个收尾，
// handshake_ms 的计时终点就不可能漂。
func HandshakeDoneAndEmit(log logger.Logger, trace *Trace) {
	if trace == nil {
		return
	}
	trace.HandshakeDone()
	Emit(log, trace)
}

// FailAndEmit 是五个 overlay 的统一失败收尾。
//
// 🔴 只在 Punch 之后的阶段（wrap/handshake）调用 —— Punch 内部的失败
// PunchTraced 已经归好类了，这里再调会被 Trace.Fail 的「首次生效」挡住，
// 不会覆盖真实卡点，但语义上不该重复归类。
func FailAndEmit(log logger.Logger, trace *Trace, stage FailStage, err error) {
	if trace == nil {
		return
	}
	trace.Fail(stage, err)
	Emit(log, trace)
}
