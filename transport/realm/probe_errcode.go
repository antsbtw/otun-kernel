package realm

// probe_errcode.go —— 把错误原文映射为稳定枚举，便于聚合。
// 原文仍完整保留在 error_msg，枚举只是聚合键。
//
// ★ 搬自旧探针内核 probe 分支（commit 1d606d93），并在 kernel 侧修了一个
// 🔴 实测暴露的归类 bug，见 classifyError 上方注释。

import (
	"errors"
	"strings"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

const (
	ErrCodeUnknown           = "unknown"
	ErrCodeTimeout           = "timeout"
	ErrCodeCanceled          = "canceled"
	ErrCodeNoCandidates      = "no_candidates"
	ErrCodeNoSTUNResponse    = "no_stun_response"
	ErrCodeDNSFailure        = "dns_failure"
	ErrCodeConnectionRefused = "connection_refused"
	ErrCodeNetworkUnreach    = "network_unreachable"
	ErrCodeTLSFailure        = "tls_failure"
	ErrCodeAuthFailure       = "auth_failure"
	ErrCodeHTTPStatus        = "http_status"
	// ErrCodeNotAssigned：节点不认识这个用户（鉴权返 404）。
	//
	// 这**不是节点故障**，而是该账号没被分配到这个节点
	// （residential 是按需分配主/备，不是全节点可用）。
	// 与 auth_failure（凭证错/被拒）必须分开：前者说明"没分配"，
	// 后者说明"分配了但凭证不对"，指向完全不同的处理。
	// 混在一起会让未分配的健康节点在面板上显示成不可达。
	ErrCodeNotAssigned = "not_assigned"
)

// classifyError 按最具体优先匹配。顺序有意义：先匹配具体成因，
// 再落到 timeout 这类宽泛特征，避免「DNS 超时」被粗分成 timeout。
//
// 🔴 实测修正（2026-07-30，本轮 T5 暴露）：原版只按字符串认 hy2 的 404 措辞
// "authentication failed, status code: 404"，而五协议走的是会合面控制客户端，
// 同一个「节点没分配」错误的原文是 "control 404/realm_not_found: realm not registered"
// —— 不含 "status code: 404"，会被归成 unknown。
//
// ★ 后果正是本轮要防的「两把尺子」：同一种失败，hy2 报 not_assigned、
// 五协议报 unknown，面板上看着是两类问题，实际是一类。
// 修法是**优先按类型判**（*squic.StatusError 带真实 StatusCode），
// 字符串匹配退化为兜底 —— 类型比措辞稳定，措辞会随上游改。
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	// 类型优先：会合面返回的 HTTP 状态码是结构化的，不必猜措辞。
	var statusErr *squic.StatusError
	if errors.As(err, &statusErr) {
		switch {
		case statusErr.StatusCode == 404:
			return ErrCodeNotAssigned
		case statusErr.StatusCode == 401, statusErr.StatusCode == 403:
			return ErrCodeAuthFailure
		case statusErr.StatusCode > 0:
			return ErrCodeHTTPStatus
		}
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "no compatible peer addresses"):
		return ErrCodeNoCandidates
	case strings.Contains(msg, "no stun responses"):
		return ErrCodeNoSTUNResponse
	case strings.Contains(msg, "no such host"), strings.Contains(msg, "dns"):
		return ErrCodeDNSFailure
	case strings.Contains(msg, "connection refused"):
		return ErrCodeConnectionRefused
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "no route to host"):
		return ErrCodeNetworkUnreach
	case strings.Contains(msg, "x509"), strings.Contains(msg, "tls"), strings.Contains(msg, "certificate"):
		return ErrCodeTLSFailure
	// 404 必须先于通用 auth 匹配 —— 原文是
	// "authentication failed, status code: 404"，同时含 "auth" 与 "404"。
	// 顺序反了就会被归成 auth_failure，"没分配"和"凭证错"混为一谈。
	//
	// 🔴 三种措辞都要认，因为两条路径的 404 说法不同（见函数头注释）：
	//   hy2  ：authentication failed, status code: 404
	//   五协议：control 404/realm_not_found: realm not registered
	// 类型判断（上面的 StatusError）是主路径，这里是错误被扁平化后的兜底。
	case strings.Contains(msg, "status code: 404"), strings.Contains(msg, "status code 404"),
		strings.Contains(msg, "control 404/"), strings.Contains(msg, "realm_not_found"):
		return ErrCodeNotAssigned
	case strings.Contains(msg, "unauthorized"), strings.Contains(msg, "forbidden"), strings.Contains(msg, "auth"):
		return ErrCodeAuthFailure
	case strings.Contains(msg, "unexpected status"), strings.Contains(msg, "status code"):
		return ErrCodeHTTPStatus
	case strings.Contains(msg, "context canceled"):
		return ErrCodeCanceled
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return ErrCodeTimeout
	default:
		return ErrCodeUnknown
	}
}
