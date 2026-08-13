// Package probeentry is the probe app's single kernel entry point
// (HANDOFF_PROBE_ENTRY_AND_SHELL.md §3): one call takes a fully-specified
// {node, protocol, path} target — the shape the enum API's per_protocol entry
// already hands out — plus a network Binder, dials it once, drives a real
// round-trip over the tunnel for the verdict, and returns a structured result
// with the realm trace embedded.
//
// 它刻意脱离 libbox 的配置驱动路径:探针要「手动指定路径 + 每次拿结构化 trace」,
// 那是 option-driven 的 outbound 给不了的。所以本包直接拼 overlay 调用,
// realm.Config 的 socket/HTTP/DNS 全走注入的 netbind.Dialer(WiFi/蜂窝强制绑定)。
//
// 单次语义:一次 RunProbe = 一次探测。轮询 N 次由外壳循环(每次独立 RunProbe),
// 保持可复现、可中断 —— 入口不藏循环。
//
// 判据纪律(§2 / probe_session.go 顶部红字):内核只证「隧道建起来了」;
// 是否真的可用由本入口经隧道对 judge_url 做真实 2xx 往返判定。
// 🔴 只信 youtube 200:gen_204 在中国移动恒真,是假判据,默认 judge_url 用 youtube。
package probeentry

import "github.com/sagernet/sing-box/common/netbind"

// Path 选打洞路径。字符串取值与外壳/枚举侧对齐(json 直传)。
type Path string

const (
	PathNormal    Path = "normal"     // 打洞优先,失败回退中继(生产同款)
	PathPunchOnly Path = "punch_only" // 只打洞,禁中继回退(隔离验证打洞本身)
	PathRelayOnly Path = "relay_only" // 跳过打洞直连中继(隔离验证中继链路)
)

// Spec 是一次探测的完整输入。字段与枚举 API 的 per_protocol 条目一一对应
// (protocol/realm_id/server_url/token/uuid/stun/sni/协议专属),外壳把枚举结果
// 原样填进来即可,不需要理解协议细节。
//
// 🔴 relay_addresses 不在此:中继地址由会合面在 /connect 应答里下发(节点注册时
// 上报给会合面),客户端配置里没有它。path=relay_only 时靠会合面下发,下发为空
// 即按 candidate 阶段失败 —— 这正是「这台没配中继」的正确归类。
type Spec struct {
	Protocol  string `json:"protocol"`   // trojan|tuic|reality|shadowsocks|vmess|hysteria2
	RealmID   string `json:"realm_id"`   // 派生后的 <base>-<proto后缀>
	ServerURL string `json:"server_url"` // 会合面地址(realm.Config.ServerURL)
	Token     string `json:"token"`      // 出口级 token
	UUID      string `json:"uuid"`       // per-user 凭证(探针测试 uuid)

	STUN               []string `json:"stun,omitempty"`
	SNI                string   `json:"sni,omitempty"`                 // 外层 wrap TLS server_name
	Insecure           bool     `json:"insecure,omitempty"`            // 会合面/wrap 自签 → 跳过校验
	RendezvousInsecure bool     `json:"rendezvous_insecure,omitempty"` // 会合面 control 通道自签(= enum 同名字段)

	// 协议专属(缺省即不适用):
	Obfs              string `json:"obfs,omitempty"`               // hy2 salamander
	Method            string `json:"method,omitempty"`             // ss AEAD
	SSPassword        string `json:"ss_password,omitempty"`        // ss per-user(空=贯穿 uuid)
	CongestionControl string `json:"congestion_control,omitempty"` // tuic
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	RealityShortID    string `json:"reality_short_id,omitempty"`
	RealityServerName string `json:"reality_server_name,omitempty"` // reality 借壳 SNI

	// 探测控制:
	Path      Path   `json:"path,omitempty"`       // 默认 normal
	JudgeURL  string `json:"judge_url,omitempty"`  // 默认 https://www.youtube.com/
	TimeoutMS int    `json:"timeout_ms,omitempty"` // 默认 15000
}

func (s *Spec) path() Path {
	if s.Path == "" {
		return PathNormal
	}
	return s.Path
}

func (s *Spec) judgeURL() string {
	if s.JudgeURL == "" {
		// 🔴 youtube 200 是唯一可信判据(gen_204 在中国移动恒真)。
		return "https://www.youtube.com/"
	}
	return s.JudgeURL
}

func (s *Spec) timeoutMS() int {
	if s.TimeoutMS <= 0 {
		return 15000
	}
	return s.TimeoutMS
}

// Result 是一次探测的结构化输出。TunnelEstablished=true 只表示隧道建起来了;
// Success=true 才表示经隧道的真实往返拿到 2xx(可信判据)。两者刻意分开 ——
// 内核永远不把「隧道建起来」当「可用」(遥测假 success 教训)。
type Result struct {
	Protocol string `json:"protocol"`
	Path     Path   `json:"path"`

	TunnelEstablished bool   `json:"tunnel_established"`
	Success           bool   `json:"success"`          // judge_url 真实往返 2xx
	FailStage         string `json:"fail_stage,omitempty"` // 来自 realm trace 或 judge 阶段
	Err               string `json:"err,omitempty"`

	JudgeStatus int   `json:"judge_status,omitempty"` // 实际 HTTP 状态码
	JudgeMS     int64 `json:"judge_ms,omitempty"`     // 往返耗时
	TotalMS     int64 `json:"total_ms,omitempty"`

	// Trace 是 realm 打洞/中继的原样埋点(可能为 nil,如 hy2 或未开埋点)。
	Trace interface{} `json:"trace,omitempty"`
}

// Binder 是 netbind.Binder 的别名,gomobile 从本包导出时用同一个类型。
type Binder = netbind.Binder
