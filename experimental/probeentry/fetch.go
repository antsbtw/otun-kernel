package probeentry

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sagernet/sing-box/experimental/probeportal"
)

// FetchSpec 是安卓壳/入口发起「登录取数」的输入(JSON)。密码在此传入,只用于
// 一次登录请求,不落盘不进日志(probeportal.Login 的约束)。
type FetchSpec struct {
	PortalBase string `json:"portal_base"` // 默认 https://portal.situstechnologies.com
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceID   string `json:"device_id"`  // 固定可辨识,别每轮随机(污染设备图谱)
	AutoAdmit  bool   `json:"auto_admit"` // 对未授权国 select-country(只对探测账号安全)

	// 探测控制:透传进每条生成的 Spec(壳可覆盖,缺省用内核默认)。
	Path      string `json:"path,omitempty"`       // normal|punch_only|relay_only
	JudgeURL  string `json:"judge_url,omitempty"`  // 缺省内核用 youtube
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

// FetchResult 是 FetchTargets 的输出(JSON):一批可直接喂给 RunProbe 的 Spec,
// 或一条错误。壳侧对每条 Spec 调 RunProbe(可叠加网络/路径维度轮询)。
type FetchResult struct {
	Specs []Spec `json:"specs"`
	Err   string `json:"err,omitempty"`
}

// FetchTargets 用探测账号登录公网 portal,拿全部在线节点×协议的连接串,转成 Spec。
// 🔴 这是探针取数的正路(与 Linux prober 同源):走公网 BFF,真机蜂窝可达,
// 不依赖内网枚举 API。connect 参数(token/uuid/stun/reality 等)全来自 API 下发,
// 与用户拿到的配置同源。
func FetchTargets(ctx context.Context, fs *FetchSpec) FetchResult {
	base := fs.PortalBase
	if base == "" {
		base = "https://portal.situstechnologies.com"
	}
	deviceID := fs.DeviceID
	if deviceID == "" {
		deviceID = "otun-probe-android"
	}
	client := probeportal.NewPortalClient(base, probeportal.Account{
		Email:    fs.Email,
		DeviceID: deviceID,
	})

	fetchCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	nodes, err := client.FetchAllTargets(fetchCtx, fs.Password, fs.AutoAdmit)
	if err != nil {
		return FetchResult{Err: err.Error()}
	}

	specs := make([]Spec, 0, len(nodes)*6)
	for _, node := range nodes {
		for proto, u := range node.ByProto {
			specs = append(specs, realmURLToSpec(node.EgressID, proto, u, fs))
		}
	}
	return FetchResult{Specs: specs}
}

// FetchTargetsJSON 是 gomobile 友好入口:JSON 进 JSON 出。
func FetchTargetsJSON(fetchSpecJSON string) string {
	var fs FetchSpec
	if err := json.Unmarshal([]byte(fetchSpecJSON), &fs); err != nil {
		return marshalFetchResult(FetchResult{Err: "parse fetch spec: " + err.Error()})
	}
	return marshalFetchResult(FetchTargets(context.Background(), &fs))
}

func marshalFetchResult(r FetchResult) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"err":"marshal fetch result"}`
	}
	return string(b)
}

// realmURLToSpec 把一条解析好的 -realm 连接串(portal 下发)转成 probeentry.Spec。
// 字段来源全部是 API 下发值,不自拼(与后端 buildProtoConnectURL 同源)。
func realmURLToSpec(egressID, proto string, u probeportal.RealmURL, fs *FetchSpec) Spec {
	s := Spec{
		Protocol:           proto,
		RealmID:            u.RealmID,
		ServerURL:          u.RendezvousURL,
		Token:              u.Token,
		UUID:               u.UUID,
		STUN:               u.STUNServers, // 来自 smart_strategy(不在 URL 里)
		SNI:                u.SNI,
		Insecure:           u.Insecure,
		RendezvousInsecure: u.Insecure, // 会合面自签同 insecure 语义
		Obfs:               u.Obfs,
		Method:             u.SSMethod,
		SSPassword:         u.SSPassword,
		CongestionControl:  u.CongestionControl,
		RealityPublicKey:   u.RealityPublicKey,
		RealityShortID:     u.RealityShortID,
		RealityServerName:  u.RealityServerName,
		Path:               Path(fs.Path),
		JudgeURL:           fs.JudgeURL,
		TimeoutMS:          fs.TimeoutMS,
	}
	// CN 落地节点用国内判据(google 204 在国内不通是预期,非故障)——
	// 壳未指定 judge_url 且该节点出口在 CN 时,给一个国内目标。
	if s.JudgeURL == "" && u.ExitCountry == "CN" {
		s.JudgeURL = "https://www.baidu.com/"
	}
	return s
}
