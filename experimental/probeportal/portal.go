// Package probeportal 是探针的「客户端那一半」：用探测账号登录公网 portal BFF，
// 调 iOS/macOS 客户端用的那几个端点拿六协议连接串。移植自 otun-probe-mesh 的
// prober/client.go（逐字节搬来，只改 package + 内联两个小工具 + 导出），
// 使 Android/内核探针与 Linux prober 用**同一套**取数逻辑（同源=可比）。
//
// 为什么探针必须走这条路而不是内网枚举 API：探针的配置若与用户拿到的配置不同源，
// 测得再准也证明不了用户的问题。本包只用客户端端点，一个都不多。
//
// 🔴 本层不得引入任何写系统文件或改路由的能力 —— 只有 HTTP 与内存里的 token。
package probeportal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 客户端端点。与 CLIENT_API_CONTRACT_V3 §4.1/§4.8 一致。
//
// ★基址必须是 portal.situstechnologies.com。situstechnologies.com 是官网，
// 打 /api/v1/* 一律返 Route not found（实测踩过）。
const (
	pathLogin         = "/api/v1/auth/login"
	pathRefresh       = "/api/v1/auth/refresh"
	pathRegions       = "/api/v1/resources/vpn/regions"
	pathCountries     = "/api/v1/resources/vpn/countries"
	pathSelectCountry = "/api/v1/resources/vpn/select-country"
	pathConnectURL    = "/api/v1/resources/vpn/connect-url"
	// 端点 67a：切换确认握手的就绪轮询。
	pathRegionStatus = "/api/v1/resources/vpn/region/status"
)

// 握手轮询参数，取契约 §7.3 的建议值（~1s 间隔，35s 超时）。
const (
	readyPollInterval = 1 * time.Second
	readyPollTimeout  = 35 * time.Second
)

// StatusRateLimited 与 StatusNotAssigned 同类：都是"没测"，不是"节点坏"。
//
// 🔴 面板上必须与真实故障区分（中性色，不标红）。准入被限流意味着这一轮
// 拿不到权限，节点本身的健康状况**未知** —— 标红等于凭空造一个故障。
const StatusRateLimited = "rate_limited"

// Account 是探测账号。🔴 密码只从环境变量取，不落 policy.json、不进日志、不进上报。
type Account struct {
	Email       string `json:"email"`
	PasswordEnv string `json:"password_env"`
	// DeviceID 是 auth 设备图谱的键。
	// 🔴 必须固定且可辨识（如 probe-realm-cn-01）—— 每轮随机会在设备图谱里
	// 刷出无数条记录，污染设备去重的真源。
	DeviceID string `json:"device_id"`
}

// Egress 是 /regions 返回的一个节点。
type Egress struct {
	EgressID    string `json:"egress_id"`
	Region      string `json:"region"` // ★这条路径上 region = 大写 ISO 国家码（§7.3 注）
	DisplayName string `json:"display_name"`
	Online      bool   `json:"online"`
	IsCurrent   bool   `json:"is_current"`
}

// Country 是 /countries 返回的一国授权状态。
type Country struct {
	Country         string `json:"country"`
	DisplayName     string `json:"display_name"`
	OnlineNodeCount int    `json:"online_node_count"`
	IsCurrent       bool   `json:"is_current"`
	// InAuthorizedSet 取代了过去手工维护的 assigned_nodes 快照。
	// 手工快照必然过期，会造出"面板显示 not_assigned 但其实早有权限"的假象。
	InAuthorizedSet bool `json:"in_authorized_set"`
}

// SmartStrategy 是下发的分流策略。探针只取 STUN 一项。
//
// ★实测事实（2026-07-30）：**STUN 服务器不在连接串里**，而在
// smart_strategy.default_stun（逗号分隔）。真实客户端就是从这里取的，
// 所以探针也必须从这里取 —— 硬编码一份就又回到"探的不是用户走的路"。
//
// 🔴 实测值是 IP 而非域名（74.125.250.129:19302,162.159.207.0:3478）。
// 域名在跨海链路上解析不出来是踩过的坑（见 [跨海STUN要害域名改IP已修]），
// 别"顺手"把它换回域名。
type SmartStrategy struct {
	DefaultSTUN string `json:"default_stun"`
	// UpMbps/DownMbps 是 hy2 的带宽声明。hy2 的 BBR **强依赖**这两个值 ——
	// 填错等于测的不是用户真实体验（见 [CCTV5卡顿新根因=带宽档10Mbps]：
	// 带宽档本身就能造成"卡顿像节点故障"）。
	//
	// 🔴 必须从下发取而不是硬编码：实测现网六个区域都是 20/20，与旧硬编码一致，
	// 所以这个改动今天行为不变；价值在于**现网改了探针会跟着改**，
	// 而硬编码会静默偏离，且偏离时表现为"节点变慢了"而非"探针配置过时了"。
	UpMbps   int `json:"up_mbps"`
	DownMbps int `json:"down_mbps"`
}

// STUNServers 把 default_stun 拆成列表。
func (s SmartStrategy) STUNServers() []string {
	var servers []string
	for _, item := range strings.Split(s.DefaultSTUN, ",") {
		if item = strings.TrimSpace(item); item != "" {
			servers = append(servers, item)
		}
	}
	return servers
}

// ConnectURLs 是 /connect-url 或 select-country 的连接串部分。
type ConnectURLs struct {
	OK       bool   `json:"ok"`
	EgressID string `json:"egress_id"`
	// Ready=false 表示凭证尚未下发到节点，必须轮询端点 67a 等就绪。
	//
	// 🔴 忽略这个字段的后果是实测踩到的：准入成功后立刻拨测，6 个节点
	// 全 auth_failure 404 —— 凭证还没到节点，看起来像"节点全坏了"。
	// 9 秒后再探就全通。指针类型是为了区分"没下发这个字段"与"显式 false"。
	Ready         *bool         `json:"ready"`
	ConnectURL    string        `json:"connect_url"`
	ConnectURLs   []string      `json:"connect_urls"`
	SmartStrategy SmartStrategy `json:"smart_strategy"`
	Nodes         []struct {
		EgressID    string   `json:"egress_id"`
		Role        string   `json:"role"`
		ConnectURL  string   `json:"connect_url"`
		ConnectURLs []string `json:"connect_urls"`
	} `json:"nodes"`
	// Regions 是区域判断的唯一可靠依据（§7.3.1）：块级 country 100% 下发，
	// 且同块内节点必属该国。顶层 nodes[] 曾是跨国平铺，不能当"当前国主备"。
	Regions []Region `json:"regions"`
}

// Region 是一个授权集区域包（§7.3.1）。
type Region struct {
	Country   string `json:"country"`
	State     string `json:"state"` // active | switching
	IsCurrent bool   `json:"is_current"`
	Nodes     []struct {
		EgressID string `json:"egress_id"`
		Role     string `json:"role"`
	} `json:"nodes"`
	Protocols []struct {
		Protocol string `json:"protocol"`
		URL      string `json:"url"`
		Node     string `json:"node"` // primary | backup
	} `json:"protocols"`
	// 每国自带一份策略；STUN 优先用块内的（跨国时全局那份未必适用）。
	SmartStrategy SmartStrategy `json:"smart_strategy"`
}

// PortalClient 是探针的客户端层。零磁盘写入，token 只在内存。
type PortalClient struct {
	baseURL string
	account Account
	http    *http.Client

	accessToken  string
	refreshToken string
	// tokenExpiry 用于在 access_token 到期前主动刷新，避免中途 401 打断一轮探测。
	tokenExpiry time.Time
}

// NewPortalClient 构造客户端。password 由调用方从环境变量取，不在这里读 —— 便于测试。
func NewPortalClient(baseURL string, account Account) *PortalClient {
	return &PortalClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		account: account,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// apiError 携带 HTTP 状态与 realm 业务错误码。
//
// ⚠️ realm 端点的业务错误在 data.error 里，不是标准信封的 error.code（§7.3 末）。
// 429 带 retry_after_sec。基础设施错误的 error 还可能是字符串而非对象 —— 解码必须容错，
// 否则一个信封形状变化就会把真实错因变成"JSON 解析失败"。
type apiError struct {
	StatusCode    int
	Code          string
	RetryAfterSec int
	Body          string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("HTTP %d %s", e.StatusCode, e.Code)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, tailLines(e.Body, 2))
}

// IsRateLimited 报告是否为切换/准入超频。
func (e *apiError) IsRateLimited() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.Code == "switch_rate_limited"
}

// envelope 覆盖 BFF 的 {success,data} 信封。
type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	// Error 可能是对象也可能是字符串，故用 RawMessage 延后解释。
	Error json.RawMessage `json:"error"`
}

// decodeAPIError 从响应体里挖出真实错因。
// 三种形状都要兼容：data.error（realm 业务）、error.code（信封 A）、error 字符串（基础设施）。
func decodeAPIError(statusCode int, body []byte) *apiError {
	result := &apiError{StatusCode: statusCode, Body: string(body)}

	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return result
	}
	if len(env.Data) > 0 {
		var data struct {
			Error         string `json:"error"`
			RetryAfterSec int    `json:"retry_after_sec"`
		}
		if err := json.Unmarshal(env.Data, &data); err == nil && data.Error != "" {
			result.Code = data.Error
			result.RetryAfterSec = data.RetryAfterSec
			return result
		}
	}
	if len(env.Error) > 0 {
		var errObject struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(env.Error, &errObject); err == nil && errObject.Code != "" {
			result.Code = errObject.Code
			return result
		}
		var errText string
		if err := json.Unmarshal(env.Error, &errText); err == nil && errText != "" {
			result.Code = errText
		}
	}
	return result
}

// do 发一次请求并解开信封，把 data 写进 out。
// authenticated=false 用于登录本身（此时还没有 token）。
func (c *PortalClient) do(
	ctx context.Context,
	method, path string,
	requestBody any,
	out any,
	authenticated bool,
) error {
	var reader io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		if err := c.ensureToken(ctx); err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		return decodeAPIError(response.StatusCode, body)
	}

	if out == nil {
		return nil
	}
	return unwrap(method, path, body, out)
}

// unwrap 解开响应外壳。
//
// ★实测事实（2026-07-30，推翻了"全站统一信封"的假设）：
// 同一个 portal 上两种形状并存 ——
//   - 住宅面端点（/resources/vpn/*）：{"success":true,"data":{...}}
//   - /auth/login：**裸结构**，顶层直接是 access_token，没有 success/data
//
// 与记忆里 [V3响应信封不统一] 一致（BFF={success,data}，其余裸结构）。
// 所以不能只认一种：只认信封会把登录成功读成失败（实测踩到），
// 只认裸结构则会漏掉住宅面的 success=false 业务失败。
func unwrap(method, path string, body []byte, out any) error {
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("%s %s 响应不是 JSON: %w", method, path, err)
	}
	// 有 data 键才按信封处理；没有就是裸结构，整个 body 就是 data。
	if len(env.Data) == 0 {
		// 🔴 但"有 success:false 却没有 data"必须当错误 ——
		// 否则会把一个失败响应硬塞进结构体，得到一堆零值当成功。
		if !env.Success && len(env.Error) > 0 {
			return decodeAPIError(http.StatusOK, body)
		}
		return json.Unmarshal(body, out)
	}
	// 住宅面端点即使 HTTP 200 也可能 success=false（业务失败在 data.error）。
	if !env.Success {
		return decodeAPIError(http.StatusOK, body)
	}
	return json.Unmarshal(env.Data, out)
}

// loginResponse 是 /auth/login 的 data。
type loginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// Login 用密码登录。
//
// ★必须带 device 块，缺了报 400（契约 §4.1 未强调，实测发现）。
// 🔴 password 只在这一次请求体里出现，不写日志、不写磁盘、不进上报。
func (c *PortalClient) Login(ctx context.Context, password string) error {
	if password == "" {
		return fmt.Errorf("探测账号密码为空（应由环境变量 %s 提供）", c.account.PasswordEnv)
	}
	requestBody := map[string]any{
		"email":    c.account.Email,
		"password": password,
		"device": map[string]string{
			"device_id":   c.account.DeviceID,
			"device_type": "desktop",
			"device_name": "otun probe",
		},
	}
	var data loginResponse
	if err := c.do(ctx, http.MethodPost, pathLogin, requestBody, &data, false); err != nil {
		return fmt.Errorf("登录失败: %w", err)
	}
	if data.AccessToken == "" {
		return fmt.Errorf("登录响应缺 access_token")
	}
	c.accessToken = data.AccessToken
	c.refreshToken = data.RefreshToken
	c.setExpiry(data.ExpiresIn)
	return nil
}

// setExpiry 记录 token 到期时刻，留 60s 余量提前刷新。
// 探测一轮可能跑十几分钟，中途 401 会把整轮结果变成一堆假故障。
func (c *PortalClient) setExpiry(expiresIn int) {
	if expiresIn <= 0 {
		expiresIn = 3600
	}
	c.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second).Add(-60 * time.Second)
}

// ensureToken 在 token 即将过期时用 refresh_token 续期。
// 有 refresh_token 意味着长驻探针不必把密码留在内存里反复用。
func (c *PortalClient) ensureToken(ctx context.Context) error {
	if c.accessToken == "" {
		return fmt.Errorf("尚未登录")
	}
	if time.Now().Before(c.tokenExpiry) {
		return nil
	}
	if c.refreshToken == "" {
		return nil // 无法刷新时照旧用手上的 token，让服务端决定是否 401
	}
	var data loginResponse
	err := c.do(ctx, http.MethodPost, pathRefresh,
		map[string]string{"refresh_token": c.refreshToken}, &data, false)
	if err != nil {
		// 刷新失败不致命：手上的 token 可能还能用一会儿。
		// 🔴 但不要在这里回落到密码登录 —— 密码不该在轮询路径上反复出现。
		return nil
	}
	if data.AccessToken != "" {
		c.accessToken = data.AccessToken
		if data.RefreshToken != "" {
			c.refreshToken = data.RefreshToken
		}
		c.setExpiry(data.ExpiresIn)
	}
	return nil
}

// Egresses 拉节点全量。
//
// ★这一条是"扩展到多少节点都自动获取"的支点：egresses[] 是节点级全量枚举，
// 新增节点自动出现，探针零改动。手工维护 targets 的时代到此结束。
func (c *PortalClient) Egresses(ctx context.Context) ([]Egress, error) {
	var data struct {
		Egresses []Egress `json:"egresses"`
	}
	if err := c.do(ctx, http.MethodGet, pathRegions, nil, &data, true); err != nil {
		return nil, fmt.Errorf("拉节点列表失败: %w", err)
	}
	return data.Egresses, nil
}

// Countries 拉国家级授权状态。
func (c *PortalClient) Countries(ctx context.Context) ([]Country, error) {
	var data struct {
		Countries []Country `json:"countries"`
	}
	if err := c.do(ctx, http.MethodGet, pathCountries, nil, &data, true); err != nil {
		return nil, fmt.Errorf("拉国家列表失败: %w", err)
	}
	return data.Countries, nil
}

// SelectCountry 准入某国 —— 把"没权限"从人工待办变成探针自己解决的一步。
//
// 🔴 只对探测账号调。绝不用真实用户 uuid 验证：这个接口会真实改动 assignment
// （有踩坑记录）。
//
// ★K=50（生产实测，契约文档写的 K≤3 已过时）→ 多国累积，不是互换。
// 准入一国不动其他国家的行，所以补 US 不会把 CA 顶掉。
func (c *PortalClient) SelectCountry(ctx context.Context, country string) (ConnectURLs, error) {
	var data ConnectURLs
	err := c.do(ctx, http.MethodPost, pathSelectCountry,
		map[string]string{"country": country}, &data, true)
	if err != nil {
		return data, fmt.Errorf("准入 %s 失败: %w", country, err)
	}
	return data, nil
}

// WaitReady 走切换确认握手（端点 67a），等凭证真的下发到节点。
//
// 🔴 这一步不能省 —— 实测踩过：准入返回成功后立刻拨测，6 个节点全
// auth_failure 404，看起来像"节点全坏了"，实际只是凭证还在下发路上（9 秒后全通）。
// 不等就会把自己造的时序问题记成节点故障，正是本轮要消灭的那类假象。
//
// ready 缺失（字段没下发）视为已就绪：集内切换通常直接 ready:true，
// 老版本后端也可能不发这个字段，此时不该无谓地卡 35 秒。
func (c *PortalClient) WaitReady(ctx context.Context, egressID string, ready *bool) error {
	if ready == nil || *ready {
		return nil
	}
	if egressID == "" {
		// 没有落点 id 就无法轮询。退回固定等待总比立刻拨测好 ——
		// 立刻拨测的失败会被记成节点故障。
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
		return nil
	}

	deadline := time.Now().Add(readyPollTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(readyPollInterval):
		}
		var status struct {
			Ready    bool   `json:"ready"`
			EgressID string `json:"egress_id"`
		}
		err := c.do(ctx, http.MethodGet,
			pathRegionStatus+"?egress_id="+url.QueryEscape(egressID), nil, &status, true)
		if err != nil {
			// 404 no_assignment 是"还没建好"，继续等；其余错误也不致命 ——
			// 等到超时后照常拨测，让真实往返给出结论。
			continue
		}
		if status.Ready {
			return nil
		}
	}
	// 🔴 超时不报错：契约说到点后端可能已回滚。照常拨测，由真实往返定性，
	// 而不是在这里替节点下"坏了"的结论。
	return nil
}

// ConnectURLs 拉当前授权集的连接串。
func (c *PortalClient) ConnectURLs(ctx context.Context) (ConnectURLs, error) {
	var data ConnectURLs
	if err := c.do(ctx, http.MethodGet, pathConnectURL, nil, &data, true); err != nil {
		return data, fmt.Errorf("拉连接串失败: %w", err)
	}
	return data, nil
}

// ---------------------------------------------------------------------------
// 连接串解析
// ---------------------------------------------------------------------------

// RealmURL 是一条 -realm 连接串解析后的形态。
//
// 实测形态（脱敏）：
//
//	hysteria2-realm://<UUID>@13.214.21.114:9443/realm?insecure=1&obfs=...
//	    &realm_id=egress-ca-01-hy2&sni=iptv.local&token=...
//
// 🔴 URL 里的 host:port（13.214.21.114:9443）是**会合面地址，不是节点直连地址**。
// 拿它当 outbound.server 会连错东西 —— 这是设计稿 §4 明确警告的坑。
type RealmURL struct {
	Scheme   string // 如 hysteria2-realm
	Protocol string // 归一化后的协议名，如 hysteria2
	UUID     string // userinfo，各协议共用的凭证
	// RendezvousURL 是会合面地址（https://host:port），填 realm.server_url。
	RendezvousURL string
	RealmID       string // realm.realm_id，决定连到节点的哪个协议面
	Token         string
	SNI           string
	Obfs          string
	Insecure      bool
	// RealityPublicKey ★API 直接给了公钥 —— 探针不必再从节点私钥推导。
	// fetch-credentials.sh 的核心存在理由（X25519 推导）就是这样消失的。
	RealityPublicKey string
	RealityShortID   string
	// RealityServerName 是 reality 内层借壳 SNI（如 www.apple.com），
	// 🔴 与外层 wrap TLS 的 SNI（上面的 SNI 字段，如 iptv.local）**不是一回事**。
	// reality 是双层 TLS：外层 wrap 用 SNI，内层 reality 用这个。混用必挂。
	RealityServerName string
	// SSMethod / SSPassword 是 shadowsocks 专属：method 是节点级 AEAD 算法，
	// password 是 per-user（下发缺省时贯穿 uuid，见 realm_handler.buildProtoConnectURL）。
	SSMethod   string
	SSPassword string
	// Password 目前只有 tuic 用（tuic 要 uuid + password 两件）。
	Password string
	// CongestionControl 是 tuic 的拥塞控制算法（下发可缺省）。
	CongestionControl string
	// Security / AlterID 是 vmess 专属。
	Security string
	AlterID  string
	// STUNServers 不来自 URL（URL 里没有），而来自 smart_strategy.default_stun。
	// 🔴 缺了它内核会报 "no STUN servers resolved" 卡在 stun 阶段 ——
	// 客户端化改造时正是漏了这一项导致 ca-01 从 ok 变成 fail_stage=stun（实测踩到）。
	STUNServers []string
	// UpMbps/DownMbps 来自 smart_strategy（不在连接串里），hy2 的 BBR 依赖它们。
	// 0 表示下发里没有 → 由 BuildProbeConfig 退回默认值，不写 0
	// （写 0 会让 hy2 的拥塞控制拿到一个荒谬的带宽声明）。
	UpMbps   int
	DownMbps int
	// ExitCountry 是该出口所在国（块级 country，非节点短名推导）。
	// 🔴 用途是选往返目标：CN 落地节点必须用国内目标量，否则永远 0%
	// 而节点毫无问题（见 roundTripURLFor）。
	// 只认 regions[].country / smart_strategy.exit_country 这类硬证据 ——
	// nj 是 New Jersey 不是南京，绝不从短名推。
	ExitCountry string
	Query       url.Values
}

// schemeProtocol 把 URL scheme 归一化成探针内部协议名。
//
// ⚠️ 住宅面六协议的 scheme 全带 -realm 后缀（前端强制过滤不带 -realm 的 scheme，
// 所以后端只能都发 -realm）。ss-realm 对应内部的 shadowsocks。
var schemeProtocol = map[string]string{
	"hysteria2-realm": "hysteria2",
	"reality-realm":   "reality",
	"tuic-realm":      "tuic",
	"trojan-realm":    "trojan",
	"ss-realm":        "shadowsocks",
	"vmess-realm":     "vmess",
}

// ParseRealmURL 解析一条 -realm 连接串。
func ParseRealmURL(raw string) (RealmURL, error) {
	var parsed RealmURL
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return parsed, fmt.Errorf("连接串无法解析: %w", err)
	}
	protocol, known := schemeProtocol[target.Scheme]
	if !known {
		return parsed, fmt.Errorf("未知 scheme %q", target.Scheme)
	}
	if target.Host == "" {
		return parsed, fmt.Errorf("连接串缺 host（scheme=%s）", target.Scheme)
	}

	query := target.Query()
	parsed = RealmURL{
		Scheme:   target.Scheme,
		Protocol: protocol,
		UUID:     target.User.Username(),
		// 会合面用 https（自签，靠 insecure）。见 [realm连自签会合面x509失败]。
		RendezvousURL:    "https://" + target.Host,
		RealmID:          query.Get("realm_id"),
		Token:            query.Get("token"),
		SNI:              query.Get("sni"),
		Obfs:             query.Get("obfs"),
		Insecure:         query.Get("insecure") == "1" || query.Get("insecure") == "true",
		RealityPublicKey: query.Get("reality_public_key"),
		RealityShortID:   query.Get("reality_short_id"),
		// ★字段名与下发端 realm_handler.buildProtoConnectURL 一一对应，
		// 那里是唯一真源；改名要两边同步（跨仓契约，别只改一边）。
		RealityServerName: query.Get("reality_server_name"),
		SSMethod:          query.Get("method"),
		SSPassword:        query.Get("ss_password"),
		Password:          query.Get("password"),
		CongestionControl: query.Get("congestion_control"),
		Security:          query.Get("security"),
		AlterID:           query.Get("alter_id"),
		Query:             query,
	}
	if parsed.UUID == "" {
		return parsed, fmt.Errorf("连接串缺 uuid（scheme=%s）", target.Scheme)
	}
	if parsed.RealmID == "" {
		return parsed, fmt.Errorf("连接串缺 realm_id（scheme=%s）", target.Scheme)
	}
	return parsed, nil
}

// egressIDFromRealmID 从 realm_id 反推 egress_id：realm_id = <egress_id>-<proto短名>。
//
// ⚠️ 这个反推只在同一节点上成立，且依赖 protoShort 那张三仓各写一遍的映射表。
// 更可靠的来源是 nodes[].egress_id 与 URL 的对应关系（见 collectRealmURLs），
// 本函数只作为该对应关系缺失时的兜底。
//
// 🔴 realm_id 与 egress_id 可以不同（如 egress_id realm-cn-01 → realm_id iptv-cn-01），
// 契约明确禁止解析命名推断区域。这里只用它做**同节点内的后缀剥离**，不推地理。
func egressIDFromRealmID(realmID, protocol string) string {
	suffix := "-" + protoShort(protocol)
	return strings.TrimSuffix(realmID, suffix)
}

// NodeURLs 把一个节点上的连接串按协议归拢。
type NodeURLs struct {
	EgressID string
	Country  string
	Role     string
	ByProto  map[string]RealmURL
}

// collectRealmURLs 把 connect-url / select-country 的响应整理成「节点 → 协议 → 连接串」。
//
// ★只从 regions[] 区域包内部取：块级 country 是区域判断的唯一可靠依据（§7.3.1），
// 且同块内节点物理上必属该国。顶层 nodes[]/protocols[] 历史上是跨国平铺，
// 拿它判断国家会把 A 国节点当成 B 国的（契约明确警告）。
//
// 顶层 connect_urls[] 只在 regions[] 整个缺失时兜底 —— 此时国家标为空，
// 由调用方决定是否使用（不猜国家，见 [节点短名禁止望文生义推地理]）。
func collectRealmURLs(payload ConnectURLs) []NodeURLs {
	byEgress := map[string]*NodeURLs{}
	order := []string{}

	ensure := func(egressID, country, role string) *NodeURLs {
		existing, present := byEgress[egressID]
		if !present {
			existing = &NodeURLs{
				EgressID: egressID,
				Country:  country,
				Role:     role,
				ByProto:  map[string]RealmURL{},
			}
			byEgress[egressID] = existing
			order = append(order, egressID)
			return existing
		}
		// 国家一旦从区域包拿到就不再被空值覆盖。
		if existing.Country == "" {
			existing.Country = country
		}
		return existing
	}

	// STUN 服务器不在连接串里，只在 smart_strategy 里 —— 顶层那份作为兜底。
	globalSTUN := payload.SmartStrategy.STUNServers()

	for _, region := range payload.Regions {
		// 块内策略优先：跨国时全局那份未必适用于本国节点。
		regionSTUN := region.SmartStrategy.STUNServers()
		if len(regionSTUN) == 0 {
			regionSTUN = globalSTUN
		}
		// 带宽同理块内优先。实测六区域当前都是 20/20，但不赌它永远一致 ——
		// 各国带宽档本来就可能不同（CN 档曾只有 10Mbps）。
		upMbps, downMbps := region.SmartStrategy.UpMbps, region.SmartStrategy.DownMbps
		if upMbps == 0 {
			upMbps = payload.SmartStrategy.UpMbps
		}
		if downMbps == 0 {
			downMbps = payload.SmartStrategy.DownMbps
		}
		// 块内 role → egress_id，用于把 protocols[].node 映射回具体节点。
		// 契约允许退化形态：只有 1 个节点、甚至唯一节点是 backup（生产实测存在），
		// 都要照常使用，不能因"没 primary"就拒绝。
		egressByRole := map[string]string{}
		for _, node := range region.Nodes {
			egressByRole[node.Role] = node.EgressID
			ensure(node.EgressID, region.Country, node.Role)
		}
		for _, protocol := range region.Protocols {
			parsed, err := ParseRealmURL(protocol.URL)
			if err != nil {
				continue
			}
			egressID, mapped := egressByRole[protocol.Node]
			if !mapped {
				// role 对不上时退回 realm_id 剥后缀。宁可少一个映射也不猜国家。
				egressID = egressIDFromRealmID(parsed.RealmID, parsed.Protocol)
			}
			if egressID == "" {
				continue
			}
			parsed.STUNServers = regionSTUN
			parsed.UpMbps, parsed.DownMbps = upMbps, downMbps
			// 出口国取块级 country（同国硬保证：块内节点必属该国）。
			parsed.ExitCountry = region.Country
			entry := ensure(egressID, region.Country, protocol.Node)
			entry.ByProto[parsed.Protocol] = parsed
		}
	}

	// regions[] 缺失时才看顶层 —— 国家未知，留空由调用方处理。
	if len(byEgress) == 0 {
		for _, raw := range payload.ConnectURLs {
			parsed, err := ParseRealmURL(raw)
			if err != nil {
				continue
			}
			egressID := egressIDFromRealmID(parsed.RealmID, parsed.Protocol)
			if egressID == "" {
				continue
			}
			parsed.STUNServers = globalSTUN
			entry := ensure(egressID, "", "")
			entry.ByProto[parsed.Protocol] = parsed
		}
	}

	result := make([]NodeURLs, 0, len(order))
	for _, egressID := range order {
		result = append(result, *byEgress[egressID])
	}
	return result
}

// protoShort 把协议名映射成 realm_id 后缀（内联自 prober/config.go，避免跨包依赖）。
func protoShort(protocol string) string {
	switch protocol {
	case "hysteria2":
		return "hy2"
	case "shadowsocks":
		return "ss"
	default:
		return protocol
	}
}

// tailLines 取文本末 count 行（内联自 prober/main.go，用于 apiError 摘要）。
func tailLines(text string, count int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > count {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, "\n")
}

// FetchAllTargets 是探针取数的一站式高层入口:登录 → 拉国家授权状态 → 对每个
// 在线国按需准入(select-country)+ 等 ready 握手 → 拉连接串 → 整理成
// 「节点 × 协议」。返回可直接喂给内核 RunProbe 的 NodeURLs 列表。
//
// 与 Linux prober 的 plan.go 同流程,浓缩成一个方法供 Android/内核复用:
//   - autoAdmit=true 时对未授权国调 select-country(会真实改探测账号 assignment,
//     只对探测账号安全);false 则只测已授权国。
//   - 每次 select-country 后走 WaitReady(端点 67a),避免凭证未下发就拨测的假 404。
//   - STUN 从 smart_strategy 取(不在连接串里),已在 collectRealmURLs 内处理。
//
// password 由调用方(壳/入口)从安全来源取,不落盘不进日志。
func (c *PortalClient) FetchAllTargets(ctx context.Context, password string, autoAdmit bool) ([]NodeURLs, error) {
	if err := c.Login(ctx, password); err != nil {
		return nil, err
	}
	countries, err := c.Countries(ctx)
	if err != nil {
		return nil, err
	}
	// 对每个「有在线节点但未在授权集」的国准入(autoAdmit)。已授权国无需动。
	if autoAdmit {
		for _, country := range countries {
			if country.OnlineNodeCount == 0 || country.InAuthorizedSet {
				continue
			}
			payload, selErr := c.SelectCountry(ctx, country.Country)
			if selErr != nil {
				// 准入失败(如限流)不致命:跳过该国,继续其余。真实往返会给出结论。
				continue
			}
			// 等凭证下发到节点(端点 67a),否则立刻拉串拨测会假 404。
			_ = c.WaitReady(ctx, payload.EgressID, payload.Ready)
		}
	}
	// 拉当前授权集的全部连接串,整理成节点×协议。
	payload, err := c.ConnectURLs(ctx)
	if err != nil {
		return nil, err
	}
	return collectRealmURLs(payload), nil
}
