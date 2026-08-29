package realm

// probe_trace.go —— 探测专用埋点
//
// 目的：把「连不上」拆成内核可定位的阶段，产出 fail_stage / 各阶段耗时 /
// 打洞细节，供连通性探测网聚合分析。见
// document/realm/CONNECTIVITY_PROBE_MESH_IMPL.md §2。
//
// ★ 来源：本文件搬自旧探针内核 antsbtw/sing-box probe 分支的
// third_party/sing-quic/hysteria2/realm/probe_trace.go（commit 1d606d93，纯新增），
// 逐字节复制，只把原本包内可见的 PunchResult/PunchHello/PunchAck 加上 squic. 限定
// —— 在那边它与 squic 同包，搬到 kernel 后成了外部类型。
//
// ★ 为什么落在 kernel 的 transport/realm 而不是 squic（决策 D3-A，2026-07-30）：
// 阶段一归位后五协议的打洞编排已在本仓（Punch 的三段全在这里），埋点无需碰 squic。
// 🔴 代价是 hy2 拿不到阶段数据 —— hy2 的编排在 squic/hysteria2/client.go
// offerNewRealm 里，kernel 一行都插不进去，要埋必须 vendored squic + replace，
// 那会把 19245 行 squic 拉进仓、把另外五协议一起放进射程。本轮不做。
//
// 🔴 若将来要补 hy2（D3-B），Trace 必须搬进 squic，不能留在这里：
// squic 不 import sing-box（实测），Trace 留在 kernel 会形成 import 环
// (sing-box → squic → sing-box)。这一条推翻了阶段一设计稿 §5.1
// 「Trace 定义在 kernel 里，两条路径共用同一个 Trace」的说法。
//
// 设计约束：
//   - 埋点是旁路的。Trace 为 nil 时所有方法是 no-op，生产路径行为不变。
//   - 只记录，不改变任何控制流与返回值。
//   - 记录的是「事实」（哪一步、耗时多少、匹配到哪个候选），不做结论推断。

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sync"
	"time"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// FailStage 标识一次连接尝试卡在哪一阶段。空值表示未失败。
type FailStage string

const (
	FailStageSTUN       FailStage = "stun"
	FailStageRendezvous FailStage = "rendezvous"
	FailStageCandidate  FailStage = "candidate"
	FailStagePunch      FailStage = "punch"
	FailStageHandshake  FailStage = "handshake"
	FailStageFirstByte  FailStage = "first_byte"
)

// NATTypeGuess 由多个 STUN 反射地址是否一致推断，仅为线索非结论。
type NATTypeGuess string

const (
	NATTypeUnknown   NATTypeGuess = "unknown"
	NATTypeCone      NATTypeGuess = "cone"
	NATTypeSymmetric NATTypeGuess = "symmetric"
)

// PunchDetail 是打洞阶段的细节，用于回答「成功时靠哪条路径成功」。
type PunchDetail struct {
	STUNServerUsed  []string     `json:"stun_server_used,omitempty"`
	LocalSrflx      []string     `json:"local_srflx,omitempty"`
	NATTypeGuess    NATTypeGuess `json:"nat_type_guess,omitempty"`
	PeerCandidates  []string     `json:"peer_candidates,omitempty"`
	CandidateCount  int          `json:"candidate_count"`
	CandidatePairs  []string     `json:"candidate_pairs,omitempty"`
	HelloSentCount  int          `json:"hello_sent_count"`
	HelloSentTS     []int64      `json:"hello_sent_ts,omitempty"`
	FirstRecvType   string       `json:"first_recv_type,omitempty"`
	PeerAddrMatched string       `json:"peer_addr_matched,omitempty"`
	WinnerFamily    string       `json:"winner_family,omitempty"`
	Mode            string       `json:"mode,omitempty"`
}

// Stages 是各阶段耗时（毫秒）。未到达的阶段为 nil，与「到达了但耗时 0」区分。
type Stages struct {
	STUNMs       *int64 `json:"stun_ms,omitempty"`
	RendezvousMs *int64 `json:"rendezvous_ms,omitempty"`
	PunchMs      *int64 `json:"punch_ms,omitempty"`
	HandshakeMs  *int64 `json:"handshake_ms,omitempty"`
	FirstByteMs  *int64 `json:"first_byte_ms,omitempty"`
	TotalMs      *int64 `json:"total_ms,omitempty"`
}

// Trace 收集一次 realm 连接尝试的全过程。并发安全：punch 阶段多个 family 并发写。
//
// 🔴 ok 字段刻意不在内核侧设置为 true —— 内核只能证明「隧道建立了」，
// 不能证明「隧道可用」。ok=true 必须由 prober 依据真实往返（HTTP 204）判定。
// 见 IMPL §3.3.d，以及遥测假 success 的教训。
type Trace struct {
	access sync.Mutex

	RealmID  string `json:"realm_id,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	// Nonce 是本次打洞的 16 字节 nonce（hex）——★双端 join 键。
	//
	// 接收端（egress）从收到的打洞包里解出同一个 nonce 并写进 punch_trace_egress，
	// 两端靠它配对，才能算出 H1 的差集（发起端判成功 vs 接收端确实收到并回了 Ack）。
	// 没有它，双端数据只能按时间窗猜，配不成对。
	//
	// 🔴 取值必须是**会合面下发的** metadata（ConnectResponse.PunchMetadata），
	// 不是客户端本地 GeneratePunchMetadata 生成的那个——实际打洞包用的是前者，
	// 接收端记的也是前者，用错就永远配不上对。
	Nonce string `json:"nonce,omitempty"`

	TunnelEstablished bool      `json:"tunnel_established"`
	FailStage         FailStage `json:"fail_stage,omitempty"`
	ErrorCode         string    `json:"error_code,omitempty"`
	ErrorMsg          string    `json:"error_msg,omitempty"`

	// Relay* 记录打洞失败后的中继回退（RELAY_FALLBACK_DESIGN.md §3.1）。
	//
	// 🔴 刻意与 FailStage/ErrorMsg **正交**：中继成功时 fail_stage 仍是 punch
	// （打洞确实失败了，这是真实的卡点，分析打洞成功率时必须仍算失败），
	// 只是 relay_used=true 表示这条连接最终由中继救回来了。把两者混在一起会让
	// "打洞成功率"和"连接成功率"两个口径互相污染。
	RelayUsed     bool   `json:"relay_used,omitempty"`
	RelayAddr     string `json:"relay_addr,omitempty"`
	RelayErrorMsg string `json:"relay_error_msg,omitempty"`

	Stages Stages      `json:"stages"`
	Punch  PunchDetail `json:"punch_detail"`

	start      time.Time
	stageStart time.Time
}

// NewTrace 创建一个埋点收集器并开始计时。
func NewTrace(realmID string, protocol string) *Trace {
	now := time.Now()
	return &Trace{
		RealmID:    realmID,
		Protocol:   protocol,
		start:      now,
		stageStart: now,
	}
}

func msSince(t time.Time) *int64 {
	v := time.Since(t).Milliseconds()
	return &v
}

// stageDone 记录当前阶段耗时并把计时锚点推进到下一阶段。
func (t *Trace) stageDone(target **int64) {
	if t == nil {
		return
	}
	*target = msSince(t.stageStart)
	t.stageStart = time.Now()
}

// STUNDone 记录 STUN 发现结果（阶段 [1]）。
func (t *Trace) STUNDone(srflx []netip.AddrPort, serversUsed []string) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.stageDone(&t.Stages.STUNMs)
	t.Punch.STUNServerUsed = serversUsed
	t.Punch.LocalSrflx = addrPortsToStrings(srflx)
	t.Punch.NATTypeGuess = guessNATType(srflx)
}

// RendezvousDone 记录会合面协商结果（阶段 [2]）。
func (t *Trace) RendezvousDone(peerCandidates []netip.AddrPort) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.stageDone(&t.Stages.RendezvousMs)
	t.Punch.PeerCandidates = addrPortsToStrings(peerCandidates)
}

// NonceNegotiated 记录本次打洞的 nonce（双端 join 键）。
//
// 单独一个方法而非并进 RendezvousDone，是因为 nonce 的来源与 peerCandidates 不同：
// 它必须取会合面下发的 metadata，而 RendezvousDone 的既有调用点/测试都只传候选地址。
// 分开加，既不改既有签名，也让"用错 metadata 就配不上对"这件事在调用点显式可见。
func (t *Trace) NonceNegotiated(metadata squic.PunchMetadata) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.Nonce = hex.EncodeToString(metadata.Nonce[:])
}

// CandidatesComputed 记录候选地址计算结果（阶段 [3]）。
func (t *Trace) CandidatesComputed(candidates []netip.AddrPort) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	// 多 family 并发，取候选数最多的一次作为代表。
	if len(candidates) > t.Punch.CandidateCount {
		t.Punch.CandidateCount = len(candidates)
		t.Punch.CandidatePairs = addrPortsToStrings(candidates)
	}
}

// HelloSent 记录一轮 PunchHello 发送（阶段 [4]）—— 用于判断重试间隔是否合理。
func (t *Trace) HelloSent() {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.Punch.HelloSentCount++
	// 上限保护：极端情况下不让埋点自身无限增长。
	if len(t.Punch.HelloSentTS) < 256 {
		t.Punch.HelloSentTS = append(t.Punch.HelloSentTS, time.Since(t.start).Milliseconds())
	}
}

// PunchDone 记录打洞成功（阶段 [5]）：实际打通的是哪个候选、先收到 Hello 还是 Ack。
func (t *Trace) PunchDone(result squic.PunchResult, family string, mode string) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.stageDone(&t.Stages.PunchMs)
	t.Punch.PeerAddrMatched = result.PeerAddr.String()
	t.Punch.FirstRecvType = punchTypeName(result.Type)
	t.Punch.WinnerFamily = family
	t.Punch.Mode = mode
}

// HandshakeDone 记录 QUIC 握手完成（阶段 [6]）。
//
// 注意：握手完成仅代表隧道建立，不代表隧道可用。first_byte 由 prober 侧
// 经隧道真实往返测得，内核给不出可信的 first_byte。
func (t *Trace) HandshakeDone() {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.stageDone(&t.Stages.HandshakeMs)
	t.TunnelEstablished = true
	t.Stages.TotalMs = msSince(t.start)
}

// RelayEstablished 记录打洞失败后经中继救回了这条连接（§3.1）。
//
// 🔴 不动 FailStage：打洞确实失败过，那是真实卡点。relay_used 是**附加**事实，
// 让分析既能看到"打洞成功率"（fail_stage=punch 仍计失败）又能看到"连接成功率"
// （relay_used=true 即最终连上）。两个口径不能互相覆盖。
// relayAddr 取字符串而非 M.Socksaddr：本文件刻意不 import sing 的 metadata
// （见文件头 D3-B 的 import 环约束），埋点存的本就是字符串。
func (t *Trace) RelayEstablished(relayAddr string) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	t.RelayUsed = true
	t.RelayAddr = relayAddr
	t.Stages.TotalMs = msSince(t.start)
}

// RelayFailed 记录中继回退也没救回来（打洞失败 + 中继失败）。
// 同样不动 FailStage/ErrorMsg —— 返回给调用方的仍是打洞原始错误（硬约束）。
func (t *Trace) RelayFailed(err error) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	if err != nil {
		t.RelayErrorMsg = err.Error()
	}
}

// Fail 记录失败阶段与原因。首次记录生效，避免上层包装错误覆盖真实卡点。
func (t *Trace) Fail(stage FailStage, err error) {
	if t == nil {
		return
	}
	t.access.Lock()
	defer t.access.Unlock()
	if t.FailStage != "" {
		return
	}
	t.FailStage = stage
	if err != nil {
		t.ErrorMsg = err.Error()
		t.ErrorCode = classifyError(err)
	}
	t.Stages.TotalMs = msSince(t.start)
}

// MarshalJSON 输出埋点快照。
func (t *Trace) MarshalJSON() ([]byte, error) {
	if t == nil {
		return []byte("null"), nil
	}
	t.access.Lock()
	defer t.access.Unlock()
	// ⚠️ 这是**白名单**：Trace 上加了字段，这里不加就不会出现在输出里
	// （加 Nonce 时踩过，测试抓到）。新增字段务必两处同改。
	type alias struct {
		RealmID           string      `json:"realm_id,omitempty"`
		Protocol          string      `json:"protocol,omitempty"`
		Nonce             string      `json:"nonce,omitempty"`
		TunnelEstablished bool        `json:"tunnel_established"`
		FailStage         FailStage   `json:"fail_stage,omitempty"`
		ErrorCode         string      `json:"error_code,omitempty"`
		ErrorMsg          string      `json:"error_msg,omitempty"`
		RelayUsed         bool        `json:"relay_used,omitempty"`
		RelayAddr         string      `json:"relay_addr,omitempty"`
		RelayErrorMsg     string      `json:"relay_error_msg,omitempty"`
		Stages            Stages      `json:"stages"`
		Punch             PunchDetail `json:"punch_detail"`
	}
	return json.Marshal(alias{
		RealmID:           t.RealmID,
		Protocol:          t.Protocol,
		Nonce:             t.Nonce,
		TunnelEstablished: t.TunnelEstablished,
		FailStage:         t.FailStage,
		ErrorCode:         t.ErrorCode,
		ErrorMsg:          t.ErrorMsg,
		RelayUsed:         t.RelayUsed,
		RelayAddr:         t.RelayAddr,
		RelayErrorMsg:     t.RelayErrorMsg,
		Stages:            t.Stages,
		Punch:             t.Punch,
	})
}

func addrPortsToStrings(addrs []netip.AddrPort) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		out = append(out, addr.String())
	}
	return out
}

func punchTypeName(packetType byte) string {
	switch packetType {
	case squic.PunchHello:
		return "hello"
	case squic.PunchAck:
		return "ack"
	default:
		return ""
	}
}

// guessNATType 由多个 STUN 反射地址推断 NAT 类型：
// 不同 STUN 看到的映射端口不一致 → 对称 NAT 特征。
// 仅一个反射地址时无法判断，返回 unknown。
func guessNATType(srflx []netip.AddrPort) NATTypeGuess {
	if len(srflx) < 2 {
		return NATTypeUnknown
	}
	first := srflx[0]
	for _, addr := range srflx[1:] {
		if addr.Addr() != first.Addr() || addr.Port() != first.Port() {
			return NATTypeSymmetric
		}
	}
	return NATTypeCone
}

// ProbeTraceLogPrefix 是埋点日志行的固定前缀，prober 据此精确提取。
// 取值刻意冗长且唯一，避免与任何正常日志混淆。
const ProbeTraceLogPrefix = "OTUN_PROBE_TRACE_V1"
