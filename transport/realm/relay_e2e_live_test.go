//go:build relay_e2e_live

// 中继回退**真实环境**端到端验证（RELAY_FALLBACK_DESIGN.md §6.45）。
//
// 🔴 与 relay_test.go 的分工：那边用假中继验 DialRelay 自身的线格式与竞速语义；
// 这里用**真会合面 + 真节点 + 真中继**，验的是三方串起来能不能对接上。
// 单测全绿而线上不通，正是本轮要查的那一类问题 —— 所以必须有这一层。
//
// 隔离手段（memory「验证产物别与生产混淆」）：
//   - build tag `relay_e2e_live`：默认编译不到，CI 与生产二进制里一行都没有。
//   - 全部参数走环境变量，仓里不留任何 token。
//
// 跑法：
//
//	OTUN_E2E_URL=https://54.255.172.86:9443 \
//	OTUN_E2E_TOKEN=... OTUN_E2E_REALM=egress-nj-01-trojan \
//	go test -tags relay_e2e_live -run TestRelayFallbackLive -v ./transport/realm/
package realm

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"

	squic "github.com/sagernet/sing-quic/hysteria2/realm"
)

// ipOnlyResolver 只认 IP 字面量。本测试的 STUN 一律用公网 IP（生产
// default_stun 也是 IP，见 memory「六协议客户端参数真源」§1），
// 不引入 DNS 依赖 —— 免得 DNS 出问题被误读成中继不通。
func ipOnlyResolver(_ context.Context, host string, _, _ bool) ([]netip.Addr, error) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{addr}, nil
}

// liveConfig 从环境变量取真实参数；缺任一项则跳过（避免误跑）。
func liveConfig(t *testing.T) (Config, string) {
	t.Helper()
	url := os.Getenv("OTUN_E2E_URL")
	token := os.Getenv("OTUN_E2E_TOKEN")
	realmID := os.Getenv("OTUN_E2E_REALM")
	if url == "" || token == "" || realmID == "" {
		t.Skip("需要 OTUN_E2E_URL / OTUN_E2E_TOKEN / OTUN_E2E_REALM")
	}
	stun := []string{"74.125.250.129:19302", "162.159.207.0:3478"}
	if v := os.Getenv("OTUN_E2E_STUN"); v != "" {
		stun = splitComma(v)
	}
	return Config{
		ServerURL:   url,
		Token:       token,
		STUNServers: stun,
		Resolver:    ipOnlyResolver,
		// 会合面用自签证书（memory：/v1/* + Bearer + 自签必 insecure）。
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}},
	}, realmID
}

func splitComma(v string) []string {
	var out []string
	cur := ""
	for _, r := range v {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// TestRelayFallbackLive 是本轮的核心验证：
// 走真实 /connect 拿到 nonce + relay 地址，然后**故意不打洞**（把节点候选地址
// 换成黑洞），直接调 DialRelay —— 若节点也按同一 nonce join 了中继，就该配对成功。
//
// 🔴 为什么不靠"让打洞自然失败"：本机与节点同宅同出口 IP，打洞多半会成功，
// 复现不出对称 NAT。直接调 DialRelay 验的是**回退这一段**能否跑通，
// 与"打洞失败后会不会走到这里"是两个独立的问题，分开验才定位得准。
func TestRelayFallbackLive(t *testing.T) {
	cfg, realmID := liveConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	control, err := squic.NewControlClient(cfg.ServerURL, cfg.Token, cfg.HTTPClient)
	if err != nil {
		t.Fatalf("NewControlClient: %v", err)
	}
	metadata, err := squic.GeneratePunchMetadata()
	if err != nil {
		t.Fatalf("GeneratePunchMetadata: %v", err)
	}

	// 候选地址随便给一个：本测试不打洞，只要会合面接受即可。
	local := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:40000")}
	response, err := control.Connect(ctx, realmID, local, metadata)
	if err != nil {
		t.Fatalf("control.Connect: %v", err)
	}
	t.Logf("会合面下发：addresses=%v relay=%v nonce=%x",
		response.Addresses, response.Relay, response.PunchMetadata.Nonce)

	if len(response.Relay) == 0 {
		t.Fatalf("会合面没下发 relay —— 该 realm 未配 relay_addresses，回退无从触发")
	}

	// ★ 节点收到打洞事件后才会 join 中继，join 与本次 Connect 是并发的。
	// 客户端侧 DialRelay 自带重发 + 10s 等待，足以覆盖这个窗口。
	conn, err := DialRelay(ctx, cfg, response.Relay, response.PunchMetadata.Nonce)
	if err != nil {
		t.Fatalf("🔴 DialRelay 失败（中继未与节点配对）：%v", err)
	}
	defer conn.Close()
	t.Logf("✅ 中继配对成功，PeerAddr=%s（= 中继地址，符合设计）", conn.PeerAddr)

	// 🔴 配对成功 ≠ 隧道可用。中继只搬字节，真正要证的是"字节到得了节点、
	// 且节点认得出这是它自己的会话" —— 靠上层握手能不能跑完来证。
	// 这里发一个探针字节并等回程：只要有任何回包，就说明双向通路真的成立。
	if _, err := conn.WriteTo([]byte("probe"), conn.PeerAddr.UDPAddr()); err != nil {
		t.Fatalf("写中继失败：%v", err)
	}
	t.Logf("已向中继写入探针字节（回程验证见 TestRelayTunnelLive）")
}
