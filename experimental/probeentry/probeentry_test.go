package probeentry_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/experimental/probeentry"
	"github.com/sagernet/sing-box/protocol/realmtest"

	trojannode "github.com/antsbtw/otun-s/node/trojannode"
)

// 分层验证第 1 步(HANDOFF_PROBE_ENTRY_AND_SHELL §4):在 loopback 测试台上跑通
// RunProbe(binder=nil),证明「入口层拼装 → 建隧道 → 经隧道真实往返判据」这条链
// 在没有真节点、没有安卓的情况下就能断言。真机绑定验证是第 2 步,不在此。
//
// judge 用 loopback HTTP 200 server:隧道把流量代理到它,RunProbe 应判 success。
// 与生产判据(youtube 200)同型,只是把「公网 youtube」换成「本地可控 200」,
// 使这条断言不依赖外网、可复现。

// httpTarget 起一个 loopback HTTP 服务,返回其 http://ip:port/ 与地址。
func httpTarget(t *testing.T) (url string, addr *net.TCPAddr) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	tcpAddr, err := net.ResolveTCPAddr("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return srv.URL, tcpAddr
}

// TestRunProbeTrojanNormalSuccess 是入口层的黄金路径:trojan/normal 建隧道 +
// 经隧道对 loopback 200 判据 → Success=true、TunnelEstablished=true。
func TestRunProbeTrojanNormalSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network integration test in -short")
	}
	const token = "probe-trojan-token"
	const realmID = "probe-trojan"
	const password = "013c633f-5b28-4386-9051-ad342a9c3e57" // 探针测试 uuid（trojan 密码=uuid）

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	judgeURL, _ := httpTarget(t)
	stun := realmtest.STUN(t)
	rvURL, engine := realmtest.Rendezvous(t, token)
	certPEM, keyPEM := realmtest.SelfSignedCert(t, "iptv.local")

	node, err := trojannode.New(trojannode.Options{
		ServerURL: rvURL, Token: token, RealmID: realmID,
		STUNServers: []string{stun.String()}, Resolver: realmtest.Resolver,
		HTTPClient: &http.Client{},
		WrapTLS:    realmtest.NodeServerTLS(t, ctx, certPEM, keyPEM),
		Password:   password,
		Handler:    realmtest.EgressHandler, // 把隧道流量转发到客户端请求的目的地(= judge server)
		Logger:     realmtest.Logger(),
	})
	if err != nil {
		t.Fatalf("new trojannode: %v", err)
	}
	nodeUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Start(ctx, nodeUDP); err != nil {
		t.Fatalf("node start: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	realmtest.WaitRegistered(t, engine, realmID, 8*time.Second)

	spec := &probeentry.Spec{
		Protocol: "trojan", RealmID: realmID, ServerURL: rvURL, Token: token,
		UUID: password, STUN: []string{stun.String()}, SNI: "iptv.local", Insecure: true,
		Path: probeentry.PathNormal, JudgeURL: judgeURL, TimeoutMS: 20000,
	}
	res := probeentry.RunProbe(ctx, spec, nil)

	if !res.TunnelEstablished {
		t.Fatalf("tunnel must establish; got err=%q fail_stage=%q", res.Err, res.FailStage)
	}
	if !res.Success {
		t.Fatalf("judge over tunnel must succeed (200); got status=%d err=%q", res.JudgeStatus, res.Err)
	}
	if res.JudgeStatus != http.StatusOK {
		t.Errorf("want judge status 200, got %d", res.JudgeStatus)
	}
	if res.Trace == nil {
		t.Errorf("probe must return a realm trace")
	}
}

// TestRunProbeUnsupportedProtocol：未知协议在入口层就失败,不 panic、不空返回。
func TestRunProbeUnsupportedProtocol(t *testing.T) {
	res := probeentry.RunProbe(context.Background(), &probeentry.Spec{
		Protocol: "wireguard", RealmID: "x", ServerURL: "http://127.0.0.1:1", Token: "t",
		STUN: []string{"127.0.0.1:1"}, TimeoutMS: 2000,
	}, nil)
	if res.Success || res.TunnelEstablished {
		t.Fatal("unsupported protocol must not succeed")
	}
	if res.Err == "" {
		t.Fatal("unsupported protocol must report an error")
	}
}

// TestRunProbeHy2ForcePathRejected：hy2 的 punch_only/relay_only 首期显式拒绝,
// 不静默当 normal 跑(避免假样本)。
func TestRunProbeHy2ForcePathRejected(t *testing.T) {
	for _, p := range []probeentry.Path{probeentry.PathPunchOnly, probeentry.PathRelayOnly} {
		res := probeentry.RunProbe(context.Background(), &probeentry.Spec{
			Protocol: "hysteria2", RealmID: "x", ServerURL: "http://127.0.0.1:1", Token: "t",
			STUN: []string{"127.0.0.1:1"}, Path: p, TimeoutMS: 2000,
		}, nil)
		if res.Success || res.TunnelEstablished {
			t.Fatalf("path %s: hy2 force-path must not succeed", p)
		}
		if res.Err == "" {
			t.Fatalf("path %s: hy2 force-path must report unsupported", p)
		}
	}
}

// TestRunProbeJSONRoundTrip：JSON 入口坏 spec 也包成 Result 返回,壳侧只解析一种结构。
func TestRunProbeJSONRoundTrip(t *testing.T) {
	out := probeentry.RunProbeJSON("{ not json", nil)
	if out == "" || out[0] != '{' {
		t.Fatalf("must return a JSON Result even on parse error, got %q", out)
	}
	fmt.Sscanf(out, "%s", new(string)) // 仅确保非空字符串,内容断言留给壳
}
