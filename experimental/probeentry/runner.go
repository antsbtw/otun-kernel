package probeentry

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/common/netbind"
	sbtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	realmlib "github.com/sagernet/sing-box/transport/realm"

	otunreality "github.com/sagernet/sing-box/overlay/reality"
	otunss "github.com/sagernet/sing-box/overlay/shadowsocks"
	otuntrojan "github.com/sagernet/sing-box/overlay/trojan"
	otuntuic "github.com/sagernet/sing-box/overlay/tuic"
	otunvmess "github.com/sagernet/sing-box/overlay/vmess"

	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// tunnelDialer 是「一条已建立的 realm 隧道」的最小抽象:给个目的地,拿一条
// 代理到该目的地的 net.Conn。五个 overlay 的 Client/Conn 都满足它。
type tunnelDialer interface {
	DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

// RunProbeJSON 是 gomobile 友好的入口:输入/输出都是 JSON 字符串,binder 由
// Android 壳实现(nil 则不绑定,Linux 上跑同一套逻辑)。返回的 JSON 永远是一个
// Result —— 连 specJSON 解析失败也包成 Result 返回,壳侧只需解析一种结构。
func RunProbeJSON(specJSON string, binder Binder) string {
	var spec Spec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		return marshalResult(Result{FailStage: "spec", Err: "parse spec: " + err.Error()})
	}
	return marshalResult(RunProbe(context.Background(), &spec, binder))
}

func marshalResult(r Result) string {
	b, err := json.Marshal(r)
	if err != nil {
		return `{"fail_stage":"internal","err":"marshal result"}`
	}
	return string(b)
}

// RunProbe 执行一次探测:建隧道 → 经隧道对 judge_url 做真实往返 → 出结构化结果。
func RunProbe(ctx context.Context, spec *Spec, binder Binder) Result {
	res := Result{Protocol: spec.Protocol, Path: spec.path()}
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, time.Duration(spec.timeoutMS())*time.Millisecond)
	defer cancel()

	dialer, trace, err := dialTunnel(ctx, spec, binder)
	res.Trace = trace
	if err != nil {
		res.FailStage = traceFailStage(trace)
		res.Err = err.Error()
		res.TotalMS = time.Since(start).Milliseconds()
		return res
	}
	defer dialer.Close()
	res.TunnelEstablished = true

	// 判据:经隧道对 judge_url 做真实 HTTP 往返。只信 2xx。
	status, judgeMS, judgeErr := judgeThroughTunnel(ctx, dialer, spec.judgeURL())
	res.JudgeStatus = status
	res.JudgeMS = judgeMS
	if judgeErr != nil {
		res.FailStage = "judge"
		res.Err = judgeErr.Error()
	} else if status >= 200 && status < 300 {
		res.Success = true
	} else {
		res.FailStage = "judge"
		res.Err = "judge status " + strconv.Itoa(status)
	}
	res.TotalMS = time.Since(start).Milliseconds()
	return res
}

// dialTunnel 建立到 spec 指定 {节点,协议,路径} 的隧道,返回 tunnelDialer 与
// realm trace(埋点开启时非 nil)。hy2 首期不在此(见 dialHysteria2)。
func dialTunnel(ctx context.Context, spec *Spec, binder Binder) (tunnelDialer, *realmlib.Trace, error) {
	nd := netbind.NewDialer(binder)
	realmCfg := realmlib.Config{
		ServerURL:   spec.ServerURL,
		Token:       spec.Token,
		STUNServers: spec.STUN,
		Dialer:      nd,
		HTTPClient:  nd.HTTPClient(spec.RendezvousInsecure),
		Resolver:    nd.Resolver(),
		Logger:      logger.NOP(),
	}
	mode, err := punchMode(spec.path())
	if err != nil {
		return nil, nil, err
	}
	// trace 在探针里总是要:入口自己生成并回填 Result,不依赖进程级 env 开关。
	trace := realmlib.NewTrace(spec.RealmID, spec.Protocol)

	switch spec.Protocol {
	case "trojan":
		wrapTLS, err := wrapClientTLS(ctx, spec)
		if err != nil {
			return nil, trace, err
		}
		c, err := otuntrojan.Dial(ctx, otuntrojan.Options{
			Realm: realmCfg, RealmID: spec.RealmID, WrapTLS: wrapTLS,
			Password: spec.UUID, Mode: mode, Trace: trace,
		})
		return c, trace, err
	case "shadowsocks":
		wrapTLS, err := wrapClientTLS(ctx, spec)
		if err != nil {
			return nil, trace, err
		}
		password := spec.SSPassword
		if password == "" {
			password = spec.UUID
		}
		c, err := otunss.Dial(ctx, otunss.Options{
			Realm: realmCfg, RealmID: spec.RealmID, WrapTLS: wrapTLS,
			Method: spec.Method, Password: password, Mode: mode, Trace: trace,
		})
		return c, trace, err
	case "vmess":
		wrapTLS, err := wrapClientTLS(ctx, spec)
		if err != nil {
			return nil, trace, err
		}
		c, err := otunvmess.Dial(ctx, otunvmess.Options{
			Realm: realmCfg, RealmID: spec.RealmID, WrapTLS: wrapTLS,
			UUID: spec.UUID, Security: "auto", AlterId: 0, Mode: mode, Trace: trace,
		})
		return c, trace, err
	case "tuic":
		tuicTLS, err := clientTLS(ctx, spec.SNI, spec.Insecure, []string{"h3"})
		if err != nil {
			return nil, trace, err
		}
		uid, err := uuid.FromString(spec.UUID)
		if err != nil {
			return nil, trace, fmt.Errorf("tuic uuid: %w", err)
		}
		c, err := otuntuic.Dial(ctx, otuntuic.Options{
			Realm: realmCfg, RealmID: spec.RealmID, TLSConfig: tuicTLS,
			UUID: uid, Password: spec.UUID, CongestionControl: spec.CongestionControl,
			Mode: mode, Trace: trace,
		})
		return c, trace, err
	case "reality":
		wrapTLS, err := wrapClientTLS(ctx, spec)
		if err != nil {
			return nil, trace, err
		}
		realityTLS, err := realityClientTLS(ctx, spec)
		if err != nil {
			return nil, trace, err
		}
		c, err := otunreality.Dial(ctx, otunreality.Options{
			Realm: realmCfg, RealmID: spec.RealmID, WrapTLS: wrapTLS, Reality: realityTLS,
			UUID: spec.UUID, Mode: mode, Trace: trace,
		})
		return c, trace, err
	case "hysteria2":
		return dialHysteria2(ctx, spec, nd, trace)
	default:
		return nil, trace, fmt.Errorf("unsupported protocol %q", spec.Protocol)
	}
}

func punchMode(p Path) (realmlib.PunchMode, error) {
	switch p {
	case PathNormal:
		return realmlib.ModeNormal, nil
	case PathPunchOnly:
		return realmlib.ModePunchOnly, nil
	case PathRelayOnly:
		return realmlib.ModeRelayOnly, nil
	default:
		return realmlib.ModeNormal, fmt.Errorf("unknown path %q", p)
	}
}

// wrapClientTLS builds the OUTER WrapStream/QUIC TLS (server_name = spec.SNI,
// ALPN h3) — the outer transport all five non-hy2 overlays share.
func wrapClientTLS(ctx context.Context, spec *Spec) (sbtls.Config, error) {
	return clientTLS(ctx, spec.SNI, spec.Insecure, []string{"h3"})
}

func clientTLS(ctx context.Context, serverName string, insecure bool, alpn []string) (sbtls.Config, error) {
	if serverName == "" {
		serverName = "iptv.local"
	}
	return sbtls.NewClient(ctx, logger.NOP(), serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure,
		ALPN:       badoption.Listable[string](alpn),
	})
}

// realityClientTLS builds the INNER Reality TLS (借壳 SNI = reality_server_name,
// public_key/short_id from spec). Requires the binary to carry -tags with_utls.
func realityClientTLS(ctx context.Context, spec *Spec) (sbtls.Config, error) {
	serverName := spec.RealityServerName
	if serverName == "" {
		serverName = "www.apple.com"
	}
	return sbtls.NewClient(ctx, logger.NOP(), serverName, option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality: &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: spec.RealityPublicKey,
			ShortID:   spec.RealityShortID,
		},
	})
}

// judgeThroughTunnel opens a proxied conn to judge_url's host, speaks HTTP(S)
// over it, and returns the status code. 🔴 A real round-trip over the tunnel is
// the ONLY trustworthy verdict — the kernel never self-reports "usable".
func judgeThroughTunnel(ctx context.Context, dialer tunnelDialer, judgeURL string) (int, int64, error) {
	u, err := url.Parse(judgeURL)
	if err != nil {
		return 0, 0, fmt.Errorf("parse judge_url: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	dest := M.ParseSocksaddrHostPortStr(host, port)

	start := time.Now()
	proxyConn, err := dialer.DialConn(ctx, dest)
	if err != nil {
		return 0, time.Since(start).Milliseconds(), fmt.Errorf("dial through tunnel: %w", err)
	}
	defer proxyConn.Close()

	var conn net.Conn = proxyConn
	if u.Scheme != "http" {
		tlsConn := tls.Client(proxyConn, &tls.Config{ServerName: host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, time.Since(start).Milliseconds(), fmt.Errorf("tls to judge host: %w", err)
		}
		conn = tlsConn
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := &http.Request{Method: http.MethodGet, URL: u, Host: host, Header: http.Header{}}
	req.Header.Set("User-Agent", "otun-probe/1")
	req.Header.Set("Connection", "close")
	if err := req.Write(conn); err != nil {
		return 0, time.Since(start).Milliseconds(), fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return 0, time.Since(start).Milliseconds(), fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, time.Since(start).Milliseconds(), nil
}

// traceFailStage 从 realm trace 取 fail_stage(nil 或未失败时空串)。
func traceFailStage(trace *realmlib.Trace) string {
	if trace == nil {
		return ""
	}
	return string(trace.FailStage)
}

