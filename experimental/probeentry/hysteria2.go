package probeentry

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/netbind"
	realmlib "github.com/sagernet/sing-box/transport/realm"

	"github.com/sagernet/sing-quic/hysteria2"
	squicrealm "github.com/sagernet/sing-quic/hysteria2/realm"

	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// dialHysteria2 建 hy2-over-realm 隧道。
//
// 🔴 首期只支持 path=normal:hy2 的打洞/中继编排在 vendored sing-quic 内部
// (offerNewRealm),不经 transport/realm 的 PunchMode 分支,所以 punch_only/
// relay_only 对 hy2 尚不可用 —— 显式报错,不静默当 normal 跑(那会产出误导性
// 的「hy2 relay_only 成功」假样本)。hy2 强制路径是后续增量(需 vendored squic
// 侧加同款 mode 开关)。
//
// hy2 的 socket 绑定走 hysteria2.ClientOptions.Dialer(netbind);会合面 control
// 与 STUN 解析走 squic realm.Options 的 HTTPClient/Resolver(同样 netbind)。
// 由于 hy2 的埋点在 squic 内部(需 vendored 侧观测),本入口暂不回填 realm trace
// (Trace 恒 nil),success 仍由经隧道的真实往返判定 —— 判据不受影响。
func dialHysteria2(ctx context.Context, spec *Spec, nd *netbind.Dialer, trace *realmlib.Trace) (tunnelDialer, *realmlib.Trace, error) {
	if spec.path() != PathNormal {
		return nil, nil, errUnsupportedHy2Path(spec.path())
	}

	tlsConfig, err := clientTLS(ctx, spec.SNI, spec.Insecure, []string{"h3"})
	if err != nil {
		return nil, nil, err
	}

	realmOptions := &squicrealm.Options{
		ServerURL:   spec.ServerURL,
		Token:       spec.Token,
		RealmID:     spec.RealmID,
		STUNServers: spec.STUN,
		HTTPClient:  nd.HTTPClient(spec.RendezvousInsecure),
		Resolver:    squicrealm.Resolver(nd.Resolver()),
		Logger:      logger.NOP(),
	}

	client, err := hysteria2.NewClient(hysteria2.ClientOptions{
		Context:            ctx,
		Dialer:             nd,
		Logger:             logger.NOP(),
		ServerAddress:      M.Socksaddr{Fqdn: "otun-realm.invalid", Port: 443}, // realm 模式下被忽略
		Password:           spec.UUID,
		SalamanderPassword: spec.Obfs,
		TLSConfig:          tlsConfig,
		RealmOptions:       realmOptions,
	})
	if err != nil {
		return nil, nil, err
	}
	return &hy2Tunnel{client: client}, trace, nil
}

// hy2Tunnel 把 hysteria2.Client 适配成 tunnelDialer。
type hy2Tunnel struct {
	client *hysteria2.Client
}

func (t *hy2Tunnel) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return t.client.DialConn(ctx, destination)
}

func (t *hy2Tunnel) Close() error { return t.client.CloseWithError(nil) }

func errUnsupportedHy2Path(p Path) error {
	return &unsupportedHy2PathError{path: p}
}

type unsupportedHy2PathError struct{ path Path }

func (e *unsupportedHy2PathError) Error() string {
	return "hysteria2 path " + string(e.path) + " not supported yet (only normal); force-path is a vendored-squic increment"
}
