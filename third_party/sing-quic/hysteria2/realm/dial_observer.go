package realm

import "net/netip"

// DialObserver 观测一次发起端 realm 建连(hy2 Client.offerNewRealm)的各个阶段。
//
// ★为什么在 sing-quic 里开这个口子(2026-10-15):五协议的打洞编排在 kernel 自己的
// transport/realm.PunchTraced 里,埋点直接内联;hy2 的编排在本包调用方 hy2 Client 内部,
// kernel 插不进去 —— 于是住宅面(hy2)的 punch_nonce / fail_stage 在生产包里**从来都是空的**
// (10-15 中国移动真机遥测全 null,后端 §3.2 第 2 条)。此前的钩子只在探针 fork
// (go.probe.mod)里,发版 Libbox 不带。现在进树内,由 kernel 侧把回调翻译成 Trace。
//
// 约束:只记录事实,不改变任何控制流;回调里不得阻塞。
// 一次建连一个观测器(Options.NewDialObserver 每次 offer 调一次),Finish 恰好调用一次。
type DialObserver interface {
	// STUNDiscovered:各地址族 STUN 反射地址发现完毕(并集)。
	STUNDiscovered(localAddresses []netip.AddrPort)
	// RendezvousDone:会合面换址完毕,metadata 含本次 nonce(双端 join 键)。
	RendezvousDone(peerAddresses []netip.AddrPort, metadata PunchMetadata)
	// PunchAttempted:某地址族开始打洞(family = "v4"/"v6")。
	PunchAttempted(family string, candidates []netip.AddrPort)
	// PunchSucceeded:打洞落定,winner 地址族与结果。
	PunchSucceeded(family string, result PunchResult)
	// RelaySettled:打洞失败后的中继回退结果(err=nil 即经中继救回)。
	RelaySettled(relayAddr string, err error)
	// HandshakeDone:QUIC 握手 + hy2 认证完成(隧道建立,不代表可用)。
	HandshakeDone()
	// Failed:卡在某阶段。stage 取 "rendezvous" / "stun" / "punch" / "handshake"。
	// 同一次建连可能先 Failed("punch") 再 RelaySettled(nil) —— 打洞失败是真实卡点,
	// 中继救回是附加事实,两者都记(与 kernel transport/realm 口径一致)。
	Failed(stage string, err error)
	// Finish:本次建连结束(成功或失败),观测器在此输出。恰好一次。
	Finish()
}
