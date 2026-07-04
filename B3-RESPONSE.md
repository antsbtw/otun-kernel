# B3 真机回归 — 内核组回复（两个问题已定位 + 修复）

> 回应 `B3 真机回归发现`（2026-06-30，OTun-M-realm2 macOS 集成）。两个问题都已**定位根因并修复**,
> 全协议在内核 CLI 真机链路（本机→新加坡会合面→法兰克福出口）复验通过。下面给根因、改了什么、前端怎么复验。

---

## 问题 1（TUIC init 期同步 punch → FATAL）✅ 已修

**根因（确认前端诊断正确）**：`overlay/tuic.Dial` 用的是 **eager dialer**——`realm.Punch` 在
`NewOutbound`/init 阶段就同步发起,失败即 FATAL,整个 `create service` 崩。其余四协议走 WrapStream
是懒打洞(DialContext 才连),所以不崩。

**修复（otun-s 侧,benefits 内核自动）**：
1. 新增 `underlay.LazyDialer`——把打洞推迟到 TUIC 引擎**首次真正 dial（offer）**时,且**可重试不缓存失败**
   （TUIC 失败后下次 DialConn 会重新 offer → 重新打洞）。
2. `overlay/tuic.Dial` 改用 LazyDialer,**init 不再打洞**;TUIC 从打穿conn 的 RemoteAddr 取真实 peer,
   静态 ServerAddress 只是占位。

**效果**：
- `singbox check`（跑 create service + outbound init）**不再 FATAL**（rc=0）。
- 一次 punch 抖动 → **per-connection ERROR,不崩**（与其余四协议对齐）;下次连接自动重试。
- 真机复验:TUIC 经内核拉 ipify → `52.59.233.52` HTTP 200。

---

## 问题 2（Trojan 等连上但 0 流量）✅ 根因定位 + 修复（需前端 TUN 复验）

**这是最关键的发现。根因:打洞/STUN 用的 UDP socket 没有从隧道里"豁免",在全局代理 TUN 下被自己的 TUN 捕获 → 回环 → punch 包永远到不了公网 → 洞打不开 → 0 流量。**

具体:`common/otunrealm/config.go` 的 `BuildConfig` 只设了 `HTTPClient` + `Resolver`,**没设
`realm.Config.Dialer`**。otun-s 的 `realm.Punch` 在 `Dialer==nil` 时回退到**裸 `net.ListenUDP`**
（`transport/realm/punch.go`）。裸 socket 在全局 TUN 下被 TUN 抓走:
- 会合面 HTTP（走 managed transport,受 outbound dialer 约束）可能还能通 → 所以"连上";
- 但 **STUN + 打洞的裸 UDP** 走不出 TUN → 数据面 0 流量。

> 这也解释了为什么**内核 CLI（mixed/SOCKS inbound,无 TUN）测全过、真机 TUN 才 0 流量**——
> CLI 没有 TUN 捕获自己的裸 socket,所以掩盖了这个问题。前端用 TUN 才暴露,诊断方向完全正确。

**修复（otun-kernel 侧）**：`BuildConfig` 现在用 sing-box 的 `dialer.New(ctx, dialerOptions, false)`
建一个 dialer 并设进 `realm.Config.Dialer`。sing-box dialer 在 Apple/Android 上**自动保护/绑定
outbound socket**(不被自己的 TUN 捕获),STUN/punch 包就能走真实接口出去。五协议共用此 `BuildConfig`,
一处修复全协议生效(TUIC 经 LazyDialer→realm.Punch(cfg) 同样吃到 cfg.Dialer)。

**内核侧复验**（CLI 链路,5 协议全过）:Trojan/SS/VMess/Reality/TUIC 经内核拉 ipify 均 → `52.59.233.52` HTTP 200。

**⚠️ 需前端在真机 TUN 复验的点**：CLI 无 TUN,无法 100% 复现 Extension 环境。请前端用**带本修复的内核**
重测:全局代理 TUN 下,Trojan（及其余四）是否真有流量。预期:`realm.Config.Dialer` 已让 STUN/punch
socket 受保护,洞应能打通。**若仍 0 流量**,下一步排查方向:
- Extension 的 `NEPacketTunnelProvider` 是否对所有 UDP 强制进 TUN（即使 sing-box dialer 想豁免）——
  可能需要 Extension 侧把会合面 IP `54.255.172.86` + STUN IP 加入 TUN 的 **bypass/excluded routes**,
  或确认 sing-box 的 `auto_route`/`auto_redirect` 没把这些 IP 也圈进去。
- 抓 Extension 内 UDP 是否真出网（Console.app 或在出口节点看 STUN/punch 是否到达）。

---

## 修复清单（已 commit）

| 仓 | 改动 |
|---|---|
| `otun-s` | `underlay.LazyDialer`（懒+可重试打洞）;`overlay/tuic` 改用之,init 不打洞 |
| `otun-kernel` | `common/otunrealm/config.go::BuildConfig` 设 `realm.Config.Dialer`（隧道豁免的 STUN/punch socket）|

两仓 `go build` / `go test`（含 `-tags with_quic with_utls with_gvisor` / `with_utls`）全绿。

---

## 给前端的复验步骤

1. 拉带修复的内核重出 `Libbox.xcframework`（with_quic with_utls with_gvisor）。
2. TUIC profile:确认点连接 **不再瞬崩**（问题 1）。
3. Trojan/SS/VMess/Reality profile:全局代理下确认**有流量、出口 IP `52.59.233.52`**（问题 2）。
4. 若 Trojan 仍 0 流量 → 按上方"⚠️"排查 Extension TUN 是否把会合面/STUN IP 也圈进隧道(bypass routes)。

参数见 `REALM-TEST-PARAMS.md`(已更新:节点仍在 otun-s-out 运行)。
