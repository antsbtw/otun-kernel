# B3 §7 punchDialer 绕过 tun — 内核组分析（需决策,未盲改）

> 回应 `B3-REALM-CLIENT-FINDINGS.md` §7：punchDialer 在 macOS NetworkExtension 下未绕过 tun,
> STUN 包被 auto_route 抓进 tun → 被分流规则塞回 realm 隧道 → 绕圈、挂 19~60s。
>
> 状态:**已定位关键事实,但不盲改**——因为现有构造已与"现网正常工作的 Hy2-realm"完全一致,
> 盲改有破坏工作路径的风险。需要更多真机证据或决策。

---

## 0. 其余需求状态（先澄清,避免重复）

- §2 TUIC init FATAL → **已修**（`underlay.LazyDialer`,懒+可重试打洞）。
- §3 Trojan 0 流量 → 文档已**撤回**（客户端 DNS-over-tunnel 死锁,非内核;客户端改 DNS 直连后五协议全通）。
- §6 rule_set 首次 fetch 阻塞启动 → **已修**（`StartContext` 降级 warn 不 return,CLI 实测不变砖）。
- **§7 = 当前唯一未决项**,本文档专门分析。

---

## 1. 关键发现:punchDialer 的构造与"现网正常的 Hy2-realm"完全一致

§7 假设"punchDialer 在 NE 下未真正绕过 tun"。但代码对照显示:

**我的 5 协议 punch dialer**（`common/otunrealm/config.go:50`）:
```go
punchDialer, err := dialer.New(ctx, dialerOptions, false)
```
`dialer.New` 就是 `dialer.NewWithOptions(Options{Context: ctx, Options: options, RemoteIsDomain: false})` 的 wrapper。

**上游 Hy2-realm 的 dialer**（`sing-box/protocol/hysteria2/outbound.go:79`）:
```go
outboundDialer, err := dialer.NewWithOptions(dialer.Options{
    Context: ctx, Options: options.DialerOptions, RemoteIsDomain: options.ServerIsDomain(),
})
// → 作为 realm.Options.Dialer 传给 sing-quic Hy2 realm
```

**两者构造等价。** 而 §1 明确写:**现网 Hy2-realm 打洞"连接正常、速度正常"**。

**矛盾点**:同样的 dialer 构造,Hy2-realm 正常,5 协议却 STUN 绕圈?这说明:
- 要么 §7 观察到的"慢"其实也发生在 Hy2-realm 上（§7 标题正是"**中国 hy2-realm 出口**真机慢"——注意 §7 描述的就是 Hy2,不是 5 协议!与 §1"Hy2 正常"自相矛盾,需前端澄清到底哪个 Hy2 场景）;
- 要么 5 协议与 Hy2 的 punch socket 在 NE 下有别的差异（下一节）。

---

## 2. sing-box 在 NE 下绕过 tun 的机制（已确认存在,且 punchDialer 应已享有）

`sing-box/common/dialer/default.go:97-118`:当 `AutoDetectInterface()` 且有 `platformInterface`（NE 环境就是）:
```go
bindFunc := networkManager.ProtectFunc()      // ← 调 NE protect()，socket 绕过 tun
dialer.Control = control.Append(dialer.Control, bindFunc)
listener.Control = control.Append(listener.Control, bindFunc)   // ← UDP listener 也 protect
```
`DefaultDialer.ListenPacket`（punch socket 走这条）→ `udpListener.ListenPacket` → 应用上面的 protect Control。

**所以理论上 punchDialer 的 STUN/punch UDP socket 在 NE 下应被 protect、绕过 tun。** 触发条件:
`disableDefaultBind == false`（即 outbound 的 DialerOptions **没有**设 `bind_interface` / `inet4_bind_address`）。

→ **排查方向 1（给前端）**:确认 realm outbound 的 `DialerOptions` 没设 bind_interface/bind_address
（否则 `disableDefaultBind=true`,protect 路径被跳过,socket 不绕 tun）。realm 模式下这些字段应为空。

---

## 3. 为什么 STUN 会被"sniff + rule_set 分流"——可能的真因

§7 日志:`router: sniffed packet protocol: stun` → `match rule_set=geoip-cn => route(realm-...)`。
STUN 被 router sniff,说明它**进了 tun**。即使 punchDialer 想 protect,若:

- **(a)** protect 没生效（DialerOptions 带了 bind,见 §2 排查1）;或
- **(b)** NE 的 `includeAllNetworks` / `auto_route` 强制把**所有** UDP（含 protected socket）塞进 tun
  —— 这是 macOS NE 已知行为,protect 在某些 NE 配置下仍被 includeAllNetworks 覆盖;或
- **(c)** STUN 目标是**国内出口 IP**（§7 说目标 `<exit>:20000`）,被 `geoip-cn` 规则匹配 →
  即使 socket 出了 tun,若它先进 tun 再被 sniff,就绕圈。

**根因更可能在 NE 配置层（b/c）,而非 punchDialer 的 Go 构造（已与 Hy2 一致）。**

---

## 4. 建议（需决策,我不盲改）

**不建议盲目改 punchDialer 的构造**——它已与现网正常的 Hy2-realm 等价,改了可能两边一起坏。

**推荐方案（与前端 §7 末尾"长期由后端 route.rules 下发豁免"一致）**:realm 打洞流量（STUN 目标 =
出口 IP:打洞端口段 + 会合面 IP）在 **route.rules 里显式 `outbound: direct` 豁免**,不进 realm 隧道。
这是 sing-box 处理"隧道自身控制流量"的标准做法,且前端已说要走这条（`SMART_STRATEGY_BACKEND_HANDOFF.md §8`）。
内核侧无需改代码。

**若要内核侧兜底**(可选,需决策):在 realm outbound 自动给打洞流量打 direct 标记/排除路由,
但这会让内核侧硬编码"哪些是打洞流量",侵入性大,且与 route.rules 方案重叠（前端明说会打架）。

**需要前端/你提供以澄清**:
1. §7 到底是 **Hy2-realm** 慢,还是 **5 协议**慢?（§1 说 Hy2 正常,§7 标题说 Hy2 慢,矛盾）
2. realm outbound 的 `DialerOptions` 是否设了 `bind_interface`/`bind_address`?（决定 protect 是否被跳过）
3. NE 是否开了 `includeAllNetworks` / `auto_route` 把 protected socket 也圈进 tun?

---

## 5. 结论

- punchDialer Go 侧构造**已正确且与上游 Hy2-realm 一致**,非明显 bug,不盲改。
- §7 根因更可能在 **NE 平台配置（includeAllNetworks/auto_route）** 或 **DialerOptions 带了 bind**,
  或就是"打洞流量该在 route.rules 豁免"这件还没做的事。
- **推荐**:route.rules 豁免打洞流量（前端已计划,内核零改动）。需前端确认上面 3 个澄清点后,
  再决定是否需要内核兜底。

> 这是"停下来问"而非"盲改"的判断:改一个已与工作路径等价的 dialer,风险大于收益。
