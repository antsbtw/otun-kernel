# B3 真机回归发现 — over-realm 五协议（客户端集成阶段反馈）

> 编写：2026-06-30，来自客户端 `OTun-M-realm2`（Apple/macOS）集成测试。
> 对应 OTUN-KERNEL.md §6 "B3 真机接手清单"。B1（环回 E2E）/B2（Libbox 符号）内核组已验通；
> 本文档是 **B3 真机这一跳** 的结果：**发现两个内核侧问题，退回内核组定位/修复。**
>
> ⚠️ **2026-06-30 更新（重要）**：下方 §2/§3 是初版发现，后续真机已全部解决，结论更正如下：
> - **TUIC（§2）**：内核组已修（init FATAL → 现在能连）✅ —— 该需求达成，§2 仅留作记录。
> - **Trojan「0 流量」（§3）**：**经更正，根因不是内核数据面，而是客户端 DNS-over-tunnel 死锁**
>   （DNS 走隧道，隧道刚建未稳 → DNS 包拿不到回应 → 所有连接卡在解析第一步）。客户端把
>   调试配置的 DNS 改直连后，**五协议（tuic/trojan/ss/vmess/reality）真机全部打通**，
>   日志显示 `connection upload/download finished`。**§3 的"内核数据面问题"判断撤回，非内核 bug。**
> - 当前对内核组的**唯一在办需求**：§6（remote rule_set 首次 fetch 失败不应阻塞启动）。
>
> ---
>
> 结论速览（初版，部分已更正见上）：
> - ✅ 换内核回归通过：新 Libbox 不破坏现网 HY2-realm + 传统 vless/ss 连接。
> - ✅ 五协议 over-realm profile 在客户端正确生成、Extension 能加载（除 TUIC）。
> - ❌ **问题 1（TUIC）**：outbound **初始化阶段同步 punch，失败即 FATAL** → Extension 启动即崩。【已修】
> - ❌ **问题 2（Trojan）**：连接建立（Extension 不崩）但 **0 流量**。【已更正：客户端 DNS 死锁，非内核】

---

## 0. 测试环境（B3）

- 客户端：`OTun-M-realm2` 分支 `realm-clean`，换入 `otun-apple-build/Libbox.xcframework`（B2 符号已验）。
- 平台：macOS（System Extension `com.situstechnologies.OXray.extension`）。
- 配置：硬编码后端给的 5 协议 PoC outbound JSON（会合面 `http://54.255.172.86:9443`，
  token `jwhCQ82...`，出口节点 otun-s-out，验收出口 IP `52.59.233.52`）。
- 配置形态：单 outbound 全局代理（不含 geosite/geoip rule_set，避开 GitHub 下载阻塞），
  tun stack=system，realm 块字段对齐 `option/realm.go`。客户端侧配置生成已逐字校验正确。

---

## 1. 换内核回归 ✅

| 项 | 结果 |
|---|---|
| 新 Libbox 加载 | ✅ libbox API 零漂移，SFI/SFM 编译链接通过 |
| 现网 HY2-realm（打洞，situstechnologies 出口） | ✅ 连接正常、速度正常 |
| 传统 vless/reality/ss（不打洞） | ✅ 正常 |

→ 新内核是"原版 + realm 接线"超集这一点，真机侧成立，不破坏现有功能。

---

## 2. 问题 1：TUIC outbound 初始化期同步 punch → FATAL → Extension 启动崩 ❌

### 现象（真机）
选 TUIC profile 点连接 → **立刻断、Extension 瞬起瞬灭、无任何日志**（System Extension 日志
不进 macOS 统一日志，抓不到；表现为"零反馈"）。

### 复现（内核源码 CLI，确凿）
用 otun-kernel 源码编 macOS CLI 本地 run TUIC 配置（tun 换 mixed 免 root）：

```bash
go build -tags "with_quic with_utls with_gvisor" -o singbox ./cmd/sing-box
./singbox run -c tuic-realm.json
# →
FATAL create service: initialize outbound[0]: punch: realm connect: connect:
  Post "http://54.255.172.86:9443/v1/m3-tuic-out/connect": dial tcp ...
```

关键：错误发生在 **`create service: initialize outbound[0]`** —— **outbound 初始化阶段就同步发起
realm punch**，punch 失败 → 整个 `create service` FATAL → 内核根本起不来。

### 五协议对比（同一 CLI，同样 run）
| 协议 | init 期行为 |
|---|---|
| **tuic** | ❌ **初始化同步 punch，失败 FATAL，service 创建失败** |
| trojan / shadowsocks / vmess / reality | ✅ 启动正常（懒打洞，DialContext 时才连，init 不阻塞/不崩） |

→ 与 OTUN-KERNEL.md §3 一致：TUIC 是 QUIC 多路复用、**持有单 realmClient（init 就建）**；
其余四个走 WrapStream 单流（用时才打洞）。**但"init 期同步 punch 且失败即 FATAL"在客户端
是致命的**：任何一次 init punch 不成功（网络时序/STUN/会合面抖动）= Extension 直接崩、用户零反馈。

### 给内核组的建议（供参考，最终方案内核组定）
TUIC 的 realm client **不应在 `NewOutbound`/初始化阶段同步打洞并以 FATAL 失败**。
建议改为**懒初始化**（首次 DialContext 才建 realmClient + punch），或 init punch 失败时
**降级为非致命**（记录错误、连接时重试），与其余四协议的懒打洞行为对齐。否则 TUIC 在真机
不可用（一次抖动即崩）。

---

## 3. 问题 2：Trojan 连接建立但 0 流量（数据面打不通）❌

### 现象（真机）
选 Trojan profile 点连接 → **Extension 正常起来、状态 Connected（不崩，符合懒打洞）**，
但 Dashboard 显示 **`0 B/s` 上下行、`0/0` 连接数、`0.0 KB` 总量** —— 隧道建立了，
**实际数据走不通**（产生流量也无 Conn 计数，疑似首个连接的 DialContext 打洞/WrapStream 阶段卡住或失败）。

### 待内核组验证
- 出口节点 otun-s-out 上 trojan listener 在 `:51823`（/tmp/node-trojan.json），realm_id `m5-trojan-out`。
- 客户端配置 realm 块与节点一致（token/realm_id/stun 对齐）。
- 需内核组在真机/有网环境验证 trojan 的 **DialContext → punch → WrapStream → 出口拨出** 数据面
  是否真的通（B1 环回 E2E 过了，但真机 punch 路径/出口 WrapStream 可能有差异）。
- 同源怀疑：其余三协议（ss/vmess/reality）也走 WrapStream 单流，可能同样"连上但 0 流量"，建议一并验。

---

## 4. 退回内核组的明确请求

1. **TUIC**：修 init 期同步 punch FATAL（建议懒初始化或非致命降级），使 Extension 不因一次 punch 抖动崩溃。
2. **Trojan（及 ss/vmess/reality）**：验证真机数据面（DialContext→punch→WrapStream→出口）是否真通；
   当前客户端侧表现为"连上但 0 流量"。
3. 复现工具：otun-kernel 源码 `go build -tags "with_quic with_utls with_gvisor" ./cmd/sing-box` +
   PoC 配置（tun 换 mixed 可免 root 本地 run，trace 日志直出）。

### 客户端侧已排除（非 app 问题）
- 配置生成正确（逐字校验）、Libbox 符号齐全（B2：quic 22202 / tuic 283 / 各 overlay 接线符号在）、
  Extension 能拉起（HY2 + trojan 都起来了）、换内核不破坏现网。
- 客户端 region 策略=境外（cnViaProxy=false，全局走隧道），DNS final 方向已对（近期回归修复）。

---

## 5. 客户端侧 PoC 脚手架（测通后将移除，不进正式发布）

仅供内核组了解客户端怎么喂配置（在 `OTun-M-realm2` 分支 realm-clean，未 commit）：
- `Library/ForOTun/OTunRealmDebugConfigs.swift`：5 协议硬编码 PoC outbound JSON + 启动自动注册 profile。
- `ConfigTemplate.generateConfigFromOutboundJSON` + `generateGlobalProxyConfig`：直喂 outbound JSON → 最简全局代理配置。
- `ConfigPipeline.applyFromFullConfigJSON`：完整 config JSON 建 profile。

---

## 6. 追加需求（2026-06-30）：remote rule_set 首次 fetch 失败不应阻塞启动

**问题**：`route/rule/rule_set_remote.go` `StartContext`（约 line 100-103）首次 fetch 失败
`return E.Cause(err, "initial rule-set")` → 整个内核启动失败。中国大陆下 geosite/geoip
规则集（无论 GitHub 还是后端短暂抖动）拉不到 → Extension 变砖。

**请求**：首次 fetch 失败时记 warn/error 但**不 return**（降级：rule_set 暂空，PostStart
定期更新继续重试——那条已是 logger.Error 不 return）。等价官方 `missing_behaviour: default`。
可选：给 RemoteRuleSet option 补 `missing_behaviour` 字段（当前 fork 无此字段）。

详见客户端 doc/RULESET_HOSTING_AND_KERNEL_HANDOFF.md §3。

---

## 7. 追加（2026-06-30）：punchDialer 在 macOS NetworkExtension 下未绕过 tun → STUN 绕圈拖慢

**现象**：中国 hy2-realm 出口真机慢。客户端 Kernel Log：realm 打洞 STUN 包（目标国内出口
IP `<exit>:20000`）从 tun 进来 → `router: sniffed packet protocol: stun` →
`match rule_set=geoip-cn => route(realm-iptv-cn-auto)` → **打洞 STUN 被自己的 realm 隧道绕圈** →
大量连接挂 19~60s，吞吐崩。客户端已排除：mtu1500/stack system/带宽20-50/DNS方向/分流方向 全对。

**根因（内核侧，代码自述）**：`common/otunrealm/config.go:42-50` 注释明说 STUN/punch socket
必须经 punchDialer 绕过 tun，否则 loopback；已用 `dialer.New(ctx, dialerOptions, false)` 防护。
**但 macOS NetworkExtension 的 auto_route 会把打洞流量也抓进 tun**，punchDialer 在 NE 环境下
未真正绕过 tun → STUN 仍回到 tun 被分流规则塞进隧道。

**请求**：确认/修复 punchDialer 在 NetworkExtension（auto_route=true 的 tun）环境下确实绕过
tun（如 bind 到真实接口 / protect socket / 排除路由）。这是 realm 在移动端/NE 可用的前提。

客户端侧不打临时补丁（前端加 stun→direct 会与 punchDialer 重叠/打架）；长期由后端 route.rules
下发 realm 打洞流量豁免（见客户端 doc/SMART_STRATEGY_BACKEND_HANDOFF.md §8）。

---

## 8. 前端回复内核组的 §7 分析（2026-06-30）—— 澄清 3 点 + 更正表述

内核组指出 §7 与 §1 矛盾、且 dialer 与现网 Hy2 等价、不应盲改内核。**前端核对事实，确认内核组方向对，回复如下：**

### 澄清①（慢的是谁）
慢的是 **Hy2-realm 中国 residential 出口**（profile `OTun-Residential-Trial`，tag `realm-iptv-cn-auto`），
**不是 5 协议**（5 协议=法兰克福 PoC，已全通）。
**更正表述矛盾**：§1"现网 Hy2 正常"指的是【换内核回归那次/法兰克福场景】，§7 是【中国 Hy2 出口 STUN 场景慢】——
两者非同一时刻/场景，不矛盾。§1 应限定为"换内核回归时 Hy2 连接正常"。

### 澄清②（bind）
realm outbound **无 bind_interface / bind_address**（实测字段：tls/password/type/realm/up_mbps/down_mbps/obfs/tag）。
→ 排除内核组怀疑的 (a)：protect 未被 bind 跳过。

### 澄清③（includeAllNetworks）
`SharedPreferences.includeAllNetworks` **默认 false**（Library/Database/SharedPreferences.swift:23），
用户未手动开。→ 排除 (c)：includeAllNetworks 未覆盖 protect。

### 前端的诚实修正
"STUN 绕圈是慢的主因"是**读日志的推断，无铁证**——未做"豁免 STUN 后是否变快"的对照实验。
日志确凿的只是：到出口 `<ip>:20000` 的 stun 包被 geoip-cn 匹配进 realm 隧道。这**现象成立**，
但是否就是慢的主因待验。

### 结论：采纳内核组方案（内核零改动）
**route.rules 豁免打洞流量（STUN/到出口 punch 端口/会合面 IP → outbound: direct），不进 realm 隧道。**
这是 sing-box 处理"隧道自身控制流量"的标准做法，与前端 SMART_STRATEGY_BACKEND_HANDOFF.md §8 长期方案一致。
**§7 的"内核改 punchDialer"需求撤回**——既然 dialer 与现网 Hy2 等价、bind/includeAllNetworks 都已排除，
不盲改内核。改由 route.rules 豁免（前端验证 + 长期后端下发）。

→ **当前对内核组：无在办需求**（§2/§6 已修，§7 撤回改走 route.rules）。

---

## 9. 最终更正（2026-06-30）：STUN 绕圈【不是】中国出口慢的主因，§7/§8 全部撤回

**对照验证结果**：中国 Hy2 出口慢，前端怀疑 STUN 打洞流量绕圈（§7/§8）。真机验证发现：
- 中国出口已变快（实测 >1.5 MB/s），但 Kernel Log 里 STUN 流量**仍走 realm 隧道**
  （`sniffed stun → match geoip-cn → route(realm-iptv-cn-auto)`，STUN 豁免规则当时并未生效）。
- 即"STUN 还在绕圈，速度照样快" → **STUN 绕圈不是慢的主因**，前端推断错误。

**真正让中国出口变快的**：客户端早先的性能修复（Hy2 带宽 up_mbps/down_mbps、tun stack=system、
mtu=1500、DNS final 方向），之前一直被旧缓存配置掩盖，重新生成配置后才生效。与内核无关。

**结论**：
- §7（punchDialer 绕 tun）、§8（STUN 绕圈）**全部撤回**，非内核问题，也非真正的性能问题。
- 前端已回退临时加的 `protocol:stun→direct` 豁免规则（无必要，且会误伤用户真实 STUN 应用）。
- **内核组对本文档：无任何在办需求**（§2 TUIC 已修、§6 rule_set 已修、§7/§8 撤回）。
  内核组的质疑（dialer 与现网 Hy2 等价、不应盲改）完全正确，特此确认。

---

## 10. B3 真机验收【全部通过】—— 内核定版（2026-06-30）

**六协议 over-realm 打洞真机全通**，客户端集成全链路验收完成：
- 法兰克福 otun-s-out：tuic/trojan/shadowsocks/vmess/reality 五协议过出口 52.59.233.52 ✅
- 中国 realm-cn-01（广西南宁移动住宅 IP）：hysteria2 + 上述五协议 = 六协议过出口 117.140.107.33，
  从美国流畅访问中国节点（CCTV5 等）✅
- 平台：macOS + iOS 真机均通过。

**结论：otun-kernel（路线 A fork）客户端侧验收通过，内核正式定版。**

内核组在本文档的全部事项均已闭环：§2 TUIC init FATAL【已修】、§6 rule_set 启动降级【已修/或随版本】、
§7/§8 STUN 绕圈+punchDialer【经多份真机日志确证非性能问题，撤回】。**内核组无遗留在办需求。**

后续工作转向：后端配置下发管理（smart_strategy 通用化 / 多区域 / rule-set 托管），不涉及内核。
