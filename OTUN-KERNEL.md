# OTun Kernel —— 四端共用的 sing-box realm 内核（路线 A）

> 本目录是 **客户端内核**。目标：让 iOS / macOS / Android / Windows 四端客户端，
> 经纯配置即可用 **6 种 over-realm 协议**（Hy2 + TUIC + Reality + Trojan + Shadowsocks + VMess）
> 打洞连上 OTun-S → 出口节点。
>
> 决策已拍板（2026-06-29，见 `../otun-s/CLIENT-INTEGRATION-HANDOFF.md` §3）：
> **路线 A（fork 内核，给 5 种非-Hy2 协议也加 `realm` 字段，仿 Hy2）+ 单内核 fork 目录。**

---

## 0. 这份 fork 是什么 / 不是什么

- **是**：`SagerNet/sing-box v1.14.0-alpha.26`（自带 Hy2 realm）的一份 fork，模块路径**保持
  `github.com/sagernet/sing-box` 不变**——这样内核内部所有 import、以及 Libbox/gomobile/CLI
  构建工具链全部零改动，仍可逐字对齐官方 `sing-box-for-apple` / `sing-box-for-android` 的
  libbox API。
- **不是**：协议引擎的重写。6 种协议的引擎（QUIC、Reality TLS、VMess/SS 加密…）仍 100%
  复用 sing-box / sing-quic / sing-* 库。本 fork 只在各协议 **outbound** 上**加接线**：
  解析 `realm` 配置字段 → 调 OTun 的打洞+接入胶水（`github.com/antsbtw/otun-s` 的
  `transport/realm` + `underlay` + `overlay/*`）→ 把打穿的洞喂给协议引擎。

一句话：**Hy2 的 realm 接线是 sing-box 自己内置的；本 fork 把同样的接线复制给另外 5 种协议，
接线背后的打洞逻辑直接 import OTun-S 已真机验通的 overlay 库，不在内核里重抄一遍。**

```
客户端 app (四端，零改动)
        │  纯配置：tuic-realm:// 等
        ▼
otun-kernel (本 fork = sing-box + realm 接线)
        │  protocol/{tuic,reality,trojan,shadowsocks,vmess}/outbound.go
        │  解析 options.Realm → 调 ↓
        ▼
github.com/antsbtw/otun-s  (库 import，不 fork)
   transport/realm.Punch ──► underlay ──► overlay/{tuic,reality,...}
        │
        ▼
   打穿的 UDP 洞 → OTun-S(新加坡) → 出口节点(法兰克福)
```

---

## 1. 目录约定

```
otun-kernel/
├── OTUN-KERNEL.md          ← 本文件
├── go.mod                  ← module 仍是 github.com/sagernet/sing-box；新增 require otun-s
├── option/<proto>.go       ← 各协议 OutboundOptions 加 Realm *RealmOptions 字段
├── option/realm.go         ← 【新增】五协议共用的 RealmOptions 结构（仿 Hysteria2Realm）
├── protocol/tuic/          ← 【改】outbound.go 接 realm
├── protocol/reality/...    ← （Reality 走 vless+reality；接线点见 §3）
├── protocol/trojan/        ← 【改】
├── protocol/shadowsocks/   ← 【改】
├── protocol/vmess/         ← 【改】
└── （其余文件与上游一致）
```

非-Hy2 五协议**共用一个** `RealmOptions`（不像 Hy2 各有 inbound/outbound 变体），
因为客户端只需要 outbound，且打洞坐标对所有协议都一样（协议无关）。

---

## 2. realm 接线的统一形状（每个协议照抄）

仿 `protocol/hysteria2/outbound.go::NewOutbound` 里 `if options.Realm != nil { … }` 那段：

1. **`option/<proto>.go`**：给 `<Proto>OutboundOptions` 加 `Realm *RealmOptions json:"realm,omitempty"`。
2. **`outbound.go`**：
   - `options.Realm == nil` → 走原版逻辑（普通 outbound，零行为变化）。
   - `options.Realm != nil` → 构造 `realm.Config`（ServerURL/Token/STUNServers/Resolver/HTTPClient），
     调对应 overlay：
     - UDP 系（TUIC）：`overlay/tuic.Dial` → 拿 `*overlay/tuic.Client`，其 `DialConn/ListenPacket`
       就是 outbound 的 `DialContext/ListenPacket`。
     - TCP 系（Reality/Trojan/SS/VMess）：`overlay/<proto>.Dial` → 拿 `*Conn`，其 `DialConn`
       即 outbound 的 `DialContext`。
   - TLS / SNI / 凭据等协议参数从原 options 取，逐字传给 overlay（caller-built TLS，和 Hy2 一致）。
3. **server/server_port 与 realm 互斥**：仿 `outboundTLSOptions`，realm 模式下 server 地址来自
   `realm.server_url` 的 host（仅用于 SNI 默认值），不需要 server/server_port。

`Resolver` / `HTTPClient` 的构造**逐字抄 Hy2 outbound.go 第 87–116 行**（DNSQueryOptionsFrom +
ResolveTransport + dnsRouter.Lookup），保证 DNS/h2 行为与 Hy2-realm 完全一致——这正是
交接文档 §7「realm 配置 4 个坑」要求的（STUN 用 IP、不用 http_client.detour、proxy-dns 用国内 DNS）。

---

## 3. 各协议接线点（对应 OTun overlay 真身）

| 协议 | 内核 outbound | overlay 入口（otun-s） | TLS 层数 | 备注 |
|---|---|---|---|---|
| TUIC | `protocol/tuic` | `overlay/tuic.Dial` | 1（QUIC/TLS） | UDP 系：QUIC 多路复用，**持有单 client 复用**；DialConn 多次安全 |
| Trojan | `protocol/trojan` | `overlay/trojan.Dial` | 1（外层 WrapStream） | 无 inner TLS；**单流**→每次 DialContext 重新打洞 |
| Shadowsocks | `protocol/shadowsocks` | `overlay/shadowsocks.Dial` | 1（外层 WrapStream） | SS AEAD 加密；**两端同 SS 库 v1**；单流→重新打洞；option 加了 `tls` 块作外层 |
| VMess | `protocol/vmess` | `overlay/vmess.Dial` | 1（外层 WrapStream） | sing-vmess；单流→重新打洞 |
| Reality | `protocol/vless`（vless+reality） | `overlay/reality.Dial` | **2**（外层 WrapStream + 内层 Reality） | **需 `-tags with_utls`**；单流→重新打洞 |

**单流 vs 多路复用（关键架构点）**：TUIC 的 `overlay/tuic.Client` 是 QUIC 多路复用，`DialConn` 可多次调用，所以 outbound **持有一个 realmClient 复用**。其余四个走 `WrapStream`——「一个洞 = 一条流」，单次使用；所以 outbound **不持有 live conn，而持有 realmDialer（参数模板），每次 `DialContext` 重新打洞 + WrapStream**，返回的 net.Conn 关闭时连洞一起释放（`realmStreamConn.Close`）。

**Reality 两层 TLS（用户已拍板：RealmOptions 加 `wrap_tls` 块）**：
- 内层 Reality = vless 的 `tls`（含 `reality` 子块）→ `tls.NewClient` 产出 Reality aTLS.Config。
- 外层 WrapStream = `realm.wrap_tls`（仅 Reality 用；其余四协议的 `tls` 块本身就是外层）。
- 客户端栈：`overlay/reality.Dial`（punch→WrapStream→Reality ClientHandshake→**VLESS framing**）
  返回 `*Client`，内核调 `Client.DialConn(dest)`，overlay 写 VLESS 请求头传目的地址。

> ✅ **VLESS 已下沉进 overlay（otun-s 2872ee8）**：`overlay/reality` 现在拥有完整 VLESS+Reality 栈
> （`Options.UUID` + `Dial→*Client` + `DialConn(ctx,dest)`），客户端与节点共用同一份 VLESS 实现。
> 内核侧**不再**自己套 `vless.Client.DialEarlyConn`——只传内/外层 TLS + UUID，调 `DialConn`。
> 出口节点 `node/realitynode` 已做 Reality ServerHandshake → VLESS server 读目的地址 → 拨出，
> Reality 与另四种 TCP 协议一样具备**任意目的地**能力（已真机验通：出口 IP `52.59.233.52`、HTTP 200）。
> 注意：realm 模式**不支持 vless `flow`**（XTLS 需要内层真 TLS 流可拼接，overlay 不暴露）。

---

## 4. 构建（四端共用本内核）

> ⚠️ **验证边界（务必先读）**：下列命令是**方法**，**不是已验证的构建报告**。
> 当前只验到 `go build -tags with_utls ./...`（普通主机编译）+ `go build ./...` 均绿、配置解析回归绿。
> **gomobile 的 `build_libbox` / `bind` 一次都没实跑**——gomobile 编译约束与普通 build 不同，
> 「`go build` 绿」**不保证** gomobile bind 能过，尤其 `with_utls` 是否正确带进 Libbox 脚本，
> 只有真出 xcframework / aar 时才暴露。实跑出包 + 四端真机验收属客户端集成阶段（见 §5、`CLIENT-INTEGRATION-HANDOFF.md`）。

### 4.0 共同前提（四端通用）

- **模块路径不变**：本 fork 仍是 `github.com/sagernet/sing-box`，所以官方 Libbox/gomobile/CLI 工具链零改动。
- **必带 `with_utls` 构建 tag**：四端**全部**要带，否则 Reality（vless+reality）在客户端不可用（交接文档 §6 红线）。
- **overlay 库来源**：`go.mod` 里 `replace github.com/antsbtw/otun-s => ../otun-s`（本地消费）。
  客户端集成阶段若要脱离本地路径，先把 otun-s push，再把 replace 换成版本号 `require`。
- 构建前自检：
  ```bash
  cd otun-kernel
  go build -tags with_utls ./...   # 应全绿（含 cmd/sing-box）
  go test  -tags with_utls ./option/ -run Realm   # 六协议配置解析回归
  ```

### 4.1 Apple（iOS / macOS）—— Libbox.xcframework（gomobile）

```bash
cd otun-kernel
make lib_install                                   # 装/校验 gomobile 工具链
go run ./cmd/internal/build_libbox -target apple   # 产出 Libbox.xcframework
```
- 产物喂给 `../OTun-M-realm2/`（干净基线），由 NetworkExtension 加载。
- **务必确认 `build_libbox` 的 tags 含 `with_utls`**（缺了 Reality 在 Apple 端直接不可用）；如脚本未透传，需在脚本/环境里补 tag。
- libbox API 漂移**逐字对齐官方 `SagerNet/sing-box-for-apple` dev 分支**，不自己发挥（交接文档 §7）。
- 别乱改 `Library/Network/` 下 Extension 代码，否则启动即 `stopTunnelWithReason: Plugin initiated`、零日志（交接文档 §7）。
- 装机/调试细节：`../OTun-M-realm2/doc/REALM_REBUILD_HANDOFF.md` §3。

### 4.2 Android —— aar（gomobile bind）

```bash
cd otun-kernel
go run ./cmd/internal/build_libbox -target android
# 或直接：gomobile bind -target=android -tags with_utls -o libbox.aar ./experimental/libbox
```
- 产物 aar 喂给 `sing-box-for-android` 壳（`../OTun-M-Android/`），由 VpnService 加载。
- 同样**必带 `with_utls`**。

### 4.3 Windows —— CLI 内核 / GUI 壳

```bash
cd otun-kernel
go build -tags with_utls -o sing-box.exe ./cmd/sing-box     # CLI 内核
# GUI：同源内核喂给 sing-box-for-windows 壳
```

### 4.4 四端共用 vs 各端差异

| 项 | 是否共用 |
|---|---|
| realm 打洞 + 六协议接入逻辑 | ✅ 全在本内核，一次实现、四端复用 |
| `with_utls` 构建约束 | ✅ 四端都要带 |
| 封装产物（xcframework / aar / exe）、系统权限、UI | ❌ 各端不同 |

### 4.5 保留原版直连中心化出口（已逐文件核实）

本内核是**「原版 sing-box ➕ realm 打洞」的超集**，直连能力完整保留：
- 每个改过的 outbound 都是 `if options.Realm != nil { …打洞…return }`，**配置里不写 `"realm"` 块 → 走 100% 原版直连路径**（逐字未改）。
- 未碰任何 inbound / 路由 / DNS；现有 vless/ss/trojan/vmess/tuic 直连、订阅、分流规则照旧。
- 直连与打洞**可在同一份配置共存**：某 outbound 直连中转、另一 outbound 带 `realm` 块走打洞，路由规则自由分流。
- 边界（仅约束写了 realm 块的那个 outbound）：realm 与 server/server_port/mux/transport/flow 互斥（写错报错非静默）；realm outbound 为 TCP-only（UDP-associate 返错，隧道内 DNS/HTTP 正常）。

---

## 5. 推进顺序（与交接文档 §4 一致）

1. ✅ 搭目录 + 设计文档（本文件）。
2. ✅ **TUIC 接通**（option/realm.go + option/tuic.go + protocol/tuic/{outbound,realm}.go）。
3. ✅ **Trojan / SS / VMess / Reality 全部接通**（共用 §2 形状 + §3 单流/双层 TLS 处理）。
   - `common/otunrealm/config.go` = 五协议共用的 realm.Config 构造 + TLS SNI 推导（抄 Hy2）。
   - `go build -tags with_utls ./...` 与无 tag 构建**均全过**；`option/realm_test.go` 六协议配置解析回归绿。
4. ✅ **otun-s 侧 Reality 节点 VLESS 读取已补**（commit 2872ee8，VLESS 下沉进 overlay，节点读目的地址→拨出，
   真机验通）。六协议任意目的地能力全部齐整。内核 `protocol/vless/realm.go` 已对齐新 overlay 签名。
5. ⏳ 真机验收：先 macOS + TUIC（最易调试，新加坡 OTun-S + 法兰克福 `cmd/otun-tuic-node`），
   逐协议过出口 IP；再出 Libbox.xcframework / aar 横向复制 iOS/Android/Windows（共用本内核）。
   ↑ 这是客户端集成阶段的活（改 app / 内核构建），适合新开对话——见 `CLIENT-INTEGRATION-HANDOFF.md`，
   第一步要拍板路线 A/B/C（本内核 fork 即路线 A 的实现）。

6. ✅ **内核侧六协议环回 E2E 全部验通(B1,运行时正确性)**:用内核**自己的 outbound**
   (`option.RealmOptions` → `NewOutbound` → `DialContext`)经环回打洞接通 otun-s 出口节点,
   逐协议 `ping → PING` proxied round-trip 通过。这把验证边界从「编译+配置」推进到「运行时接线正确」:
   - 共用 harness:`protocol/realmtest/`(STUN/会合面/echo target/自签名 TLS/fake HTTPClientManager+DNSRouter/
     EgressHandler;Reality 专用 builder 在 `reality.go`,`//go:build with_utls`)。
   - `protocol/{tuic,trojan,shadowsocks,vmess}/realm_e2e_test.go`(无 tag)+
     `protocol/vless/realm_e2e_test.go`(Reality,`//go:build with_utls`,双层 TLS+VLESS+uTLS)。
   - 全部纯 `go test`、纯本机、无 VPS/Xcode/gomobile。出口节点/会合面/STUN 复用 otun-s 已验组件当对端。
   - ⚠️ 工具链噪声:相对路径 replace 下 `go vet`/`go test -c` 会打印 `otun-s/protocol/X: directory not found`
     —— 非致命,**`go test` 实际编译运行正常**。用 `go test`(非 `-c`/`vet`)验证。
   - ❌ 仍未验(留客户端集成阶段):gomobile 出包(`with_utls` 是否进 Libbox 二进制)、NetworkExtension 真机环境。

7. ✅ **B2 Libbox.xcframework 符号验证(产物里接线确实编进)**:`otun-apple-build/Libbox.xcframework`
   (macos-arm64_x86_64 切片)二进制 `nm` 符号核验,证明 gomobile 出包把路线 A 接线**全部编进**了:
   - `with_utls` 生效:1422 utls + 122 reality 符号 → **Reality 在 Apple 端可用**(脚本 `build_libbox/main.go:66`
     sharedTags 含 `with_utls`,且确实进了二进制,不只是脚本声明)。
   - 六协议 realm 接线在产物里:`common/otunrealm`(6)、`overlay/{tuic,trojan,shadowsocks,vmess,reality}`、
     `transport/realm`(29)、`underlay`(59)符号齐全;接线函数 `tuic.newRealmClient` /
     `{trojan,shadowsocks,vmess}.realmDialer.DialConn` / `vless.realmDialer.DialContext` 逐个可见。
   - 这证实:gomobile 编的不是「原版 sing-box」,而是带本 fork 全部 realm 接线 + otun-s overlay 库的内核。
   - ❌ 仍未验(B3,真机):xcframework 拷进 `OTun-M-realm2/` → Xcode 编译 → NetworkExtension 真机
     逐协议过出口 IP(context/DNS/权限坑只有真机暴露)。

### 已接通文件清单
- `option/realm.go`（共用 RealmOptions，含 Reality 专用 `wrap_tls`）+ 各 `option/<proto>.go` 加 `Realm` 字段。
- `common/otunrealm/config.go`（共用桥接）。
- `protocol/{tuic,trojan,shadowsocks,vmess,vless}/realm.go` + 各 `outbound.go` 接线分支。
- `option/realm_test.go`（六协议解析回归）。
- `protocol/realmtest/{harness.go,reality.go}`（B1 环回 E2E 共用 harness）。
- `protocol/{tuic,trojan,shadowsocks,vmess,vless}/realm_e2e_test.go`（六协议运行时 E2E）。

## 6. B3 真机接手清单（下一个对话的起点）

> 内核 fork 从源码 → 环回 E2E（B1）→ Apple 产物符号（B2）整条链路已验；**只剩真机这一跳**。
> 这一步是客户端集成阶段：改 app 配置生成层 + 装机调 NetworkExtension。适合新开对话。
> 装机/Extension 方法与现网 Hy2-realm 经验见 `../OTun-M-realm2/doc/REALM_REBUILD_HANDOFF.md`。

### 6.1 关键区分（动手前必懂）
现网已验的是 **Hy2-realm**（`hysteria2-realm://`，sing-box 自带，走 situstechnologies + 上海移动出口）。
B3 要验的是**本 fork 新增的 5 种协议**（`tuic-realm://` 等），走 **otun-s 新加坡 OTun-S + 法兰克福出口**。
所以：**装机/Extension 流程可整段复用；但 app 的配置生成层要新增 scheme 解析**——这是 B3 的真正新工作。

### 6.2 步骤
1. **换内核（零代码改动验回归）**：把 `otun-apple-build/Libbox.xcframework`（B2 已符号验证）
   覆盖 `../OTun-M-realm2/Libbox.xcframework`（现有 757M，新 759M，切片同构）。先**不加任何 realm 配置**，
   按 `REALM_REBUILD_HANDOFF.md` §3 真机编译装机，验 **vless/Hy2-realm 仍正常**（证明换内核不破坏现有功能）。
   - ⚠️ libbox API 漂移逐字对齐官方 `SagerNet/sing-box-for-apple` dev 分支；**别乱改 `Library/Network/` Extension 代码**
     （否则启动即 `stopTunnelWithReason: Plugin initiated`、零日志，见 `REALM_REBUILD_HANDOFF.md` §2）。
   - 装机命令：见 `REALM_REBUILD_HANDOFF.md` §3（`xcodebuild -scheme SFI` + `xcrun devicectl device install`）。
2. **加新 scheme 配置生成**：在 `../OTun-M-realm2/Library/ForOTun/ConfigTemplate.swift` 的 `ProtocolURLParser`
   加 `tuic-realm://` 解析分支，生成带 `realm` 块的 **tuic** outbound（对应本 fork 的 `option.RealmOptions`）。
   配置字段映射见本文件 §2/§3 + `option/realm.go`（`server_url`/`token`/`realm_id`/`stun_servers`，TUIC 的 `tls` 块作 SNI）。
   - realm 4 坑沿用（`REALM_REBUILD_HANDOFF.md` §3.2 / 记忆 `realm-config-pitfalls`）：
     STUN 用 IP、realm 不要 `http_client.detour`、proxy-dns 用对出口可达的 DNS、realm 走单 outbound 不走 urltest。
3. **macOS + TUIC 先真机验**（最易调试）：经新加坡 OTun-S `54.255.172.86:9443`（h2c）打到法兰克福
   `cmd/otun-tuic-node` 出口，验**出口 IP = `52.59.233.52`** + 能传数据。realm token 见服务端 `/tmp/otun-users.json`。
4. **同端补另 4 协议**：Reality（需确认 Libbox 带 `with_utls`——B2 已证实符号在）走 `vless-reality://`+`wrap_tls`；
   Trojan/SS/VMess 各加 scheme。逐协议过出口 IP。
5. **横向复制 iOS / Android / Windows**：四端共用本内核，主要是封装/权限/UI 差异；内核接线零重写。

### 6.3 现网环境（复用，勿新开机器）
- 会合面：新加坡 OTun-S，`ssh otun-s-test`，`54.255.172.86:9443`（h2c）。token 见 `/tmp/otun-users.json`。
- 出口：法兰克福 `ssh otun-s-out`（`52.59.233.52`），`cmd/otun-tuic-node` 等。配置样例见 `/tmp/node-*.json`。
- ⚠️ 中国生产节点 `realm-cn-01` 全程不碰；用法兰克福出口。

### 6.4 B3 验收
四端各自 6 协议（Hy2 现成 + 5 种本 fork 新增）over-realm 打洞连上出口、传数据、出口 IP 正确；
不破坏现有 vless/ss 等非-realm 套餐。

## 7. 红线（勿碰）

- 不改 **会合面 rendezvous 线缆协议**（6 端点逐字兼容，见记忆 `realm-rendezvous-wire-protocol`）。
  本 fork 只新增 outbound 能力，不破坏会合面。
- 不动生产中国节点 `realm-cn-01`；集成测试用法兰克福出口 `52.59.233.52`。
- 不破坏现有 vless/ss 等非-realm 套餐：`options.Realm == nil` 时严格走原版路径。
- 协议引擎不重写，只加接线（验收定义 §8/§12）。

## 8. 相关位置

- 服务端 + overlay 库：`../otun-s`（`transport/realm`、`underlay`、`overlay/*`、`node/*`）。
- 上游内核研究副本（勿改，作 diff 基线）：`../sing-box-realm`。
- sing-quic realm 真身：`../sing-box-realm-deps/sing-quic/hysteria2/realm`。
- 全里程碑细节：`../otun-s/M1-ANALYSIS.md`。
- 项目记忆：`realm-source-locations`、`realm-rendezvous-wire-protocol`、`otun-s-test-vps`。
