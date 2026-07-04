# 六协议 over-realm 真机测试参数（后端下发用）

> 给后端/前端联调:这是当前 PoC 真机环境（会合面 `otun-s-test` + 出口 `otun-s-out`）的完整节点配置,字段已对齐 `otun-kernel` 的 `option/realm.go` (`RealmOptions`)。后端把这些拼进各协议 outbound 下发,客户端（otun-kernel）即可打洞测试。
>
> ⚠️ **全部是 PoC 值**:公网明文 h2c 会合面、自签 WrapStream 证书。**仅联调,勿进生产。** 生产时 server_url 走 `https://<域名>/realm`（经 Cloudflare/nginx）,WrapStream 用真证书去掉 insecure。

---

## 0. 节点拓扑

| 角色 | 机器 | 地址 |
|---|---|---|
| 会合面 OTun-S | `otun-s-test`（新加坡） | `http://54.255.172.86:9443`（h2c） |
| 出口节点 | `otun-s-out`（法兰克福） | 公网 `52.59.233.52`;各协议监听不同 UDP 端口（仅节点自用,客户端不直连——走打洞） |

数据面 = 客户端 ↔ 出口节点 **直接打洞**,不经会合面。出口 IP 应为 `52.59.233.52`。

---

## 1. 共用参数（所有协议）

| 字段 | 值 |
|---|---|
| `realm.server_url` | `http://54.255.172.86:9443` |
| `realm.token` | `jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg` |
| `realm.stun_servers` | `["74.125.250.129:19302","162.159.207.0:3478"]`（**必须 IP,不能域名** — realm 坑） |

---

## 2. 各协议完整 outbound 配置（sing-box JSON,字段对齐 RealmOptions）

> 配置形态规则（来自 `option/realm.go` + OTUN-KERNEL.md §3）：
> - **TUIC / Trojan / Shadowsocks / VMess**:顶层 `tls` 块 = 外层 WrapStream（QUIC）TLS。当前节点 WrapStream 用自签 `wrap.local` → 客户端必须 `"insecure": true`、`"server_name": "wrap.local"`、`"alpn": ["h3"]`。
> - **Reality**:顶层 `tls` 块 = **内层 Reality**（public_key/short_id/sni/utls）;外层 WrapStream TLS 放在 `realm.wrap_tls`。

### 2.1 TUIC（realm `m3-tuic-out`）
```jsonc
{
  "type": "tuic",
  "tag": "tuic-realm-out",
  "uuid": "deadbeef-0102-0304-0506-0708090a0b0c",
  "password": "m3-tuic-pw",
  "tls": { "enabled": true, "server_name": "wrap.local", "insecure": true, "alpn": ["h3"] },
  "realm": {
    "server_url": "http://54.255.172.86:9443",
    "token": "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg",
    "realm_id": "m3-tuic-out",
    "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"]
  }
}
```

### 2.2 Trojan（realm `m5-trojan-out`）
```jsonc
{
  "type": "trojan",
  "tag": "trojan-realm-out",
  "password": "trojan-pw-m5",
  "tls": { "enabled": true, "server_name": "wrap.local", "insecure": true, "alpn": ["h3"] },
  "realm": {
    "server_url": "http://54.255.172.86:9443",
    "token": "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg",
    "realm_id": "m5-trojan-out",
    "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"]
  }
}
```

### 2.3 Shadowsocks（realm `m5-ss-out`）
```jsonc
{
  "type": "shadowsocks",
  "tag": "ss-realm-out",
  "method": "aes-128-gcm",
  "password": "ss-pw-m5",
  "tls": { "enabled": true, "server_name": "wrap.local", "insecure": true, "alpn": ["h3"] },
  "realm": {
    "server_url": "http://54.255.172.86:9443",
    "token": "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg",
    "realm_id": "m5-ss-out",
    "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"]
  }
}
```
> 注:SS 两端必须同 method+password（节点用 sing-shadowsocks v1,客户端 otun-kernel 亦然）。

### 2.4 VMess（realm `m5-vmess-out`）
```jsonc
{
  "type": "vmess",
  "tag": "vmess-realm-out",
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "security": "auto",
  "alter_id": 0,
  "tls": { "enabled": true, "server_name": "wrap.local", "insecure": true, "alpn": ["h3"] },
  "realm": {
    "server_url": "http://54.255.172.86:9443",
    "token": "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg",
    "realm_id": "m5-vmess-out",
    "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"]
  }
}
```

### 2.5 Reality（VLESS+Reality,realm `m5-reality-out`）
```jsonc
{
  "type": "vless",
  "tag": "reality-realm-out",
  "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
  "tls": {
    "enabled": true,
    "server_name": "www.apple.com",
    "utls": { "enabled": true, "fingerprint": "chrome" },
    "reality": {
      "enabled": true,
      "public_key": "2OrHcCSeqlYmdVt2yAtwr2ahna9pxnjItbGzsf3qIk0",
      "short_id": "0123456789abcdef"
    }
  },
  "realm": {
    "server_url": "http://54.255.172.86:9443",
    "token": "jwhCQ82CRclSSeHHcXDvWjO0Cp5fV51dJ0csZtWdg",
    "realm_id": "m5-reality-out",
    "stun_servers": ["74.125.250.129:19302","162.159.207.0:3478"],
    "wrap_tls": { "enabled": true, "server_name": "wrap.local", "insecure": true, "alpn": ["h3"] }
  }
}
```
> Reality 节点借壳目标 = `www.apple.com`（节点侧实际拨其 v4 IP `88.221.168.210`,SNI 仍 `www.apple.com`）。客户端只需上面的 public_key/short_id/sni。

### 2.6 Hysteria2（对照,sing-box 原生 realm,**无需 otun-kernel**）
Hy2 用 sing-box 内置 realm,格式即现有 `hysteria2-realm://`（参数同 §1,realm_id 用现网 Hy2 出口的）。**这条现成内核就能跑**,与上面 5 条区别见 `../otun-s/ARCHITECTURE-OVERVIEW.md` §3。

---

## 3. 验收标准（每协议）

经该 outbound 代理请求 `http://api.ipify.org` → 返回 **`52.59.233.52`**（法兰克福出口 IP），HTTP 200。打洞 + 协议握手 + 传数据全通。

---

## 4. 关于后端「方案 A：按通道下发订阅」的边界说明

后端若走「`getAllSubscriptions()` 按通道分别下发 `subscribe_url`」路径:**realm 参数（本文档）是确定的**,但「subscribe_url 是否按通道分别下发、download 下来是否完整配置」属**后端订阅系统的下发逻辑 + 客户端 `importVPNConfig(from:)` 路径**,不在 otun-s/otun-kernel 范围,需后端/客户端 app 侧自行确认。本文档只负责:把这两台 PoC 节点的 realm 配置,给成 otun-kernel 认得的字段格式,供后端拼进下发内容。

---

## 5. 参数来源/失效说明

- 这些值来自当前在 `otun-s-out` 运行的节点配置（`/tmp/node-*.json`、`/tmp/reality-node.json`、`/tmp/otun-node.json`）。
- 若节点重启/换配置,realm_id/凭证可能变——以节点上实际配置为准,或让维护者重新导出。
- Reality `public_key` 由节点 `private_key`（`KEsi25VhCACjoLpAuEQLSoWBGvgEUICDon8gduUM70U`）配对推出。
- 字段定义权威来源:`otun-kernel/option/realm.go`（`RealmOptions`）。
