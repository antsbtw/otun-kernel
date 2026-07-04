# geosite/geoip rule-set 启动降级 — 内核组回复（§3 已做）

> 回应 `geosite/geoip 规则集：后端托管 + 内核启动降级（防变砖）` 的 §3（内核需求）。
> §1（前端 URL）+ §2（后端托管 .srs）不在内核范围 —— 仍需后端先托管,见原文档"上线顺序"。

---

## 已改（§3 根治"不启动"）✅

**`route/rule/rule_set_remote.go` `StartContext`**：初次 fetch 失败由**致命 return 改为 warn 降级**。

改前（变砖）:
```go
if s.lastUpdated.IsZero() {
    err = s.fetch(ctx, true)
    if err != nil {
        return E.Cause(err, "initial rule-set: ", s.options.Tag)  // ← 整个内核启动失败
    }
}
```
改后（降级）:
```go
if s.lastUpdated.IsZero() {
    err = s.fetch(ctx, true)
    if err != nil {
        s.logger.Warn(E.Cause(err, "initial rule-set (will retry, rule-set empty until then): ", s.options.Tag))
    }
}
```

**效果**（= 上游 `missing_behaviour: default`）:
- 初次下载失败 → rule-set 暂为空（其规则不匹配,内核照常启动,不崩）。
- `PostStart` 的 `loopUpdate` 继续每 `update_interval` 重试;且因 `lastUpdated` 仍为零,`loopUpdate` 启动时**立即**重试一次（line 201 `time.Since(zero) > interval`）。
- `cache_file` 覆盖正常情况 —— 只有"全新安装 + 首次下载失败"才触发降级,下次更新成功即恢复。
- 红线（同原文档）:降级期 CN 分流暂失效（流量可能走错向）,但**比变砖好**。

> 未加 `missing_behaviour` option 字段（原文档"可选"项）—— 当前以最小改动达成同等行为;若后续要对齐上游 option 语义可再补。

---

## 已验证（真机 CLI 复现）✅

内核 CLI + 一个指向**当前 404 的** `https://situstechnologies.com/rule-set/geosite-cn.srs`、**无 cache_file** 的配置:
```
WARN router: initial rule-set (will retry, rule-set empty until then): geosite-cn: unexpected status: 404 Not Found
INFO sing-box started (2.29s)        ← 没崩，服务起来
ERROR router: fetch rule-set geosite-cn: ... 404   ← loopUpdate 已在重试，非致命
```
改前这个 404 会是 `FATAL initial rule-set` → Extension 起不来。现在降级,内核正常启动。

---

## 产物（已含此修复 + 前两个 B3 修复）

新 `Libbox.xcframework`（`Jun 30 09:06`）已放 `otun-apple-build/Libbox.xcframework`,含:
- rule-set 启动降级（本文档）
- `underlay.LazyDialer`（B3 问题1:TUIC init FATAL）
- `otunrealm` punch dialer 隧道豁免（B3 问题2:0 流量）

前端从 `otun-apple-build/` 拉取替换 app 即可。

---

## 验收对照（原文档 §4 内核相关项）

- [x] 内核降级:rule_set URL 不可达 + 无缓存首启 → Extension 仍启动（实测 CLI,见上）。
- [ ] cache_file 成功一次后断网重启用缓存正常起 —— 此为既有行为（StartContext line 88-97 已加载缓存且不依赖网络）,前端真机可顺带确认。
- [ ] 后端 portal/v3test 托管 .srs 返回 200（§2,后端做）。
- [ ] 前端换 URL 后真机首次能下到 rule_set（§1+§2 落地后验）。
