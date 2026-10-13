# 安全电子商务系统 III —— 第 7 周 SAST / DAST 与依赖扫描基线报告

> 本报告由仓库内 `security/` 安全扫描工具自动生成，所有结论均来自可复现的真实扫描，未使用任何构造数据。

| 项目 | 内容 |
| --- | --- |
| 仓库 | `yya1021/Group3-Project` |
| 分支 / 提交 | `main` @ `880c27d` |
| 扫描时间 | 2026-10-12T09:23:08+08:00 |
| 执行环境 | win32 x64 / Node v24.4.1 / npm 11.4.2 |
| 扫描入口 | `security/run-scan.ps1` → `security/scan.js` |

## 1. 节点交付对照

| 任务书第 7 周节点 | 任务书要求的提交物 | 本次实际产物 | 状态 |
| --- | --- | --- | --- |
| SAST / DAST 与依赖扫描 | 基线报告、漏洞清单 | `security/reports/baseline-report.md`（本文）、`security/reports/vulnerability-list.md`、三个扫描器的原始 JSON | ✅ 完成 |

## 2. 扫描范围与方法

### 2.1 SAST（静态应用安全测试）

- 引擎：`security/scanners/sast.js`，规则库：`security/lib/rules.js`
- 覆盖文件：**81** 个（`server/`、`client/src/`、`deploy/`、`server/data/`、根配置，已排除 node_modules）
- 规则总数：**22**，本次命中规则：**22**
- 检测方式：正则模式匹配 + 语义化结构检查（路由中间件链解析），每条命中均给出文件、行号与代码片段

| 规则编号 | 命中次数 |
| --- | --- |
| `SEC-CRED-01` | 9 |
| `SEC-CRED-02` | 1 |
| `SEC-CRED-03` | 2 |
| `SEC-HASH-01` | 1 |
| `SEC-HASH-02` | 1 |
| `SEC-TOKEN-01` | 1 |
| `SEC-AUTH-01` | 2 |
| `SEC-CRYPTO-01` | 1 |
| `SEC-XFF-01` | 1 |
| `SEC-UPLOAD-01` | 1 |
| `SEC-UPLOAD-02` | 1 |
| `SEC-XSS-01` | 1 |
| `SEC-CORS-01` | 1 |
| `SEC-HDR-01` | 1 |
| `SEC-ERR-01` | 1 |
| `SEC-DOS-01` | 1 |
| `SEC-RATE-01` | 1 |
| `SEC-CSV-01` | 1 |
| `SEC-STORAGE-01` | 1 |
| `SEC-AUTHZ-01` | 10 |
| `SEC-AUTHZ-02` | 3 |
| `SEC-LOG-01` | 1 |

### 2.2 DAST（动态应用安全测试）

- 目标地址：`http://127.0.0.1:59822`（本地沙箱实例）
- 启动方式：以独立端口启动后端，并把 `DATA_DIR` / `UPLOADS_DIR` 指向临时沙箱目录，**不污染仓库数据与上传目录**
- 写入型探针（文件上传、目录穿越）：已启用（仅对本地沙箱目标）
- 探针覆盖：安全响应头、CORS、匿名访问、纵向越权、登录限速、代理头伪造、不受限上传、目录穿越、异常信息泄露、应用层加密强制性、数字信封控制回归

| 探针 | 关键实测结果 |
| --- | --- |
| 基线请求 | HTTP 200，X-Powered-By: Express |
| 缺失安全头 | x-content-type-options、x-frame-options、content-security-policy、referrer-policy、permissions-policy |
| CORS | Access-Control-Allow-Origin = `*` |
| 匿名可访问接口 | 1 个返回 200 |
| 低权限可达的管理接口 | 8 个 |
| 登录限速 | 12 次失败登录，是否触发限速：false |
| 伪造 X-Forwarded-For | 记录到的 ip = `203.0.113.66` |
| 上传可执行内容 | 200 |
| 目录穿越落盘 | true |
| 异常堆栈泄露 | true |
| 明文请求是否被拒 | 否（可绕过） |

### 2.3 依赖成分与已知漏洞扫描

- 主数据源：**npm audit**（registry：`https://registry.npmjs.org/`）
- 降级数据源：内置离线公告表（11 条，用于离线演示与交叉校验）
- 本次实际使用：npm audit（在线）

| 指标 | 数值 |
| --- | --- |
| lockfileVersion | 3 |
| 依赖包总数 | 255 |
| 生产依赖 | 98 |
| 仅开发依赖 | 157 |
| npm audit 统计 | critical 4 / high 4 / moderate 5 / low 0 / 合计 13 |

**命中漏洞且属于生产依赖的包**（须优先修复）：`@vue/server-renderer`、`body-parser`、`express`、`proxy-addr`、`qs`、`source-map-js`、`vue`

## 3. 结果概览

| 严重度 | 数量 |
| --- | --- |
| 🔴 CRITICAL / 严重 | 5 |
| 🟠 HIGH / 高 | 20 |
| 🟡 MEDIUM / 中 | 19 |
| ⚪ LOW / 低 | 2 |
| 🔵 INFO / 提示 | 0 |
| **合计** | **46** |

| 扫描器 | 发现数 |
| --- | --- |
| 依赖扫描 | 13 |
| SAST（静态） | 22 |
| DAST（动态） | 11 |
| **合计** | **46** |

其中 **25** 条为严重/高危，必须在第 8 周开始前进入修复排期（详见第 5 节与《漏洞清单》）。

## 4. 安全控制基线（已有控制的有效性验证）

第 4 周交付的「应用层安全隧道」在本轮扫描中作为正向对照项做了回归验证，结论如下：

| 检查项 | 期望结果 | 实测结果 | 结论 |
| --- | --- | --- | --- |
| 注册演示账号 | 201 且返回 token | HTTP 201，已取得普通用户令牌 | ✅ 通过 |
| 上传内容安全 | 拒绝 HTML/SVG 等可执行类型；文件名不可穿越 | 存在不安全行为（见上方发现） | ❌ 未通过 |
| 数字信封可正常解封（复用项目前端实现） | HTTP 401（凭据错误，说明信封已被成功解密） | HTTP 401 {"success":false,"error":"用户名或密码错误"} | ✅ 通过 |
| 防重放（nonce 一次性） | HTTP 409（REPLAY） | HTTP 409 {"success":false,"error":"检测到重放请求","code":"REPLAY"} | ✅ 通过 |
| 完整性校验（AAD 绑定被篡改即拒绝） | HTTP 400（完整性或时间窗校验失败） | HTTP 400 {"success":false,"error":"密文解密或完整性校验失败","code":"INTEGRITY_FAILED"} | ✅ 通过 |

| 已有控制 | 实现位置 | 本次评估 |
| --- | --- | --- |
| SM2 数字信封 + SM4-GCM 认证加密 | `server/src/services/envelope.js`、`sm4-gcm.js` | 协议实现正确，GCM 完整性校验有效；**但加密并非强制**，明文请求可直接绕过 |
| 时间窗 + nonce 防重放 | `server/src/services/replay.js` | 有效：同一信封重放被拒绝（见验证表） |
| RBAC 权限矩阵 | `server/src/services/permissions.js` | 矩阵本身可用，但部分高权限路由未接入校验（见 `SEC-AUTHZ-01`） |
| 管理员 TOTP 二次认证 | `server/src/services/totp.js` | 协议实现正确；无速率限制导致可爆破，且密钥已随仓库泄露 |
| 统一口令哈希 | `server/src/services/store.js` | 使用无盐单轮 SHA-256，不满足现代口令存储要求 |
| 审计日志 | `server/src/services/audit.js` | 有记录但 IP 可伪造、文件可篡改且已随仓库提交 |
| 上传大小限制 | `server/src/routes/file.routes.js` | 仅限制大小，未限制类型，且存在目录穿越 |

## 5. 修复优先级建议与节点排期

| 优先级 | 建议完成时间 | 内容 | 对应发现 |
| --- | --- | --- | --- |
| P0（立即） | 本周内 | 从仓库移除 `server/data/*.json` 并轮换口令/TOTP 密钥/恢复码 | `SEC-CRED-01`、`SEC-LOG-01` |
| P0（立即） | 第 8 周前 | 补齐接口鉴权与权限校验（重点 `/api/files*`、`/api/comments*`、`/api/pending`、`/api/approve|reject`） | `SEC-AUTHZ-01/02`、`DAST-AUTH-01`、`DAST-AUTHZ-01` |
| P1 | 第 8 周 | 口令与恢复码改用 bcrypt/Argon2；令牌改用 CSPRNG | `SEC-HASH-01/02`、`SEC-TOKEN-01` |
| P1 | 第 8 周 | 上传白名单 + 路径规范化 + 下载响应加固 | `SEC-UPLOAD-01/02`、`DAST-UPLOAD-01/02` |
| P1 | 第 9 周（与性能基线并行） | 敏感路由强制信封；登录与 TOTP 限流 | `SEC-CRYPTO-01`、`DAST-CRYPTO-01`、`SEC-RATE-01`、`DAST-RATE-01` |
| P2 | 第 9~10 周 | helmet 安全头、CORS 白名单、统一错误处理、CSV 公式注入防护 | `SEC-HDR-01`、`SEC-CORS-01`、`SEC-ERR-01`、`SEC-CSV-01` |
| P2 | 第 10 周 | 依赖升级（含 4 个 critical）并重跑本扫描器做前后对比 | 全部 `DEP-*` |
| P3 | 第 11~12 周 | SVG 转义、localStorage 令牌改造、代理头可信来源校验 | `SEC-XSS-01`、`SEC-STORAGE-01`、`SEC-XFF-01`、`DAST-LOG-01` |

## 6. 复现步骤

```powershell
# 在仓库根目录执行（一键完成：依赖检查 → 启动沙箱服务 → SAST/DAST/依赖扫描 → 生成报告）
.\security\run-scan.ps1

# 只跑某个扫描器
.\security\run-scan.ps1 -Only sast
.\security\run-scan.ps1 -Only deps
.\security\run-scan.ps1 -Only dast -BaseUrl http://127.0.0.1:3000
```

产物：

| 文件 | 说明 |
| --- | --- |
| `security/reports/baseline-report.md` | 本基线报告 |
| `security/reports/vulnerability-list.md` | 漏洞清单（含逐条证据与修复建议） |
| `security/reports/sast-results.json` | SAST 原始结果 |
| `security/reports/dast-results.json` | DAST 原始结果（含全部请求/响应证据） |
| `security/reports/deps-results.json` | 依赖扫描原始结果 |
| `security/reports/scan-summary.json` | 三轮合并汇总 |

## 7. 局限性与后续计划

1. **SAST 为模式+结构混合分析**：每条命中均已人工复核并标注置信度；不做数据流污点追踪，可能存在漏报。
2. **离线公告表存在滞后**：优先采信 npm audit 的在线结果；离线表仅用于无网演示与交叉校验。
3. **未覆盖的测试面**：本节点不做压力/容量测试（由第 9 周性能基线覆盖），也未做认证后的深层业务逻辑挖掘与云部署面（nginx/cloudflared）配置核查。
4. **修复后必须重跑**：每次修复后重跑本工具，保留前后对比结果，作为第 12 周验收的证据链。

---

_报告生成时间：2026-10-12T09:23:08+08:00；发现总数：46；严重：5，高：20，中：19，低：2。_
