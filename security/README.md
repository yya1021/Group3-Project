# security/ —— 第 7 周安全扫描工具包

对应任务书节点：**第 7 周 · SAST / DAST 与依赖扫描**，提交物为**基线报告**与**漏洞清单**。

本目录是一套可复现的扫描工具：不依赖第三方安全产品，纯 Node.js 实现（依赖扫描会调用 `npm audit`），
一键即可产出带真实证据的报告。

## 一键演示

```powershell
# 仓库根目录下双击运行，或在终端执行
scan.bat
```

该批处理会调用本目录的 `run-scan.ps1`，自动完成：
依赖检查 → 代理探测（供 npm audit 使用）→ 启动**沙箱服务** → SAST → 依赖扫描 → DAST → 生成报告，
结束后按任意键直接打开报告目录。

也可以直接调用 PowerShell 脚本（支持更多参数）：

```powershell
.\security\run-scan.ps1
```

> **沙箱机制**：DAST 阶段会以独立端口启动后端，并把 `DATA_DIR` / `UPLOADS_DIR` 指向系统临时目录，
> 因此扫描过程**不会改动仓库中的 `server/data/*.json` 与 `server/uploads/`**，扫描结束后临时目录会被删除。

### 常用变体

```powershell
.\security\run-scan.ps1 -Only sast,deps            # 只跑静态与依赖扫描（最快，无需启动服务）
.\security\run-scan.ps1 -Only dast                 # 只跑动态扫描（自动起沙箱服务）
.\security\run-scan.ps1 -Only dast -BaseUrl http://127.0.0.1:3000   # 扫描已在运行的服务
.\security\run-scan.ps1 -NoWriteProbes             # 跳过上传/目录穿越等写入型探针
```

直接使用 Node：

```powershell
node security/scan.js --only=sast,deps
node security/scan.js --only=dast --base-url=http://127.0.0.1:3000 --no-write-probes
```

## 产物

> 交付给老师的两份报告（基线报告、漏洞清单）请用**完整运行**（不带 `-Only`）生成，
> 这样报告中才包含 SAST / DAST / 依赖扫描三部分的完整结论。

| 文件 | 说明 |
| --- | --- |
| `reports/baseline-report.md` | 基线报告（范围、方法、结果概览、控制基线、修复排期、复现步骤、局限性） |
| `reports/vulnerability-list.md` | 漏洞清单（汇总表 + 逐条证据、影响与修复建议 + 控制有效性验证） |
| `reports/sast-results.json` | SAST 原始结果 |
| `reports/deps-results.json` | 依赖扫描原始结果 |
| `reports/dast-results.json` | DAST 原始结果（含每个探针的请求/响应证据） |
| `reports/scan-summary.json` | 三轮扫描的合并汇总 |
| `reports/findings.json` | 全部发现（去重、排序、统一编号） |

报告中的「交叉验证」列用于对照同一问题的**静态定位**与**动态复现**（例如 `SEC-UPLOAD-02` ↔ `DAST-UPLOAD-02`），
两者是同一缺陷的不同证据形态，不是重复上报。

## 目录结构

```
security/
├── run-scan.ps1            # 一键演示入口（Windows / PowerShell）
├── scan.js                 # 扫描编排器（CLI）
├── lib/
│   ├── findings.js         # 发现模型、严重度、去重排序
│   ├── report.js           # Markdown / 控制台报告渲染
│   ├── rules.js            # SAST 规则库（含 CWE 映射）
│   └── util.js             # 文件遍历、行号定位、版本比较等
└── scanners/
    ├── sast.js             # ① 静态扫描引擎
    ├── deps.js             # ② 依赖成分与已知漏洞扫描
    └── dast.js             # ③ 动态扫描引擎（真实 HTTP 探针）
```

## 三个扫描器分别在做什么

### ① SAST —— 静态应用安全测试

规则库见 [`lib/rules.js`](./lib/rules.js)，两类检测方式：

- **模式匹配**：定位危险 API/写法（如 `createHash('sha256')`、`cors()`、`path.join(uploadsDir, 用户输入)`），
  输出文件、行号与代码片段作为证据；
- **结构分析**：解析每个 `router.<method>('<path>', ...)` 声明的中间件链，
  自动找出「只校验登录、缺少权限校验」与「完全未鉴权」的路由。

每条命中都带 CWE 编号、置信度与修复建议；未命中的规则会在基线报告中作为**阴性结果**列出。

### ② 依赖成分与已知漏洞扫描

- 主数据源：`npm audit --json --registry=https://registry.npmjs.org/`
  （本机若使用 `npmmirror` 等镜像，其 `/security/advisories/bulk` 接口未实现，会返回 404，因此显式指定官方 registry）；
- 降级数据源：内置离线公告表（无网环境演示用，并在基线报告中记录降级原因，**不伪造数据**）；
- 会读取 `package-lock.json` 的 `dev` 标记，区分**生产依赖**与**仅开发依赖**，便于排定修复优先级。

### ③ DAST —— 动态应用安全测试

对真实运行中的服务发起 HTTP 请求，共 11 组探针：

| # | 探针 | 验证内容 |
| --- | --- | --- |
| 1 | 安全响应头 | `nosniff` / `X-Frame-Options` / CSP / Referrer-Policy 等是否缺失 |
| 2 | CORS | 携带任意 `Origin` 是否被放通 |
| 3 | 匿名访问 | 敏感接口在无令牌时是否返回业务数据 |
| 4 | 纵向越权 | 自行注册的普通用户能否调用管理/审核类接口 |
| 5 | 登录限速 | 连续失败登录是否触发 429/锁定 |
| 6 | 代理头伪造 | 伪造 `X-Forwarded-For` 是否被写入记录 |
| 7 | 不受限上传 | 上传 HTML 后能否被同源渲染（存储型 XSS） |
| 8 | 目录穿越 | 上传文件名含 `../` 是否越出上传目录落盘 |
| 9 | 异常处理 | 畸形请求是否回显堆栈 |
| 10 | 应用层加密强制性 | 明文请求能否绕过数字信封 |
| 11 | 控制回归验证 | 数字信封能否正常解封、防重放（409）与完整性校验（400）是否有效 |

> 探针 7 / 8 属于**写入型**探针，仅在目标为本地地址时执行，且探针文件会被立即清理并记录在证据中；
> 对远程目标会自动跳过（可用 `-NoWriteProbes` 显式关闭）。

第 11 组探针**复用项目前端自身的信封实现**（`client/src/api/envelope.js`）构造真实请求，
因此验证的是真实协议实现，而不是自研的近似实现。

## 合规与安全说明

- 只扫描本仓库自身代码与本机沙箱实例；`-BaseUrl` 指向外部目标前请确认已获得授权。
- 扫描不会写入凭证、不会修改被测代码；写入型探针仅创建临时文件并在同一轮内删除。
- 报告中所有证据均来自真实执行结果；若某个扫描器无法运行，报告会记录原始报错并降级，不会编造结论。
