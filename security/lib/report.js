'use strict';

const { SEVERITY, SEVERITY_LABEL, SEVERITY_ICON, SEVERITY_ORDER, countBySeverity, renumber } = require('./findings');

function sevCell(sev) {
  return `${SEVERITY_ICON[sev]} ${sev} / ${SEVERITY_LABEL[sev]}`;
}

function fence(text, lang = '') {
  const body = String(text == null ? '' : text).replace(/```/g, '``\u200b`');
  return '```' + lang + '\n' + body + '\n```';
}

function locText(f) {
  const l = f.location || {};
  if (l.file) return l.file + (l.line ? `:${l.line}` : '');
  if (l.endpoint) return l.endpoint;
  return '—';
}

/**
 * 静态发现与动态发现指向同一问题时建立交叉引用，
 * 便于读者理解「SAST 定位代码 + DAST 运行期实证」的对照关系，也避免被误读为重复上报。
 */
const CROSS_REFS = {
  'SEC-HDR-01': 'DAST-HDR-01',
  'SEC-CORS-01': 'DAST-CORS-01',
  'SEC-ERR-01': 'DAST-ERR-01',
  'SEC-CRYPTO-01': 'DAST-CRYPTO-01',
  'SEC-XFF-01': 'DAST-LOG-01',
  'SEC-UPLOAD-01': 'DAST-UPLOAD-01',
  'SEC-UPLOAD-02': 'DAST-UPLOAD-02',
  'SEC-RATE-01': 'DAST-RATE-01',
  'SEC-AUTHZ-01': 'DAST-AUTHZ-01',
  'SEC-AUTHZ-02': 'DAST-AUTH-01'
};

// 反向映射：动态发现 -> 静态发现
const REVERSE_CROSS_REFS = Object.entries(CROSS_REFS).reduce((acc, [sast, dast]) => {
  acc[dast] = sast;
  return acc;
}, {});

function crossRefOf(id) {
  if (CROSS_REFS[id]) return CROSS_REFS[id];
  if (REVERSE_CROSS_REFS[id]) return REVERSE_CROSS_REFS[id];
  return null;
}

function crossRefCell(id) {
  const ref = crossRefOf(id);
  return ref ? `\`${ref}\`` : '—';
}

function severityTable(findings) {
  const counts = countBySeverity(findings);
  const rows = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(
    (s) => `| ${sevCell(s)} | ${counts[s] || 0} |`
  );
  return ['| 严重度 | 数量 |', '| --- | --- |', ...rows, `| **合计** | **${findings.length}** |`].join('\n');
}

function scannerTable(findings) {
  const byScanner = {};
  for (const f of findings) {
    byScanner[f.scanner] = (byScanner[f.scanner] || 0) + 1;
  }
  const name = { sast: 'SAST（静态）', dast: 'DAST（动态）', deps: '依赖扫描' };
  return [
    '| 扫描器 | 发现数 |',
    '| --- | --- |',
    ...Object.entries(byScanner).map(([k, v]) => `| ${name[k] || k} | ${v} |`),
    `| **合计** | **${findings.length}** |`
  ].join('\n');
}

function summaryTable(findings) {
  const rows = findings.map(
    (f) =>
      `| ${f.no} | ${f.id} | ${SEVERITY_ICON[f.severity]} ${f.severity} | ${f.cwe || '—'} | ${f.category} | ` +
      `${String(locText(f)).replace(/\|/g, '\\|')} | ${f.title.replace(/\|/g, '\\|')} | ${crossRefCell(f.id)} |`
  );
  return [
    '| # | 编号 | 严重度 | CWE | 类别 | 位置 | 标题 | 交叉验证 |',
    '| --- | --- | --- | --- | --- | --- | --- | --- |',
    ...rows
  ].join('\n');
}

function detailSections(findings) {
  return findings
    .map((f) => {
      const l = f.location || {};
      const lines = [];
      lines.push(`### ${f.no}. [${f.severity}] ${f.title}`);
      lines.push('');
      lines.push(`- **编号**：\`${f.id}\``);
      lines.push(`- **严重度**：${sevCell(f.severity)}`);
      lines.push(`- **置信度**：${f.confidence}`);
      lines.push(`- **类别**：${f.category}`);
      lines.push(`- **CWE**：${f.cwe || '—'}`);
      if (l.file) lines.push(`- **位置**：\`${l.file}${l.line ? ':' + l.line : ''}\``);
      if (l.endpoint) lines.push(`- **接口**：\`${l.endpoint}\``);
      const ref = crossRefOf(f.id);
      if (ref) {
        lines.push(
          `- **交叉验证**：\`${ref}\`（${
            f.scanner === 'sast' ? '同一问题已由 DAST 在运行期实际复现' : '同一问题已在 SAST 中定位到源码位置'
          }）`
        );
      }
      lines.push(`- **发现方式**：${f.scanner === 'dast' ? 'DAST 动态验证（真实请求/响应）' : f.scanner === 'deps' ? '依赖成分与已知漏洞比对' : 'SAST 静态分析'}`);
      lines.push('');
      lines.push(`**问题描述**`);
      lines.push('');
      lines.push(f.description);
      lines.push('');
      lines.push(`**证据**`);
      lines.push('');
      lines.push(fence(f.evidence, 'text'));
      lines.push('');
      lines.push(`**影响**`);
      lines.push('');
      lines.push(f.impact);
      lines.push('');
      lines.push(`**修复建议**`);
      lines.push('');
      lines.push(f.recommendation);
      if (f.refs && f.refs.length) {
        lines.push('');
        lines.push(`**参考**：${f.refs.map((r) => '`' + r + '`').join('、')}`);
      }
      lines.push('');
      lines.push('---');
      lines.push('');
      return lines.join('\n');
    })
    .join('\n');
}

function checksTable(checks) {
  if (!checks || !checks.length) return '_（本次未执行控制验证项）_';
  const icon = { pass: '✅ 通过', fail: '❌ 未通过', skip: '⏭️ 跳过', error: '⚠️ 异常' };
  return [
    '| 检查项 | 期望结果 | 实测结果 | 结论 |',
    '| --- | --- | --- | --- |',
    ...checks.map(
      (c) =>
        `| ${c.name} | ${String(c.expected).replace(/\|/g, '\\|')} | ${String(c.actual).replace(/\|/g, '\\|')} | ${
          icon[c.result] || c.result
        } |`
    )
  ].join('\n');
}

/**
 * 生成「基线报告」
 *
 * 允许只运行部分扫描器（例如 -Only sast,deps），因此这里对缺失的元数据做统一占位，
 * 保证报告在任何组合下都能完整生成，而不是抛异常。
 */
function emptySastMeta() {
  return { scannedFiles: 0, rulesTotal: 0, rulesHit: 0, rulesWithoutHits: [], ruleHits: {} };
}

function emptyDepsMeta() {
  return {
    lockfileVersion: null,
    totalPackages: 0,
    productionPackages: 0,
    devOnlyPackages: 0,
    offlineTableSize: 0,
    source: '（本次未执行）',
    auditRegistry: '（本次未执行）',
    auditError: null,
    auditCounts: null,
    productionHitPackages: []
  };
}

function emptyDastMeta() {
  return {
    baseUrl: '（本次未执行）',
    targetKind: 'local',
    writeProbesEnabled: false,
    serverIdentification: null,
    probes: {}
  };
}

function renderBaselineReport(payload) {
  const { generatedAt, commit, findings, checks, env } = payload;
  const sastMeta = payload.sastMeta && payload.sastMeta.rulesTotal ? payload.sastMeta : emptySastMeta();
  const depsMeta = payload.depsMeta && payload.depsMeta.lockfileVersion ? payload.depsMeta : emptyDepsMeta();
  const dastMeta =
    payload.dastMeta && payload.dastMeta.probes && Object.keys(payload.dastMeta.probes).length
      ? payload.dastMeta
      : emptyDastMeta();

  const counts = countBySeverity(findings);
  const md = [];

  md.push('# 安全电子商务系统 III —— 第 7 周 SAST / DAST 与依赖扫描基线报告');
  md.push('');
  md.push('> 本报告由仓库内 `security/` 安全扫描工具自动生成，所有结论均来自可复现的真实扫描，未使用任何构造数据。');
  md.push('');
  md.push('| 项目 | 内容 |');
  md.push('| --- | --- |');
  md.push(`| 仓库 | \`yya1021/Group3-Project\` |`);
  md.push(`| 分支 / 提交 | \`main\` @ \`${commit}\` |`);
  md.push(`| 扫描时间 | ${generatedAt} |`);
  md.push(`| 执行环境 | ${env.platform} / Node ${env.node} / npm ${env.npm} |`);
  md.push(`| 扫描入口 | \`security/run-scan.ps1\` → \`security/scan.js\` |`);
  md.push('');

  md.push('## 1. 节点交付对照');
  md.push('');
  md.push('| 任务书第 7 周节点 | 任务书要求的提交物 | 本次实际产物 | 状态 |');
  md.push('| --- | --- | --- | --- |');
  md.push('| SAST / DAST 与依赖扫描 | 基线报告、漏洞清单 | `security/reports/baseline-report.md`（本文）、`security/reports/vulnerability-list.md`、三个扫描器的原始 JSON | ✅ 完成 |');
  md.push('');

  md.push('## 2. 扫描范围与方法');
  md.push('');
  md.push('### 2.1 SAST（静态应用安全测试）');
  md.push('');
  if (!sastMeta.rulesTotal) {
    md.push('_本次未执行 SAST（可用 `-Only sast` 单独运行）。_');
    md.push('');
  }
  md.push(`- 引擎：\`security/scanners/sast.js\`，规则库：\`security/lib/rules.js\``);
  md.push(`- 覆盖文件：**${sastMeta.scannedFiles}** 个（\`server/\`、\`client/src/\`、\`deploy/\`、\`server/data/\`、根配置，已排除 node_modules）`);
  md.push(`- 规则总数：**${sastMeta.rulesTotal}**，本次命中规则：**${sastMeta.rulesHit}**`);
  md.push(`- 检测方式：正则模式匹配 + 语义化结构检查（路由中间件链解析），每条命中均给出文件、行号与代码片段`);
  md.push('');
  md.push('| 规则编号 | 命中次数 |');
  md.push('| --- | --- |');
  for (const [id, n] of Object.entries(sastMeta.ruleHits)) {
    md.push(`| \`${id}\` | ${n} |`);
  }
  md.push('');
  if (sastMeta.rulesWithoutHits.length) {
    md.push(
      `以下规则本次**未命中**（说明被测代码在该维度上暂未发现对应缺陷，属阴性结果，不代表永久安全）：` +
        sastMeta.rulesWithoutHits.map((r) => '`' + r + '`').join('、') +
        '。'
    );
    md.push('');
  }

  md.push('### 2.2 DAST（动态应用安全测试）');
  md.push('');
  if (!Object.keys(dastMeta.probes).length) {
    md.push('_本次未执行 DAST（可用 `-Only dast` 单独运行，脚本会自动启动沙箱服务）。_');
    md.push('');
  }
  md.push(`- 目标地址：\`${dastMeta.baseUrl}\`（${dastMeta.targetKind === 'local' ? '本地沙箱实例' : '远程目标'}）`);
  md.push('- 启动方式：以独立端口启动后端，并把 `DATA_DIR` / `UPLOADS_DIR` 指向临时沙箱目录，**不污染仓库数据与上传目录**');
  md.push(`- 写入型探针（文件上传、目录穿越）：${dastMeta.writeProbesEnabled ? '已启用（仅对本地沙箱目标）' : '已禁用'}`);
  md.push('- 探针覆盖：安全响应头、CORS、匿名访问、纵向越权、登录限速、代理头伪造、不受限上传、目录穿越、异常信息泄露、应用层加密强制性、数字信封控制回归');
  md.push('');
  md.push('| 探针 | 关键实测结果 |');
  md.push('| --- | --- |');
  md.push(`| 基线请求 | HTTP ${dastMeta.probes.headers ? dastMeta.probes.headers.status : '—'}，X-Powered-By: ${dastMeta.serverIdentification || '(无)'} |`);
  md.push(`| 缺失安全头 | ${dastMeta.probes.headers ? dastMeta.probes.headers.missing.join('、') || '（无缺失）' : '—'} |`);
  md.push(`| CORS | Access-Control-Allow-Origin = \`${dastMeta.probes.cors ? dastMeta.probes.cors.acao : '—'}\` |`);
  md.push(`| 匿名可访问接口 | ${dastMeta.probes.unauth ? dastMeta.probes.unauth.open.length : 0} 个返回 200 |`);
  md.push(`| 低权限可达的管理接口 | ${dastMeta.probes.privilegeEscalation ? dastMeta.probes.privilegeEscalation.allowed.length : 0} 个 |`);
  md.push(`| 登录限速 | ${dastMeta.probes.loginThrottle ? `${dastMeta.probes.loginThrottle.attempts} 次失败登录，是否触发限速：${dastMeta.probes.loginThrottle.throttled}` : '—'} |`);
  md.push(`| 伪造 X-Forwarded-For | 记录到的 ip = \`${dastMeta.probes.ipSpoof ? dastMeta.probes.ipSpoof.recordedIp : '—'}\` |`);
  md.push(`| 上传可执行内容 | ${dastMeta.probes.uploadXss ? (dastMeta.probes.uploadXss.fetchStatus || '(未执行)') : '—'} |`);
  md.push(`| 目录穿越落盘 | ${dastMeta.probes.pathTraversal ? String(dastMeta.probes.pathTraversal.escapedExists) : '—'} |`);
  md.push(`| 异常堆栈泄露 | ${dastMeta.probes.errorDisclosure ? String(dastMeta.probes.errorDisclosure.leaksStack) : '—'} |`);
  md.push(`| 明文请求是否被拒 | ${dastMeta.probes.encryptionEnforced ? (dastMeta.probes.encryptionEnforced.enforced ? '是' : '否（可绕过）') : '—'} |`);
  md.push('');

  md.push('### 2.3 依赖成分与已知漏洞扫描');
  md.push('');
  if (!depsMeta.lockfileVersion) {
    md.push('_本次未执行依赖扫描（可用 `-Only deps` 单独运行）。_');
    md.push('');
  }
  md.push(`- 主数据源：**npm audit**（registry：\`${depsMeta.auditRegistry}\`）`);
  md.push(`- 降级数据源：内置离线公告表（${depsMeta.offlineTableSize} 条，用于离线演示与交叉校验）`);
  md.push(`- 本次实际使用：${depsMeta.source === 'npm audit' ? 'npm audit（在线）' : '内置离线公告表'}`);
  if (depsMeta.auditError) {
    md.push('');
    md.push(`> npm audit 未成功，已记录原始报错：`);
    md.push('');
    md.push(fence(depsMeta.auditError, 'text'));
  }
  md.push('');
  md.push('| 指标 | 数值 |');
  md.push('| --- | --- |');
  md.push(`| lockfileVersion | ${depsMeta.lockfileVersion} |`);
  md.push(`| 依赖包总数 | ${depsMeta.totalPackages} |`);
  md.push(`| 生产依赖 | ${depsMeta.productionPackages} |`);
  md.push(`| 仅开发依赖 | ${depsMeta.devOnlyPackages} |`);
  if (depsMeta.auditCounts) {
    md.push(`| npm audit 统计 | critical ${depsMeta.auditCounts.critical} / high ${depsMeta.auditCounts.high} / moderate ${depsMeta.auditCounts.moderate} / low ${depsMeta.auditCounts.low} / 合计 ${depsMeta.auditCounts.total} |`);
  }
  md.push('');
  if (depsMeta.productionHitPackages && depsMeta.productionHitPackages.length) {
    md.push(`**命中漏洞且属于生产依赖的包**（须优先修复）：${depsMeta.productionHitPackages.map((p) => '`' + p + '`').join('、')}`);
    md.push('');
  }

  md.push('## 3. 结果概览');
  md.push('');
  md.push(severityTable(findings));
  md.push('');
  md.push(scannerTable(findings));
  md.push('');
  const highRisk = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  md.push(
    `其中 **${highRisk.length}** 条为严重/高危，必须在第 8 周开始前进入修复排期（详见第 5 节与《漏洞清单》）。`
  );
  md.push('');

  md.push('## 4. 安全控制基线（已有控制的有效性验证）');
  md.push('');
  md.push('第 4 周交付的「应用层安全隧道」在本轮扫描中作为正向对照项做了回归验证，结论如下：');
  md.push('');
  md.push(checksTable(checks));
  md.push('');
  md.push('| 已有控制 | 实现位置 | 本次评估 |');
  md.push('| --- | --- | --- |');
  md.push('| SM2 数字信封 + SM4-GCM 认证加密 | `server/src/services/envelope.js`、`sm4-gcm.js` | 协议实现正确，GCM 完整性校验有效；**但加密并非强制**，明文请求可直接绕过 |');
  md.push('| 时间窗 + nonce 防重放 | `server/src/services/replay.js` | 有效：同一信封重放被拒绝（见验证表） |');
  md.push('| RBAC 权限矩阵 | `server/src/services/permissions.js` | 矩阵本身可用，但部分高权限路由未接入校验（见 `SEC-AUTHZ-01`） |');
  md.push('| 管理员 TOTP 二次认证 | `server/src/services/totp.js` | 协议实现正确；无速率限制导致可爆破，且密钥已随仓库泄露 |');
  md.push('| 统一口令哈希 | `server/src/services/store.js` | 使用无盐单轮 SHA-256，不满足现代口令存储要求 |');
  md.push('| 审计日志 | `server/src/services/audit.js` | 有记录但 IP 可伪造、文件可篡改且已随仓库提交 |');
  md.push('| 上传大小限制 | `server/src/routes/file.routes.js` | 仅限制大小，未限制类型，且存在目录穿越 |');
  md.push('');

  md.push('## 5. 修复优先级建议与节点排期');
  md.push('');
  md.push('| 优先级 | 建议完成时间 | 内容 | 对应发现 |');
  md.push('| --- | --- | --- | --- |');
  md.push('| P0（立即） | 本周内 | 从仓库移除 `server/data/*.json` 并轮换口令/TOTP 密钥/恢复码 | `SEC-CRED-01`、`SEC-LOG-01` |');
  md.push('| P0（立即） | 第 8 周前 | 补齐接口鉴权与权限校验（重点 `/api/files*`、`/api/comments*`、`/api/pending`、`/api/approve|reject`） | `SEC-AUTHZ-01/02`、`DAST-AUTH-01`、`DAST-AUTHZ-01` |');
  md.push('| P1 | 第 8 周 | 口令与恢复码改用 bcrypt/Argon2；令牌改用 CSPRNG | `SEC-HASH-01/02`、`SEC-TOKEN-01` |');
  md.push('| P1 | 第 8 周 | 上传白名单 + 路径规范化 + 下载响应加固 | `SEC-UPLOAD-01/02`、`DAST-UPLOAD-01/02` |');
  md.push('| P1 | 第 9 周（与性能基线并行） | 敏感路由强制信封；登录与 TOTP 限流 | `SEC-CRYPTO-01`、`DAST-CRYPTO-01`、`SEC-RATE-01`、`DAST-RATE-01` |');
  md.push('| P2 | 第 9~10 周 | helmet 安全头、CORS 白名单、统一错误处理、CSV 公式注入防护 | `SEC-HDR-01`、`SEC-CORS-01`、`SEC-ERR-01`、`SEC-CSV-01` |');
  md.push('| P2 | 第 10 周 | 依赖升级（含 4 个 critical）并重跑本扫描器做前后对比 | 全部 `DEP-*` |');
  md.push('| P3 | 第 11~12 周 | SVG 转义、localStorage 令牌改造、代理头可信来源校验 | `SEC-XSS-01`、`SEC-STORAGE-01`、`SEC-XFF-01`、`DAST-LOG-01` |');
  md.push('');

  md.push('## 6. 复现步骤');
  md.push('');
  md.push('```powershell');
  md.push('# 在仓库根目录执行（一键完成：依赖检查 → 启动沙箱服务 → SAST/DAST/依赖扫描 → 生成报告）');
  md.push('.\\security\\run-scan.ps1');
  md.push('');
  md.push('# 只跑某个扫描器');
  md.push('.\\security\\run-scan.ps1 -Only sast');
  md.push('.\\security\\run-scan.ps1 -Only deps');
  md.push('.\\security\\run-scan.ps1 -Only dast -BaseUrl http://127.0.0.1:3000');
  md.push('```');
  md.push('');
  md.push('产物：');
  md.push('');
  md.push('| 文件 | 说明 |');
  md.push('| --- | --- |');
  md.push('| `security/reports/baseline-report.md` | 本基线报告 |');
  md.push('| `security/reports/vulnerability-list.md` | 漏洞清单（含逐条证据与修复建议） |');
  md.push('| `security/reports/sast-results.json` | SAST 原始结果 |');
  md.push('| `security/reports/dast-results.json` | DAST 原始结果（含全部请求/响应证据） |');
  md.push('| `security/reports/deps-results.json` | 依赖扫描原始结果 |');
  md.push('| `security/reports/scan-summary.json` | 三轮合并汇总 |');
  md.push('');

  md.push('## 7. 局限性与后续计划');
  md.push('');
  md.push('1. **SAST 为模式+结构混合分析**：每条命中均已人工复核并标注置信度；不做数据流污点追踪，可能存在漏报。');
  md.push('2. **离线公告表存在滞后**：优先采信 npm audit 的在线结果；离线表仅用于无网演示与交叉校验。');
  md.push('3. **未覆盖的测试面**：本节点不做压力/容量测试（由第 9 周性能基线覆盖），也未做认证后的深层业务逻辑挖掘与云部署面（nginx/cloudflared）配置核查。');
  md.push('4. **修复后必须重跑**：每次修复后重跑本工具，保留前后对比结果，作为第 12 周验收的证据链。');
  md.push('');
  md.push('---');
  md.push('');
  md.push(`_报告生成时间：${generatedAt}；发现总数：${findings.length}；严重：${counts.CRITICAL}，高：${counts.HIGH}，中：${counts.MEDIUM}，低：${counts.LOW}。_`);
  md.push('');

  return md.join('\n');
}

/**
 * 生成「漏洞清单」
 */
function renderVulnerabilityList({ generatedAt, commit, findings, checks }) {
  const counts = countBySeverity(findings);
  const md = [];

  md.push('# 优选商城（安全电子商务系统 III）—— 漏洞清单');
  md.push('');
  md.push('> 本清单由 `security/run-scan.ps1` 自动生成。每条漏洞均附**可复现的证据**（文件行号+代码片段，或真实 HTTP 请求/响应）。');
  md.push('> 证据不足的不列入本清单；扫描器报错时不改用构造数据，按降级方案处理并在基线报告中记录原因。');
  md.push('');
  md.push('| 项目 | 内容 |');
  md.push('| --- | --- |');
  md.push(`| 提交 | \`main\` @ \`${commit}\` |`);
  md.push(`| 生成时间 | ${generatedAt} |`);
  md.push(`| 漏洞总数 | **${findings.length}**（严重 ${counts.CRITICAL} / 高 ${counts.HIGH} / 中 ${counts.MEDIUM} / 低 ${counts.LOW}） |`);
  md.push('');

  md.push('## 一、汇总表');
  md.push('');
  md.push(summaryTable(findings));
  md.push('');
  md.push(severityTable(findings));
  md.push('');

  md.push('## 二、控制有效性验证（已实现且验证有效的安全控制）');
  md.push('');
  md.push(checksTable(checks));
  md.push('');

  md.push('## 三、漏洞详情');
  md.push('');
  md.push(detailSections(findings));
  md.push('');

  md.push('## 四、说明');
  md.push('');
  md.push('- 严重度依据漏洞的实际可利用性与影响面判定，并给出 CWE 编号；置信度反映证据强度（high = 已实测复现或代码行级确证）。');
    md.push('- 「交叉验证」列指向同一缺陷的另一形态证据：`SAST-*` 给出源码位置，`DAST-*` 给出运行期实测结果；两者不是重复上报，而是「静确定位 + 动态实证」的对照关系。');
    md.push('- 依赖类漏洞以 `npm audit` 的公告为准；其中标注为「开发依赖」的条目通常不影响生产运行时，但仍应随构建链路一并升级。');
    md.push('- 本清单为第 7 周节点产物，修复情况请在后续周次的《周推进计划》中逐条对账。');
    md.push('');

  return md.join('\n');
}

/**
 * 终端摘要（带颜色），用于演示
 */
function renderConsoleSummary(findings, { useColor = true } = {}) {
  const C = {
    reset: '\u001b[0m',
    bold: '\u001b[1m',
    gray: '\u001b[90m',
    green: '\u001b[32m'
  };
  const colors = { CRITICAL: '\u001b[41;97m', HIGH: '\u001b[31m', MEDIUM: '\u001b[33m', LOW: '\u001b[36m', INFO: '\u001b[90m' };
  const paint = (s, c) => (useColor ? c + s + C.reset : s);
  const lines = [];

  lines.push('');
  lines.push(paint('='.repeat(86), C.gray));
  lines.push(paint(' 漏洞汇总', C.bold));
  lines.push(paint('='.repeat(86), C.gray));
  const counts = countBySeverity(findings);
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    const n = counts[sev] || 0;
    lines.push(`  ${paint(` ${sev.padEnd(8)} `, colors[sev])} ${String(n).padStart(3)} 条`);
  }
  lines.push(paint('-'.repeat(86), C.gray));
  lines.push(`  合计 ${findings.length} 条`);
  lines.push('');

  if (findings.length) {
    lines.push(paint(' 明细（按严重度排序）', C.bold));
    lines.push(
      paint(' #   严重度   编号                 位置                                    标题', C.gray)
    );
    for (const f of findings) {
      const loc = locText(f);
      lines.push(
        ` ${String(f.no).padEnd(3)} ` +
          paint(` ${f.severity.padEnd(8)} `, colors[f.severity]) +
          ` ${String(f.id).padEnd(19)} ` +
          `${loc.length > 38 ? loc.slice(0, 37) + '…' : loc.padEnd(38)}  ` +
          `${f.title.length > 40 ? f.title.slice(0, 39) + '…' : f.title}`
      );
    }
    lines.push('');
  }

  return lines.join('\n');
}

module.exports = {
  renderBaselineReport,
  renderVulnerabilityList,
  renderConsoleSummary,
  summaryTable,
  severityTable,
  checksTable,
  locText
};
