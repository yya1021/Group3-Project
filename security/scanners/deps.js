'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const util = require('../lib/util');
const { createFinding, dedupe, sortFindings, SEVERITY } = require('../lib/findings');

// npm audit 的严重度 -> 本项目严重度
const AUDIT_SEVERITY_MAP = {
  critical: SEVERITY.CRITICAL,
  high: SEVERITY.HIGH,
  moderate: SEVERITY.MEDIUM,
  low: SEVERITY.LOW,
  info: SEVERITY.INFO
};

// 依据公告标题关键词推断 CWE（无法判定时留空，不做臆测）
const CWE_KEYWORDS = [
  [/xss|cross-site scripting|attribute-name/i, 'CWE-79'],
  [/denial of service|\bDoS\b|event-loop/i, 'CWE-400'],
  [/path traversal|directory traversal/i, 'CWE-22'],
  [/prototype pollution/i, 'CWE-1321'],
  [/command injection/i, 'CWE-78'],
  [/remote code execution|\bRCE\b|arbitrary file can be read and executed/i, 'CWE-94'],
  [/ip spoofing/i, 'CWE-348'],
  [/open redirect/i, 'CWE-601'],
  [/regular expression|ReDoS|inefficient/i, 'CWE-1333'],
  [/ntlmv2|hash disclosure|credential/i, 'CWE-200'],
  [/cors|any website/i, 'CWE-942'],
  [/bypass/i, 'CWE-693']
];

function guessCwe(title) {
  for (const [rx, cwe] of CWE_KEYWORDS) {
    if (rx.test(title)) return cwe;
  }
  return '';
}

/**
 * 内置离线公告表（npm audit 不可用时的降级方案）。
 * 数据源：GitHub Advisory Database / NVD。表内仅收录可确证的公告，未收录不等于安全。
 * 说明：优先使用 npm audit 的在线结果，本表仅作离线兜底。
 */
const OFFLINE_ADVISORIES = [
  { name: 'express', introduced: '0.0.0', fixed: '4.19.2', severity: 'MEDIUM', advisory: 'CVE-2024-29041', cwe: 'CWE-601', title: 'Express 4.x 开放重定向（res.location/res.redirect 未编码 URL）' },
  { name: 'express', introduced: '0.0.0', fixed: '4.20.0', severity: 'MEDIUM', advisory: 'CVE-2024-43796', cwe: 'CWE-79', title: 'Express 4.x 通过 res.redirect 的 XSS' },
  { name: 'body-parser', introduced: '0.0.0', fixed: '1.20.3', severity: 'MEDIUM', advisory: 'CVE-2024-45590', cwe: 'CWE-400', title: 'body-parser 1.20.x urlencoded 解析 DoS' },
  { name: 'cookie', introduced: '0.0.0', fixed: '0.7.0', severity: 'LOW', advisory: 'CVE-2024-47764', cwe: 'CWE-74', title: 'cookie 包未校验 cookie 名/值中的控制字符' },
  { name: 'path-to-regexp', introduced: '0.0.0', fixed: '0.1.10', severity: 'HIGH', advisory: 'CVE-2024-45296', cwe: 'CWE-1333', title: 'path-to-regexp ReDoS（两个回溯点）' },
  { name: 'send', introduced: '0.0.0', fixed: '0.19.0', severity: 'MEDIUM', advisory: 'CVE-2024-43799', cwe: 'CWE-79', title: 'send 包模板注入导致 XSS' },
  { name: 'serve-static', introduced: '0.0.0', fixed: '1.16.0', severity: 'MEDIUM', advisory: 'CVE-2024-43800', cwe: 'CWE-79', title: 'serve-static 通过 redirect 导致 XSS' },
  { name: 'cross-spawn', introduced: '0.0.0', fixed: '7.0.5', severity: 'MEDIUM', advisory: 'CVE-2024-21538', cwe: 'CWE-1333', title: 'cross-spawn ReDoS（低效正则回溯）' },
  { name: 'micromatch', introduced: '0.0.0', fixed: '4.0.8', severity: 'MEDIUM', advisory: 'CVE-2024-4067', cwe: 'CWE-1333', title: 'micromatch ReDoS' },
  { name: 'braces', introduced: '0.0.0', fixed: '3.0.3', severity: 'MEDIUM', advisory: 'CVE-2024-4068', cwe: 'CWE-400', title: 'braces 大括号展开导致资源耗尽' },
  { name: 'esbuild', introduced: '0.0.0', fixed: '0.25.0', severity: 'MEDIUM', advisory: 'GHSA-67mh-4wv8-2f99', cwe: 'CWE-942', title: 'esbuild 开发服务器允许任意站点发起请求并读取响应' }
];

// 判断包是否为「仅开发依赖」（lockfile v3 的 dev 标记）
function buildScopeIndex(packages) {
  const scope = new Map();
  for (const [key, info] of Object.entries(packages)) {
    if (!key.startsWith('node_modules/')) continue;
    const name = key.slice('node_modules/'.length).split('node_modules/').pop();
    const isDev = info.dev === true;
    if (!scope.has(name)) scope.set(name, isDev);
    else if (!isDev) scope.set(name, false); // 只要有一处是生产依赖，即视为生产依赖
  }
  return scope;
}

// 在 package-lock.json 中定位包条目的行号（用于给出精确证据位置）
function findLockLine(lockText, name) {
  if (!lockText) return null;
  const needle = `"node_modules/${name}": {`;
  let idx = lockText.indexOf(needle);
  if (idx === -1) {
    const rx = new RegExp(`"node_modules/[^"]*node_modules/${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}": \\{`);
    const m = rx.exec(lockText);
    if (!m) return null;
    idx = m.index;
  }
  return lockText.slice(0, idx).split('\n').length;
}

function describeFix(fixAvailable) {
  if (fixAvailable === true) return '执行 `npm audit fix` 可在不破坏兼容的前提下升级。';
  if (fixAvailable === false) return '暂无可用修复版本，需要评估替代方案或隔离使用。';
  if (fixAvailable && typeof fixAvailable === 'object') {
    return `需要升级 ${fixAvailable.name} 到 ${fixAvailable.version}${fixAvailable.isSemVerMajor ? '（跨大版本，需回归测试）' : ''}。`;
  }
  return '未提供修复信息，请人工确认。';
}

/**
 * 执行依赖成分与已知漏洞扫描。
 * 主数据源：npm audit（在线，权威）；降级数据源：内置离线公告表。
 */
function runDeps({ rootDir, log = () => {}, auditRegistry = 'https://registry.npmjs.org/', proxyEnv = {} }) {
  const lockPath = path.join(rootDir, 'package-lock.json');
  const lock = util.readJson(lockPath);
  const lockText = util.readText(lockPath);

  if (!lock || !lock.packages) {
    return {
      findings: [],
      meta: { error: '未找到可解析的 package-lock.json（lockfileVersion 3 及以上）', auditAvailable: false }
    };
  }

  const packages = lock.packages;
  const scopeIndex = buildScopeIndex(packages);
  const allNames = Object.keys(packages)
    .filter((k) => k.startsWith('node_modules/'))
    .map((k) => k.slice('node_modules/'.length).split('node_modules/').pop());
  const uniqueNames = [...new Set(allNames)];

  log(`依赖扫描: package-lock.json 共 ${uniqueNames.length} 个包（lockfileVersion ${lock.lockfileVersion}）`);

  const findings = [];
  const productionHitNames = new Set();
  const meta = {
    lockfileVersion: lock.lockfileVersion,
    totalPackages: uniqueNames.length,
    productionPackages: uniqueNames.filter((n) => scopeIndex.get(n) === false).length,
    devOnlyPackages: uniqueNames.filter((n) => scopeIndex.get(n) === true).length,
    auditAvailable: false,
    auditRegistry,
    auditError: null,
    offlineTableSize: OFFLINE_ADVISORIES.length,
    source: 'offline-table'
  };

  // ---------- 1) 在线：npm audit ----------
  const auditEnv = { ...process.env, ...proxyEnv };
  const child = spawnSync(
    `npm audit --json --registry=${auditRegistry}`,
    [],
    { encoding: 'utf8', shell: true, cwd: rootDir, env: auditEnv, maxBuffer: 64 * 1024 * 1024 }
  );

  let auditJson = null;
  try {
    auditJson = JSON.parse(child.stdout || '');
  } catch (e) {
    auditJson = null;
  }

  if (auditJson && auditJson.vulnerabilities) {
    meta.auditAvailable = true;
    meta.source = 'npm audit';
    meta.auditCounts = auditJson.metadata && auditJson.metadata.vulnerabilities;
    log(
      `依赖扫描: npm audit 返回 ${meta.auditCounts ? meta.auditCounts.total : Object.keys(auditJson.vulnerabilities).length} 条公告` +
        `（critical ${meta.auditCounts ? meta.auditCounts.critical : '?'} / high ${meta.auditCounts ? meta.auditCounts.high : '?'}）`
    );

    for (const [name, vuln] of Object.entries(auditJson.vulnerabilities)) {
      const viaAdvisories = (vuln.via || []).filter((v) => typeof v === 'object');
      const viaDeps = (vuln.via || []).filter((v) => typeof v === 'string');
      const titles = viaAdvisories.map((v) => `${v.title}（${v.url}）`).join('; ');
      const severity = AUDIT_SEVERITY_MAP[vuln.severity] || SEVERITY.MEDIUM;
      const scope = scopeIndex.get(name) === true ? '开发依赖' : '生产依赖';
      if (scope === '生产依赖') productionHitNames.add(name);

      findings.push(
        createFinding({
          id: `DEP-${name}`,
          title: `依赖组件已知漏洞：${name}@${(packages[`node_modules/${name}`] || {}).version || vuln.range}`,
          severity,
          cwe: guessCwe(viaAdvisories.map((v) => v.title).join(' ') || '') || '',
          category: '第三方组件漏洞',
          scanner: 'deps',
          confidence: 'high',
          location: {
            file: 'package-lock.json',
            line: findLockLine(lockText, name),
            endpoint: undefined
          },
          description:
            `npm audit 报告的受影响版本范围：${vuln.range}；影响层级：${scope}。` +
            (viaDeps.length ? ` 通过依赖链引入：${viaDeps.join(' / ')}。` : ''),
          evidence:
            `公告：${titles || '（npm audit 未给出公告标题）'}\n` +
            `当前解析版本：${(packages[`node_modules/${name}`] || {}).version || '（见 lock 内嵌路径）'}\n` +
            `严重度：${vuln.severity}；修复建议：${describeFix(vuln.fixAvailable)}`,
          impact:
            scope === '开发依赖'
              ? '仅影响本地开发/构建环节，生产镜像中通常不包含该依赖；但仍会污染 CI 与开发者工位。'
              : '属于生产运行时依赖，漏洞可被外部请求直接触达，需优先修复。',
          recommendation: describeFix(vuln.fixAvailable) + ' 修复后请重跑依赖扫描并保留前后对比。',
          refs: [
            `npm audit --registry=${auditRegistry}`,
            ...viaAdvisories.map((v) => v.url).filter(Boolean)
          ]
        })
      );
    }
  } else {
    meta.auditError = (child.stderr || child.stdout || '未知错误').toString().trim().slice(0, 500);
    log(`依赖扫描: npm audit 不可用，降级使用离线公告表。原因：${meta.auditError.split('\n')[0]}`);
  }

  // ---------- 2) 离线公告表（始终执行，作为交叉校验/降级） ----------
  let offlineHits = 0;
  for (const adv of OFFLINE_ADVISORIES) {
    const entryKey = Object.keys(packages).find(
      (k) => k.startsWith('node_modules/') && k === `node_modules/${adv.name}`
    );
    if (!entryKey) continue;
    const version = packages[entryKey].version;
    if (!version || !util.inVulnRange(version, adv.introduced, adv.fixed)) continue;
    offlineHits++;
    if (scopeIndex.get(adv.name) !== true) productionHitNames.add(adv.name);

    // 若在线结果已覆盖同包同公告，则跳过避免重复
    const already = findings.some((f) => f.id === `DEP-${adv.name}` && f.refs.some((r) => r.includes(adv.advisory)));
    if (already) continue;

    findings.push(
      createFinding({
        id: `DEP-OFFLINE-${adv.name}-${adv.advisory}`,
        title: `依赖组件已知漏洞（离线公告表）：${adv.name}@${version} — ${adv.title}`,
        severity: adv.severity,
        cwe: adv.cwe,
        category: '第三方组件漏洞',
        scanner: 'deps',
        confidence: 'medium',
        location: { file: 'package-lock.json', line: findLockLine(lockText, adv.name) },
        description: `包 ${adv.name} 的解析版本 ${version} 落入受影响区间 [${adv.introduced}, ${adv.fixed})。`,
        evidence:
          `公告编号：${adv.advisory}\n` +
          `受影响版本：>=${adv.introduced} <${adv.fixed}；当前版本：${version}\n` +
          `修复版本：${adv.fixed}（升级到该版本或以上）`,
        impact: '与公告描述一致，具体可达性取决于该依赖在业务中的实际调用路径。',
        recommendation: `将 ${adv.name} 升级到 ${adv.fixed} 或更高版本，并重跑 npm audit 交叉验证。`,
        refs: ['offline-advisory-table', adv.advisory]
      })
    );
  }
  meta.offlineHits = offlineHits;
  if (meta.auditAvailable) {
    meta.crossCheck = offlineHits > 0 ? `离线表补充命中 ${offlineHits} 项` : '离线表无额外命中';
  }

  const unique = sortFindings(dedupe(findings));
  meta.findingCount = unique.length;
  meta.productionHitPackages = [...productionHitNames].sort();

  return { findings: unique, meta };
}

module.exports = { runDeps, OFFLINE_ADVISORIES };
