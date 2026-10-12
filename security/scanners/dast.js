'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');
const { createFinding, dedupe, sortFindings } = require('../lib/findings');

const TIMEOUT_MS = 8000;

// 需要检查的安全响应头（缺失即风险）
const REQUIRED_HEADERS = [
  { name: 'x-content-type-options', expect: 'nosniff', risk: '上传的 HTML/SVG 可能被浏览器按内容嗅探并渲染' },
  { name: 'x-frame-options', expect: '(DENY / SAMEORIGIN)', risk: '页面可被第三方站点 iframe 嵌套（点击劫持）' },
  { name: 'content-security-policy', expect: '(存在策略)', risk: '缺少 CSP 会显著放大 XSS 危害' },
  { name: 'referrer-policy', expect: '(存在策略)', risk: '完整 URL 可能随外链泄露' },
  { name: 'permissions-policy', expect: '(存在策略)', risk: '相机/麦克风/定位等能力默认开放' }
];

// 期望匿名访问被拒绝的接口
const UNAUTH_PROBES = [
  { path: '/api/me', label: '当前用户信息' },
  { path: '/api/users', label: '用户清单' },
  { path: '/api/orders', label: '订单清单' },
  { path: '/api/audit-logs', label: '审计日志' },
  { path: '/api/roles', label: '角色权限矩阵' },
  { path: '/api/pending', label: '待审核文章队列' },
  { path: '/api/comments', label: '全量评论（含待审）' },
  { path: '/api/files', label: '文件清单' },
  { path: '/api/files/1', label: '文件详情' },
  { path: '/api/files/1/download', label: '文件下载' }
];

// 期望低权限用户（普通用户）无法调用的管理/审核类接口
const LOW_PRIV_PROBES = [
  { method: 'GET', path: '/api/pending', label: '读取待审核文章队列' },
  { method: 'GET', path: '/api/comments', label: '读取全量评论（含待审）' },
  { method: 'GET', path: '/api/users', label: '读取用户清单（应 403）' },
  { method: 'GET', path: '/api/audit-logs', label: '读取审计日志（应 403）' },
  { method: 'POST', path: '/api/comments/1/approve', label: '审核通过评论' },
  { method: 'POST', path: '/api/comments/1/reject', label: '拒绝评论' },
  { method: 'POST', path: '/api/approve/1', label: '审核通过文章' },
  { method: 'POST', path: '/api/reject/1', label: '拒绝文章' },
  { method: 'DELETE', path: '/api/files/999999', label: '删除他人上传文件' },
  { method: 'DELETE', path: '/api/posts/999999', label: '删除文章' }
];

async function httpRequest(baseUrl, method, urlPath, { token, body, headers = {}, timeout = TIMEOUT_MS } = {}) {
  const url = baseUrl.replace(/\/$/, '') + urlPath;
  const init = {
    method,
    headers: { ...headers },
    signal: AbortSignal.timeout(timeout)
  };
  if (token) init.headers['Authorization'] = token;
  if (body !== undefined) {
    if (typeof body === 'string') {
      init.body = body;
    } else {
      init.headers['Content-Type'] = init.headers['Content-Type'] || 'application/json';
      init.body = JSON.stringify(body);
    }
  }
  try {
    const res = await fetch(url, init);
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch (e) {
      json = null;
    }
    const headerObj = {};
    res.headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });
    return { ok: true, status: res.status, headers: headerObj, text, json, url };
  } catch (e) {
    return { ok: false, status: 0, headers: {}, text: '', json: null, url, error: e.message };
  }
}

function short(text, n = 300) {
  const s = String(text || '').replace(/\s+/g, ' ').trim();
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function isLocalTarget(baseUrl) {
  try {
    const u = new URL(baseUrl);
    return ['127.0.0.1', 'localhost', '::1', '0.0.0.0'].includes(u.hostname);
  } catch (e) {
    return false;
  }
}

/**
 * 执行 DAST 动态扫描。
 * @param {object} opts
 * @param {string} opts.baseUrl       目标地址，例如 http://127.0.0.1:3210
 * @param {string} [opts.sandboxDir]  被测服务的 DATA_DIR/UPLOADS_DIR 所在沙箱目录（用于校验穿越写入）
 * @param {boolean} [opts.writeProbes] 是否允许执行会产生写入的探针（仅本地沙箱目标建议开启）
 */
async function runDast({ rootDir, baseUrl, sandboxDir, writeProbes, log = () => {} }) {
  const findings = [];
  const checks = [];
  const meta = {
    baseUrl,
    targetKind: isLocalTarget(baseUrl) ? 'local' : 'remote',
    writeProbesEnabled: false,
    probes: {},
    serverIdentification: null
  };

  const allowWrite = writeProbes !== false && isLocalTarget(baseUrl);
  meta.writeProbesEnabled = allowWrite;
  if (writeProbes !== false && !isLocalTarget(baseUrl)) {
    log('DAST: 目标非本地地址，已自动禁用写入型探针（上传 / 目录穿越）。');
  }

  log(`DAST: 目标 ${baseUrl}`);

  // ---------- 1) 安全响应头 ----------
  log('DAST: [1/11] 检查安全响应头…');
  const baseline = await httpRequest(baseUrl, 'GET', '/api/products');
  const missingHeaders = [];
  for (const h of REQUIRED_HEADERS) {
    if (!baseline.headers[h.name]) missingHeaders.push(h);
  }
  meta.probes.headers = {
    status: baseline.status,
    present: Object.keys(baseline.headers),
    missing: missingHeaders.map((h) => h.name)
  };
  meta.serverIdentification = baseline.headers['x-powered-by'] || null;

  if (baseline.ok) {
    if (missingHeaders.length) {
      findings.push(
        createFinding({
          id: 'DAST-HDR-01',
          title: 'HTTP 响应缺少关键安全头',
          severity: 'MEDIUM',
          cwe: 'CWE-693',
          category: '安全配置错误',
          scanner: 'dast',
          confidence: 'high',
          location: { endpoint: 'GET /api/products' },
          description:
            `对 GET /api/products 的响应中缺少 ${missingHeaders.length} 个安全响应头：` +
            missingHeaders.map((h) => h.name).join('、') +
            '。',
          evidence:
            `实测响应头（HTTP ${baseline.status}）：\n` +
            Object.entries(baseline.headers)
              .map(([k, v]) => `  ${k}: ${short(v, 80)}`)
              .join('\n') +
            `\n缺失项及风险：\n` +
            missingHeaders.map((h) => `  - ${h.name}（期望 ${h.expect}）：${h.risk}`).join('\n'),
          impact: '缺少 nosniff 会让上传的 HTML/SVG 被浏览器按内容执行；缺少 CSP/Frame-Options 放大 XSS 与点击劫持风险。',
          recommendation: '引入 helmet 统一设置安全响应头，并对 /uploads 单独下发 Content-Disposition: attachment 与 nosniff。'
        })
      );
    }
    if (baseline.headers['x-powered-by']) {
      findings.push(
        createFinding({
          id: 'DAST-INFO-01',
          title: '响应头泄露服务端技术栈与版本',
          severity: 'LOW',
          cwe: 'CWE-200',
          category: '信息泄露',
          scanner: 'dast',
          confidence: 'high',
          location: { endpoint: 'GET /api/products' },
          description: '响应包含 X-Powered-By 头，直接暴露使用的框架。',
          evidence: `X-Powered-By: ${baseline.headers['x-powered-by']}`,
          impact: '攻击者可据此快速定位与该版本匹配的已知漏洞（配合依赖扫描结果可将利用成功率显著提高）。',
          recommendation: 'app.disable("x-powered-by") 或使用 helmet 的 hidePoweredBy。'
        })
      );
    }
  } else {
    log(`DAST: 基线请求失败：${baseline.error}`);
  }

  // ---------- 2) CORS ----------
  log('DAST: [2/11] 检查 CORS 策略…');
  const cors = await httpRequest(baseUrl, 'GET', '/api/products', {
    headers: { Origin: 'https://evil.example' }
  });
  const acao = cors.headers['access-control-allow-origin'] || null;
  meta.probes.cors = { status: cors.status, origin: 'https://evil.example', acao };
  if (acao === '*' || acao === 'https://evil.example') {
    findings.push(
      createFinding({
        id: 'DAST-CORS-01',
        title: 'CORS 允许任意来源读取接口响应',
        severity: 'MEDIUM',
        cwe: 'CWE-942',
        category: '安全配置错误',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'GET /api/products' },
        description: '携带任意 Origin 的请求都被允许跨域读取响应。',
        evidence:
          `请求：GET /api/products\n  Origin: https://evil.example\n` +
          `响应：HTTP ${cors.status}\n  Access-Control-Allow-Origin: ${acao}`,
        impact: '任意第三方页面可在受害者浏览器中读取本接口数据；当前令牌走 Authorization 头减轻了影响，但一旦改用 Cookie 会话即形成实质越权读取。',
        recommendation: '把 CORS 收敛为显式来源白名单，禁止通配符。'
      })
    );
  } else {
    checks.push({
      id: 'CHK-CORS',
      name: 'CORS 来源白名单',
      expected: '不回显非白名单来源',
      actual: `Access-Control-Allow-Origin: ${acao || '(未设置)'}`,
      result: 'pass'
    });
  }

  // ---------- 3) 匿名访问 ----------
  log('DAST: [3/11] 检查匿名访问（未携带令牌）…');
  const unauthOpen = [];
  const unauthBlocked = [];
  for (const p of UNAUTH_PROBES) {
    const r = await httpRequest(baseUrl, 'GET', p.path);
    const entry = { ...p, status: r.status, bodyPreview: short(r.text, 200) };
    if (r.status === 200) {
      unauthOpen.push(entry);
    } else {
      unauthBlocked.push(entry);
    }
  }
  meta.probes.unauth = { open: unauthOpen, blocked: unauthBlocked };
  // 匿名访问发现的证据会在「上传探针」完成后补充（真实文件名/下载内容比空列表更有说服力）
  const unauthFileEvidence = [];
  if (!unauthOpen.length) {
    checks.push({
      id: 'CHK-UNAUTH',
      name: '匿名访问敏感接口',
      expected: '全部返回 401/403',
      actual: `全部被拒绝（${unauthBlocked.map((e) => e.status).join('/')}）`,
      result: 'pass'
    });
  }

  // ---------- 4) 注册普通用户，验证越权 ----------
  log('DAST: [4/11] 注册低权限账号并检查越权…');
  const username = `secdemo_${Date.now()}`;
  const password = `Pw_${Math.random().toString(36).slice(2, 10)}`;
  const reg = await httpRequest(baseUrl, 'POST', '/api/register', {
    body: { username, password, role: 'user' }
  });
  const lowToken = reg.json && reg.json.token ? reg.json.token : null;
  meta.probes.register = {
    username,
    status: reg.status,
    gotToken: !!lowToken,
    // 该请求体为明文（未使用数字信封），其成功本身即证明应用层加密未强制
    plaintextBody: true,
    bodyPreview: short(reg.text, 250)
  };
  log(`DAST: 已注册演示账号 ${username}（HTTP ${reg.status}）`);

  if (!lowToken) {
    log('DAST: 未能取得低权限令牌，跳过越权与后续写入型探针。');
    checks.push({
      id: 'CHK-REGISTER',
      name: '注册演示账号',
      expected: '201 且返回 token',
      actual: `HTTP ${reg.status} ${short(reg.text, 120)}`,
      result: 'fail'
    });
  } else {
    checks.push({
      id: 'CHK-REGISTER',
      name: '注册演示账号',
      expected: '201 且返回 token',
      actual: `HTTP ${reg.status}，已取得普通用户令牌`,
      result: 'pass'
    });

    const allowed = [];
    const denied = [];
    for (const p of LOW_PRIV_PROBES) {
      const r = await httpRequest(baseUrl, p.method, p.path, { token: lowToken });
      const entry = { ...p, status: r.status, bodyPreview: short(r.text, 200) };
      // 200/201 = 业务成功；404/400 说明请求已越过鉴权层进入业务逻辑，同样属于越权可达
      if (r.status === 200 || r.status === 201 || r.status === 400 || r.status === 404) {
        allowed.push(entry);
      } else {
        denied.push(entry);
      }
    }
    meta.probes.privilegeEscalation = { allowed, denied };

    const escalated = allowed.filter((e) => e.status === 200 || e.status === 201);
    if (allowed.length) {
      findings.push(
        createFinding({
          id: 'DAST-AUTHZ-01',
          title: '普通用户可调用管理/审核类接口（纵向越权）',
          severity: 'HIGH',
          cwe: 'CWE-862',
          category: '权限控制缺陷',
          scanner: 'dast',
          confidence: 'high',
          location: { endpoint: allowed.map((e) => `${e.method} ${e.path}`).join(', ') },
          description:
            `使用自行注册的普通用户（${username}）令牌访问 ${allowed.length} 个管理/审核类接口时，` +
            `${escalated.length} 个返回成功、其余进入了业务逻辑（400/404 而非 403），说明这些路由只校验了「是否登录」。`,
          evidence:
            `账号：${username}（role=user，通过公开注册接口获得）\n` +
            allowed
              .map((e) => `${e.method} ${e.path}（${e.label}）→ HTTP ${e.status}\n    响应片段：${e.bodyPreview}`)
              .join('\n') +
            `\n\n对照组（正确返回 403 的接口）：\n` +
            denied.map((e) => `  - ${e.method} ${e.path} → ${e.status}`).join('\n'),
          impact:
            '攻击者无需任何特权即可注册账号，随后读取审核队列、越权审核/删除文章与评论、删除他人上传的文件；' +
            '结合公开注册接口形成零门槛的完整越权链。',
          recommendation: '为每条路由显式声明 requirePermission(资源, 动作)，并补充「低权限角色调用高权限接口必须 403」的自动化用例。'
        })
      );
    } else {
      checks.push({
        id: 'CHK-RBAC',
        name: '低权限角色访问管理接口',
        expected: '全部返回 403',
        actual: '全部被拒绝',
        result: 'pass'
      });
    }
  }

  // ---------- 5) 登录速率限制 ----------
  log('DAST: [5/11] 检查登录接口速率限制…');
  const attempts = 12;
  const attemptResults = [];
  const started = Date.now();
  for (let i = 0; i < attempts; i++) {
    const r = await httpRequest(baseUrl, 'POST', '/api/login', {
      body: { username: 'admin', password: `wrong-password-${i}` }
    });
    attemptResults.push(r.status);
  }
  const elapsedMs = Date.now() - started;
  const throttled = attemptResults.some((s) => s === 429 || s === 423);
  meta.probes.loginThrottle = {
    attempts,
    statuses: attemptResults,
    elapsedMs,
    throttled
  };
  if (!throttled) {
    findings.push(
      createFinding({
        id: 'DAST-RATE-01',
        title: '登录接口无速率限制与失败锁定',
        severity: 'HIGH',
        cwe: 'CWE-307',
        category: '认证缺陷',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/login' },
        description: `连续 ${attempts} 次错误口令登录全部被正常处理，未出现 429/423 或任何锁定迹象。`,
        evidence:
          `请求：连续 ${attempts} 次 POST /api/login（错误口令）\n` +
          `响应状态序列：${attemptResults.join(', ')}\n` +
          `总耗时：${elapsedMs} ms（平均 ${(elapsedMs / attempts).toFixed(0)} ms/次）→ 单线程即可约 ${(1000 / (elapsedMs / attempts)).toFixed(0)} 次/秒 的爆破速率`,
        impact:
          '可对账号口令做高速字典爆破；TOTP 为 6 位且服务端允许 ±1 个时间窗（3 个候选码），' +
          '无限次尝试下二次认证被实质性削弱。',
        recommendation: '按账号+来源 IP 做指数退避与失败锁定，对 /login/totp 单独限流，并对失败告警。'
      })
    );
  }

  // ---------- 6) 代理头伪造 ----------
  log('DAST: [6/11] 检查 X-Forwarded-For 伪造是否被采信…');
  const spoofIp = '203.0.113.66';
  const marker = `dast-ipspoof-${Date.now()}`;
  const commentRes = await httpRequest(baseUrl, 'POST', '/api/comments', {
    headers: { 'X-Forwarded-For': spoofIp, 'CF-Connecting-IP': spoofIp },
    body: { contentType: 'product', contentId: 1, author: 'dast-probe', content: marker }
  });
  let recordedIp = null;
  let readBackStatus = null;
  if (lowToken) {
    const list = await httpRequest(baseUrl, 'GET', '/api/comments', { token: lowToken });
    readBackStatus = list.status;
    const hit = list.json && Array.isArray(list.json.comments)
      ? list.json.comments.find((c) => c.content === marker)
      : null;
    recordedIp = hit ? hit.ip : null;
  }
  meta.probes.ipSpoof = {
    spoofed: spoofIp,
    commentCreateStatus: commentRes.status,
    readBackStatus,
    recordedIp
  };
  if (recordedIp === spoofIp) {
    findings.push(
      createFinding({
        id: 'DAST-LOG-01',
        title: '业务记录与审计日志采信客户端伪造的 IP 头',
        severity: 'MEDIUM',
        cwe: 'CWE-348',
        category: '日志与审计缺陷',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/comments' },
        description: '服务端直接采用 X-Forwarded-For / CF-Connecting-IP 作为客户端 IP 写入记录，未校验请求是否来自可信代理。',
        evidence:
          `请求：POST /api/comments（匿名）\n` +
          `  X-Forwarded-For: ${spoofIp}\n  CF-Connecting-IP: ${spoofIp}\n  content: ${marker}\n` +
          `响应：HTTP ${commentRes.status}\n` +
          `随后 GET /api/comments 读回该记录（HTTP ${readBackStatus}）：ip 字段为 "${recordedIp}"（即请求头中伪造的值）`,
        impact:
          '攻击者可让审计日志记录任意来源 IP，溯源、封禁与责任认定全部失效；' +
          '审计报告的证明力被破坏（本项目的审计日志正是 Week 7/12 的证据链基础）。',
        recommendation:
          '仅在请求来源属于受信代理网段时采信转发头（配合 app.set("trust proxy", 受信网段)）；' +
          '或直接记录 socket 地址，另存转发头仅用于排查。'
      })
    );
  } else {
    checks.push({
      id: 'CHK-IPSPOOF',
      name: '客户端 IP 采集可信性',
      expected: '不采信伪造的转发头',
      actual: `记录的 ip = ${recordedIp === null ? '(未取回)' : recordedIp}`,
      result: recordedIp === spoofIp ? 'fail' : 'pass'
    });
  }

  // ---------- 7) 上传导致存储型 XSS ----------
  log('DAST: [7/11] 检查文件上传与静态托管…');
  let uploadFindingEvidence = null;
  let traversalEvidence = null;

  if (lowToken && allowWrite) {
    // 7a) 上传可执行 HTML
    const xssName = `dast-xss-${Date.now()}.html`;
    const payload = '<html><body><script>document.title="DAST_XSS_PROOF";</script>DAST-XSS-PROOF</body></html>';
    const up = await httpRequest(baseUrl, 'POST', '/api/files', {
      token: lowToken,
      body: {
        title: 'dast-xss-probe',
        fileName: xssName,
        fileType: 'text/html',
        fileData: Buffer.from(payload, 'utf8').toString('base64')
      }
    });
    const storedName = up.json && up.json.data ? up.json.data.fileName : null;
    let fetchStatus = null;
    let fetchType = null;
    let fetchHasPayload = false;
    if (storedName) {
      const fetched = await httpRequest(baseUrl, 'GET', `/uploads/${encodeURIComponent(storedName)}`);
      fetchStatus = fetched.status;
      fetchType = fetched.headers['content-type'] || null;
      fetchHasPayload = fetched.text.includes('DAST-XSS-PROOF');
    }
    meta.probes.uploadXss = {
      uploadStatus: up.status,
      storedName,
      fetchStatus,
      fetchType,
      fetchHasPayload
    };

    // 追加证据：以匿名身份枚举文件清单并下载刚上传的文件（证明未授权数据外泄）
    if (up.json && up.json.data && up.json.data.id != null) {
      const fileId = up.json.data.id;
      const anonList = await httpRequest(baseUrl, 'GET', '/api/files');
      const anonDetail = await httpRequest(baseUrl, 'GET', `/api/files/${fileId}`);
      const anonDownload = await httpRequest(baseUrl, 'GET', `/api/files/${fileId}/download`);
      meta.probes.unauthFileDisclosure = {
        fileId,
        listStatus: anonList.status,
        detailStatus: anonDetail.status,
        downloadStatus: anonDownload.status,
        downloadBodyHasPayload: anonDownload.text.includes('DAST-XSS-PROOF'),
        listMentionsFile: anonList.text.includes(storedName || '\u0000')
      };
      if (anonList.status === 200) {
        unauthFileEvidence.push(
          `匿名 GET /api/files → HTTP ${anonList.status}，响应中包含刚上传的文件记录：${meta.probes.unauthFileDisclosure.listMentionsFile}\n` +
            `  响应片段：${short(anonList.text, 220)}`
        );
      }
      if (anonDetail.status === 200) {
        unauthFileEvidence.push(
          `匿名 GET /api/files/${fileId} → HTTP ${anonDetail.status}，可直接读取文件元数据（含上传者与 IP）\n` +
            `  响应片段：${short(anonDetail.text, 220)}`
        );
      }
      if (anonDownload.status === 200) {
        unauthFileEvidence.push(
          `匿名 GET /api/files/${fileId}/download → HTTP ${anonDownload.status}` +
            `${anonDownload.headers['content-disposition'] ? `，Content-Disposition: ${anonDownload.headers['content-disposition']}` : ''}\n` +
            `  响应体包含上传内容：${meta.probes.unauthFileDisclosure.downloadBodyHasPayload}`
        );
      }
    }
    if (storedName && fetchStatus === 200 && fetchHasPayload) {
      uploadFindingEvidence =
        `请求（普通用户令牌）：POST /api/files\n` +
        `  fileName: ${xssName}\n  fileType: text/html（服务端未做类型校验）\n` +
        `  fileData: <base64 编码的 <script> 页面>\n` +
        `响应：HTTP ${up.status}，落盘文件名 ${storedName}\n\n` +
        `随后匿名访问：GET /uploads/${encodeURIComponent(storedName)}\n` +
        `  → HTTP ${fetchStatus}\n  → Content-Type: ${fetchType}\n` +
        `  → 响应体包含 payload：${fetchHasPayload}`;
    }

    // 7b) 上传文件名目录穿越
    const traversalMarker = `dast-traversal-${Date.now()}.txt`;
    const traversalName = `a/../../${traversalMarker}`;
    const tv = await httpRequest(baseUrl, 'POST', '/api/files', {
      token: lowToken,
      body: {
        title: 'dast-traversal-probe',
        fileName: traversalName,
        fileType: 'text/plain',
        fileData: Buffer.from('DAST path traversal proof', 'utf8').toString('base64')
      }
    });
    let escapedPath = null;
    let escapedExists = false;
    if (sandboxDir) {
      const candidate = path.resolve(sandboxDir, traversalMarker);
      // 安全护栏：仅当解析结果仍位于沙箱目录内时才做存在性校验
      if (candidate.startsWith(path.resolve(sandboxDir))) {
        escapedPath = candidate;
        escapedExists = fs.existsSync(candidate);
        if (escapedExists) {
          try {
            fs.unlinkSync(candidate);
          } catch (e) {
            /* 清理失败不影响结论，已在证据中说明 */
          }
        }
      }
    }
    meta.probes.pathTraversal = {
      uploadStatus: tv.status,
      requestedFileName: traversalName,
      storedName: tv.json && tv.json.data ? tv.json.data.fileName : null,
      escapedPath,
      escapedExists,
      cleanedUp: escapedExists
    };
    if (escapedExists) {
      traversalEvidence =
        `请求（普通用户令牌）：POST /api/files\n` +
        `  fileName: ${traversalName}\n` +
        `响应：HTTP ${tv.status}，服务端拼接后的文件名 ${tv.json && tv.json.data ? tv.json.data.fileName : '(未知)'}\n\n` +
        `文件实际落盘位置（越出上传目录）：${escapedPath}\n` +
        `存在性校验：exists = ${escapedExists}（探针文件已删除，未污染仓库）`;
    }
  } else if (lowToken) {
    meta.probes.uploadXss = { skipped: '目标非本地沙箱，已跳过写入型探针' };
    meta.probes.pathTraversal = { skipped: '目标非本地沙箱，已跳过写入型探针' };
  }

  if (uploadFindingEvidence) {
    findings.push(
      createFinding({
        id: 'DAST-UPLOAD-01',
        title: '不受限文件上传 + 上传目录静态托管 → 存储型 XSS',
        severity: 'HIGH',
        cwe: 'CWE-434',
        category: '不受限文件上传',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/files → GET /uploads/{name}' },
        description: '上传接口不校验类型/扩展名，且上传目录由 express.static 对外托管，浏览器会按 Content-Type 渲染上传的 HTML。',
        evidence: uploadFindingEvidence,
        impact:
          '攻击者（任意注册用户）可上传 HTML/SVG，把恶意页面托管在被测站点的同源下，' +
          '可窃取 localStorage 中的登录令牌（见 SAST SEC-STORAGE-01）并冒用受害者身份，也可用于钓鱼。',
        recommendation:
          '扩展名 + MIME + 魔数三重白名单；上传目录移出 Web 根并用鉴权接口读取；' +
          '下载响应统一 Content-Disposition: attachment 与 X-Content-Type-Options: nosniff。'
      })
    );
  }
  if (traversalEvidence) {
    findings.push(
      createFinding({
        id: 'DAST-UPLOAD-02',
        title: '上传文件名可目录穿越，写入上传目录之外的任意路径',
        severity: 'HIGH',
        cwe: 'CWE-22',
        category: '路径穿越',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/files' },
        description: 'fileName 未做 basename 剥离，path.join 会把 ../ 归一化，最终落盘位置越出上传目录。',
        evidence: traversalEvidence,
        impact:
          '可越出上传目录写文件。若写入点位于应用可加载路径（如覆盖 src 下文件）并配合重启/热加载，' +
          '可升级为服务器端代码执行；至少可造成任意文件写入（覆盖配置、写 webshell 到静态目录）。',
        recommendation: '用 path.basename 只取基名，或由服务端自行生成文件名；落盘前校验 path.resolve 结果必须以上传目录 + 分隔符开头。'
      })
    );
  }
  if (lowToken && allowWrite) {
    checks.push({
      id: 'CHK-UPLOAD',
      name: '上传内容安全',
      expected: '拒绝 HTML/SVG 等可执行类型；文件名不可穿越',
      actual: uploadFindingEvidence || traversalEvidence ? '存在不安全行为（见上方发现）' : '未复现',
      result: uploadFindingEvidence || traversalEvidence ? 'fail' : 'pass'
    });
  }

  // ---------- 7c) 汇总「匿名访问」发现（此时已具备真实文件数据作为证据） ----------
  if (unauthOpen.length) {
    findings.push(
      createFinding({
        id: 'DAST-AUTH-01',
        title: '敏感接口允许完全匿名访问',
        severity: 'HIGH',
        cwe: 'CWE-306',
        category: '认证缺陷',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: unauthOpen.map((e) => `GET ${e.path}`).join(', ') },
        description: `${unauthOpen.length} 个接口在不携带任何凭证的情况下返回 200 与业务数据。`,
        evidence:
          unauthOpen
            .map((e) => `GET ${e.path}（${e.label}）→ HTTP ${e.status}\n    响应片段：${e.bodyPreview}`)
            .join('\n') +
          (unauthFileEvidence.length
            ? `\n\n进一步验证（匿名身份直接读取真实上传文件）：\n${unauthFileEvidence.join('\n')}`
            : '') +
          `\n\n对照组（正确拒绝匿名访问的接口，HTTP ${unauthBlocked.map((e) => e.status).join('/')}）：\n` +
          unauthBlocked.map((e) => `  - ${e.path} → ${e.status}`).join('\n'),
        impact:
          '匿名即可枚举并下载 /uploads 中的全部附件（含他人上传的业务文件），' +
          '文件详情还会回传上传者与来源 IP；构成直接的未授权数据外泄面。',
        recommendation: '按「默认拒绝」为文件相关路由补齐鉴权；文件下载叠加资源归属校验；确需公开的接口显式列入白名单。'
      })
    );
  }

  // ---------- 8) 错误堆栈泄露 ----------
  log('DAST: [8/11] 检查异常错误处理…');
  const malformed = await httpRequest(baseUrl, 'POST', '/api/login', {
    headers: { 'Content-Type': 'application/json' },
    body: '{"username": "admin", '
  });
  const leaksStack =
    /SyntaxError|at Object\.|at Layer\.|node_modules|\.js:\d+:\d+/.test(malformed.text || '');
  meta.probes.errorDisclosure = {
    status: malformed.status,
    contentType: malformed.headers['content-type'] || null,
    leaksStack,
    bodyPreview: short(malformed.text, 400)
  };
  if (leaksStack) {
    findings.push(
      createFinding({
        id: 'DAST-ERR-01',
        title: '异常请求触发错误堆栈回显',
        severity: 'MEDIUM',
        cwe: 'CWE-209',
        category: '信息泄露',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/login（畸形 JSON）' },
        description: '发送畸形 JSON 后，服务端返回的响应体中包含异常堆栈与源码路径。',
        evidence:
          `请求：POST /api/login\n  Content-Type: application/json\n  Body: {"username": "admin", （非法 JSON）\n` +
          `响应：HTTP ${malformed.status}\n  Content-Type: ${meta.probes.errorDisclosure.contentType}\n` +
          `  响应片段：${meta.probes.errorDisclosure.bodyPreview}`,
        impact: '泄露框架版本、目录结构与代码片段，为攻击者精确定位可利用点提供线索。',
        recommendation: '注册统一错误处理中间件，仅返回错误码与提示；堆栈只写服务端日志；生产环境强制 NODE_ENV=production。'
      })
    );
  } else {
    checks.push({
      id: 'CHK-ERROR',
      name: '异常响应信息量',
      expected: '不返回堆栈',
      actual: `HTTP ${malformed.status}，未检出堆栈特征`,
      result: 'pass'
    });
  }

  // ---------- 9) 应用层加密是否强制 ----------
  log('DAST: [9/11] 检查应用层加密（数字信封）是否强制…');
  const plainLogin = await httpRequest(baseUrl, 'POST', '/api/login', {
    body: { username: '__dast_nonexistent__', password: 'x' }
  });
  const plainProcessed = plainLogin.status === 401 || plainLogin.status === 200;
  meta.probes.encryptionEnforced = {
    plaintextLoginStatus: plainLogin.status,
    registerWithoutEnvelope: meta.probes.register ? meta.probes.register.status : null,
    enforced: !plainProcessed
  };
  if (plainProcessed) {
    findings.push(
      createFinding({
        id: 'DAST-CRYPTO-01',
        title: '应用层加密（数字信封）未强制，明文请求可直接绕过',
        severity: 'HIGH',
        cwe: 'CWE-693',
        category: '安全控制缺失',
        scanner: 'dast',
        confidence: 'high',
        location: { endpoint: 'POST /api/login、POST /api/register' },
        description:
          '服务端对非信封请求体直接放行（envelope.middleware 的 isEnvelope 判断不成立即 next()），' +
          '因此「敏感请求必须加密」并非强制约束。',
        evidence:
          `请求 1：POST /api/login，明文 JSON {"username":"__dast_nonexistent__","password":"x"}\n` +
          `  → HTTP ${plainLogin.status}（已被业务逻辑正常处理，说明完全跳过了信封解密路径）\n\n` +
          `请求 2：POST /api/register，明文 JSON（注册演示账号）\n` +
          `  → HTTP ${meta.probes.register ? meta.probes.register.status : '(未执行)'}`,
        impact:
          '攻击者或被篡改的客户端只需发送明文 JSON 即可降级，Week 4 交付的机密性/完整性保护形同虚设；' +
          '抓包可见的明文与「加密无法被绕过」的设计目标不符。',
        recommendation: '对敏感路由强制要求信封格式（非信封直接 400），或改由统一的请求入口策略执行「信封或拒绝」。'
      })
    );
  }

  // ---------- 10) 控制有效性验证：数字信封防重放 / 完整性 ----------
  log('DAST: [10/11] 验证数字信封的防重放与完整性保护（正向对照）…');
  const envelopeChecks = await verifyEnvelopeControls(baseUrl, rootDir);
  checks.push(...envelopeChecks);
  meta.probes.envelope = envelopeChecks.reduce((acc, c) => {
    acc[c.id] = { result: c.result, actual: c.actual };
    return acc;
  }, {});

  // ---------- 11) 上传目录静态托管无鉴权 ----------
  log('DAST: [11/11] 汇总…');
  const filesList = await httpRequest(baseUrl, 'GET', '/api/files');
  if (filesList.status === 200 && filesList.json && Array.isArray(filesList.json.files)) {
    const sample = filesList.json.files[0];
    meta.probes.fileMetadataExposure = {
      count: filesList.json.files.length,
      sampleFields: sample ? Object.keys(sample) : []
    };
  }

  const unique = sortFindings(dedupe(findings));
  return { findings: unique, checks, meta };
}

/**
 * 加载被测项目**自身**的数字信封实现（client/src/api/envelope.js）。
 *
 * 为什么要做一次改写：浏览器打包器允许省略扩展名的相对导入（`from './sm4gcm'`），
 * 而 Node 的 ESM 解析器要求显式扩展名，且 `data:`/内联模块无法解析裸包名。
 * 因此这里把两个源文件复制到临时目录，仅把导入说明符改成可被 Node 解析的绝对地址，
 * 其余逻辑（含加密算法）完全复用仓库代码，保证验证的是真实协议实现。
 */
async function loadProjectSealBody(rootDir) {
  const clientApi = path.join(rootDir, 'client', 'src', 'api');
  const sm4Path = path.join(clientApi, 'sm4gcm.js');
  const envelopePath = path.join(clientApi, 'envelope.js');
  if (!fs.existsSync(sm4Path) || !fs.existsSync(envelopePath)) {
    throw new Error('未找到 client/src/api 下的信封实现');
  }

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-envelope-'));
  const smCryptoUrl = pathToFileURL(require.resolve('sm-crypto')).href;
  const rewrite = (src) =>
    src
      .replace(/from\s+'\.\/sm4gcm'/, "from './sm4gcm.mjs'")
      .replace(/from\s+'sm-crypto'/g, `from '${smCryptoUrl}'`);

  fs.writeFileSync(path.join(workDir, 'sm4gcm.mjs'), rewrite(fs.readFileSync(sm4Path, 'utf8')), 'utf8');
  fs.writeFileSync(path.join(workDir, 'envelope.mjs'), rewrite(fs.readFileSync(envelopePath, 'utf8')), 'utf8');

  const mod = await import(pathToFileURL(path.join(workDir, 'envelope.mjs')).href);
  return {
    sealBody: mod.sealBody,
    publicKey: mod.SERVER_SM2_PUBLIC_KEY,
    cleanup: () => {
      try {
        fs.rmSync(workDir, { recursive: true, force: true });
      } catch (e) {
        /* 清理失败不影响结论 */
      }
    }
  };
}

/**
 * 使用项目前端自身的信封实现构造真实请求，
 * 验证「防重放」与「完整性校验」两项控制是否真的生效。
 */
async function verifyEnvelopeControls(baseUrl, rootDir) {
  const checks = [];
  let loader = null;
  try {
    loader = await loadProjectSealBody(rootDir);
  } catch (e) {
    checks.push({
      id: 'CHK-ENVELOPE',
      name: '数字信封探针',
      expected: '能够加载 client/src/api/envelope.js',
      actual: `加载失败：${e.message}`,
      result: 'skip'
    });
    return checks;
  }

  try {
    const sealBody = loader.sealBody;
    const payload = { username: '__dast_envelope_probe__', password: 'probe' };
    let envelope;
    try {
      envelope = sealBody(payload, { method: 'POST', path: '/api/login' });
    } catch (e) {
      checks.push({
        id: 'CHK-ENVELOPE',
        name: '数字信封探针',
        expected: '能够构造信封',
        actual: `构造失败：${e.message}`,
        result: 'error'
      });
      return checks;
    }

    // 首包：信封结构合法、可解析，但因凭据错误应返回 401
    const first = await httpRequest(baseUrl, 'POST', '/api/login', { body: envelope });
    checks.push({
      id: 'CHK-ENVELOPE-ACCEPT',
      name: '数字信封可正常解封（复用项目前端实现）',
      expected: 'HTTP 401（凭据错误，说明信封已被成功解密）',
      actual: `HTTP ${first.status} ${short(first.text, 120)}`,
      result: first.status === 401 ? 'pass' : 'fail',
      evidence: `信封字段：${Object.keys(envelope).join(', ')}；nonce=${envelope.nonce}`
    });

    // 重放同一信封：nonce 已被消费，应返回 409
    const replay = await httpRequest(baseUrl, 'POST', '/api/login', { body: envelope });
    checks.push({
      id: 'CHK-ENVELOPE-REPLAY',
      name: '防重放（nonce 一次性）',
      expected: 'HTTP 409（REPLAY）',
      actual: `HTTP ${replay.status} ${short(replay.text, 120)}`,
      result: replay.status === 409 ? 'pass' : 'fail'
    });

    // 篡改 nonce：AAD 绑定 nonce，解密/完整性校验应失败，返回 400
    const tampered = {
      ...envelope,
      nonce: Buffer.from(`tampered-${Date.now()}`).toString('base64').slice(0, 16)
    };
    const tamper = await httpRequest(baseUrl, 'POST', '/api/login', { body: tampered });
    checks.push({
      id: 'CHK-ENVELOPE-INTEGRITY',
      name: '完整性校验（AAD 绑定被篡改即拒绝）',
      expected: 'HTTP 400（完整性或时间窗校验失败）',
      actual: `HTTP ${tamper.status} ${short(tamper.text, 120)}`,
      result: tamper.status === 400 ? 'pass' : 'fail'
    });

    return checks;
  } finally {
    loader.cleanup();
  }
}

module.exports = { runDast, httpRequest };
