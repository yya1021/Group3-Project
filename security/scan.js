'use strict';

/**
 * 安全扫描统一入口（第 7 周节点：SAST / DAST 与依赖扫描）
 *
 * 用法：
 *   node security/scan.js                       # 全量：SAST + 依赖 + DAST（自动启动沙箱服务）
 *   node security/scan.js --only=sast,deps      # 只跑静态与依赖
 *   node security/scan.js --only=dast --base-url=http://127.0.0.1:3000
 *   node security/scan.js --no-write-probes     # 不执行会产生写入的 DAST 探针
 *
 * 所有报告写入 security/reports/。
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const { spawn, spawnSync } = require('child_process');

const util = require('./lib/util');
const { sortFindings, renumber, countBySeverity } = require('./lib/findings');
const { renderBaselineReport, renderVulnerabilityList, renderConsoleSummary } = require('./lib/report');
const { runSast } = require('./scanners/sast');
const { runDeps } = require('./scanners/deps');
const { runDast, httpRequest } = require('./scanners/dast');

const ROOT = path.resolve(__dirname, '..');
const REPORTS_DIR = path.join(__dirname, 'reports');

// ---------- 命令行参数 ----------
function parseArgs(argv) {
  const opts = {
    only: ['sast', 'deps', 'dast'],
    baseUrl: null,
    port: null,
    outDir: REPORTS_DIR,
    writeProbes: true,
    sandboxDir: null,
    useColor: true
  };
  for (const arg of argv) {
    if (arg.startsWith('--only=')) opts.only = arg.slice(7).split(',').map((s) => s.trim()).filter(Boolean);
    else if (arg.startsWith('--base-url=')) opts.baseUrl = arg.slice(11);
    else if (arg.startsWith('--port=')) opts.port = parseInt(arg.slice(7), 10);
    else if (arg.startsWith('--out=')) opts.outDir = path.resolve(arg.slice(6));
    else if (arg === '--no-write-probes') opts.writeProbes = false;
    else if (arg.startsWith('--sandbox=')) opts.sandboxDir = path.resolve(arg.slice(10));
    else if (arg === '--no-color') opts.useColor = false;
  }
  return opts;
}

const OPTS = parseArgs(process.argv.slice(2));
const log = (msg) => console.log(`  ${msg}`);

function banner(title) {
  const line = '─'.repeat(86);
  console.log('');
  console.log(line);
  console.log(`  ${title}`);
  console.log(line);
}

function sh(cmd) {
  const r = spawnSync(cmd, [], { encoding: 'utf8', shell: true, cwd: ROOT });
  return (r.stdout || '').trim();
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitForServer(baseUrl, timeoutMs = 25000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const r = await httpRequest(baseUrl, 'GET', '/api/products', { timeout: 2000 });
    if (r.ok && r.status < 500) return true;
    await new Promise((res) => setTimeout(res, 300));
  }
  return false;
}

function makeSandbox(prefix) {
  const dir = path.join(os.tmpdir(), `${prefix}-${Date.now()}`);
  fs.mkdirSync(path.join(dir, 'data'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'uploads'), { recursive: true });
  return dir;
}

function removeDir(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    /* 清理失败不影响结果 */
  }
}

async function withSandboxServer({ sandboxDir, port }, fn) {
  const env = {
    ...process.env,
    PORT: String(port),
    DATA_DIR: path.join(sandboxDir, 'data'),
    UPLOADS_DIR: path.join(sandboxDir, 'uploads'),
    // 与真实部署一致：不设置 NODE_ENV=production，以观察默认错误处理行为
    NODE_ENV: process.env.NODE_ENV || 'development'
  };
  const child = spawn(process.execPath, [path.join(ROOT, 'server', 'src', 'server.js')], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let out = '';
  child.stdout.on('data', (d) => (out += d.toString()));
  child.stderr.on('data', (d) => (out += d.toString()));

  const baseUrl = `http://127.0.0.1:${port}`;
  const ready = await waitForServer(baseUrl);
  if (!ready) {
    child.kill();
    throw new Error(`沙箱服务未能在超时前就绪（端口 ${port}）。服务输出：\n${out.slice(0, 800)}`);
  }
  log(`沙箱服务已就绪：${baseUrl}（DATA_DIR=${env.DATA_DIR}）`);

  try {
    return await fn(baseUrl);
  } finally {
    child.kill('SIGTERM');
    await new Promise((res) => setTimeout(res, 300));
    if (child.exitCode === null) child.kill('SIGKILL');
  }
}

async function main() {
  const generatedAt = util.nowIso();
  const commit = sh('git rev-parse --short HEAD') || '(非 git 仓库)';
  const envInfo = {
    platform: `${process.platform} ${process.arch}`,
    node: process.version,
    npm: sh('npm --version') || '(未知)'
  };

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════════════════════════════╗');
  console.log('║  优选商城 · 第 7 周安全扫描（SAST / DAST / 依赖成分扫描）                            ║');
  console.log('╚══════════════════════════════════════════════════════════════════════════════════════╝');
  console.log(`  仓库根目录：${ROOT}`);
  console.log(`  提交：${commit}`);
  console.log(`  环境：${envInfo.platform} / Node ${envInfo.node} / npm ${envInfo.npm}`);
  console.log(`  扫描项：${OPTS.only.join(', ')}`);

  const runSastScan = OPTS.only.includes('sast');
  const runDepsScan = OPTS.only.includes('deps');
  const runDastScan = OPTS.only.includes('dast');

  let sastResult = { findings: [], meta: {} };
  let depsResult = { findings: [], meta: {} };
  let dastResult = { findings: [], checks: [], meta: {} };
  let fatal = null;

  // ---------- SAST ----------
  if (runSastScan) {
    banner('① SAST —— 静态应用安全测试');
    try {
      sastResult = runSast({ rootDir: ROOT, log });
    } catch (e) {
      fatal = fatal || `SAST 执行失败：${e.message}`;
      console.error(`  SAST 执行失败：${e.stack}`);
    }
  }

  // ---------- 依赖扫描 ----------
  if (runDepsScan) {
    banner('② 依赖成分与已知漏洞扫描');
    try {
      depsResult = runDeps({
        rootDir: ROOT,
        log,
        proxyEnv: pickProxyEnv()
      });
    } catch (e) {
      fatal = fatal || `依赖扫描执行失败：${e.message}`;
      console.error(`  依赖扫描执行失败：${e.stack}`);
    }
  }

  // ---------- DAST ----------
  if (runDastScan) {
    banner('③ DAST —— 动态应用安全测试');
    try {
      if (OPTS.baseUrl) {
        log(`使用外部目标：${OPTS.baseUrl}（不启动沙箱服务）`);
        dastResult = await runDast({
          rootDir: ROOT,
          baseUrl: OPTS.baseUrl,
          sandboxDir: OPTS.sandboxDir,
          writeProbes: OPTS.writeProbes,
          log
        });
      } else {
        const sandboxDir = OPTS.sandboxDir || makeSandbox('sec-scan');
        const port = OPTS.port || (await freePort());
        log(`创建沙箱目录：${sandboxDir}`);
        try {
          dastResult = await withSandboxServer({ sandboxDir, port }, (baseUrl) =>
            runDast({ rootDir: ROOT, baseUrl, sandboxDir, writeProbes: OPTS.writeProbes, log })
          );
        } finally {
          if (!OPTS.sandboxDir) {
            removeDir(sandboxDir);
            log('沙箱目录已清理（仓库数据与上传目录未被改动）');
          }
        }
      }
    } catch (e) {
      fatal = fatal || `DAST 执行失败：${e.message}`;
      console.error(`  DAST 执行失败：${e.message}`);
    }
  }

  // ---------- 汇总与报告 ----------
  const all = sortFindings([...sastResult.findings, ...depsResult.findings, ...dastResult.findings]);
  const findings = renumber(all);
  const counts = countBySeverity(findings);
  const checks = dastResult.checks || [];

  console.log(renderConsoleSummary(findings, { useColor: OPTS.useColor }));

  util.ensureDir(OPTS.outDir);
  const summary = {
    generatedAt,
    commit,
    env: envInfo,
    root: ROOT,
    counts,
    total: findings.length,
    scanners: {
      sast: { meta: sastResult.meta, findings: sastResult.findings.length },
      deps: { meta: depsResult.meta, findings: depsResult.findings.length },
      dast: { meta: dastResult.meta, findings: dastResult.findings.length, checks }
    },
    fatal
  };

  util.writeText(path.join(OPTS.outDir, 'findings.json'), JSON.stringify({ generatedAt, commit, counts, findings }, null, 2));
  if (runSastScan) {
    util.writeText(
      path.join(OPTS.outDir, 'sast-results.json'),
      JSON.stringify({ generatedAt, meta: sastResult.meta, findings: sastResult.findings }, null, 2)
    );
  }
  if (runDepsScan) {
    util.writeText(
      path.join(OPTS.outDir, 'deps-results.json'),
      JSON.stringify({ generatedAt, meta: depsResult.meta, findings: depsResult.findings }, null, 2)
    );
  }
  if (runDastScan) {
    util.writeText(
      path.join(OPTS.outDir, 'dast-results.json'),
      JSON.stringify({ generatedAt, meta: dastResult.meta, checks, findings: dastResult.findings }, null, 2)
    );
  }
  util.writeText(path.join(OPTS.outDir, 'scan-summary.json'), JSON.stringify(summary, null, 2));

  util.writeText(
    path.join(OPTS.outDir, 'vulnerability-list.md'),
    renderVulnerabilityList({ generatedAt, commit, findings, checks })
  );
  util.writeText(
    path.join(OPTS.outDir, 'baseline-report.md'),
    renderBaselineReport({
      generatedAt,
      commit,
      findings,
      sastMeta: sastResult.meta,
      depsMeta: depsResult.meta,
      dastMeta: dastResult.meta,
      checks,
      env: envInfo
    })
  );

  console.log('  报告已生成：');
  console.log(`    - ${path.join(OPTS.outDir, 'baseline-report.md')}      （基线报告）`);
  console.log(`    - ${path.join(OPTS.outDir, 'vulnerability-list.md')}   （漏洞清单）`);
  console.log(`    - ${path.join(OPTS.outDir, 'sast-results.json')} / dast-results.json / deps-results.json / scan-summary.json`);
  console.log('');
  console.log(
    `  结论：共 ${findings.length} 条发现（严重 ${counts.CRITICAL} / 高 ${counts.HIGH} / 中 ${counts.MEDIUM} / 低 ${counts.LOW}）`
  );
  if (fatal) console.log(`  ⚠ 存在执行异常：${fatal}`);
  console.log('');

  return fatal ? 2 : 0;
}

function pickProxyEnv() {
  const env = {};
  for (const key of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy']) {
    if (process.env[key]) env[key] = process.env[key];
  }
  return env;
}

// 保证异常退出时不留后台进程
process.on('exit', () => {});
process.on('SIGINT', () => process.exit(130));

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error('扫描器发生未捕获异常：');
    console.error(e && e.stack ? e.stack : e);
    process.exit(1);
  });
