'use strict';

const fs = require('fs');
const path = require('path');

// 需要跳过的目录（依赖、构建产物、版本库内部、扫描产物）
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.vite', '.cache'
]);

// 递归收集目录下的文件（返回相对 rootDir 的 POSIX 风格路径）
function walkFiles(rootDir, { exts = null, skipDirs = SKIP_DIRS } = {}) {
  const out = [];

  function visit(absDir, relDir) {
    let entries;
    try {
      entries = fs.readdirSync(absDir, { withFileTypes: true });
    } catch (e) {
      return;
    }
    for (const entry of entries) {
      const rel = relDir ? `${relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        visit(path.join(absDir, entry.name), rel);
      } else if (entry.isFile()) {
        if (exts && !exts.some((e) => entry.name.endsWith(e))) continue;
        out.push(rel);
      }
    }
  }

  visit(rootDir, '');
  return out.sort();
}

function readText(absPath) {
  try {
    return fs.readFileSync(absPath, 'utf8');
  } catch (e) {
    return null;
  }
}

function readJson(absPath) {
  const text = readText(absPath);
  if (text == null) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
}

// 把字符偏移换算成 1-based 行列号
function offsetToLineCol(content, offset) {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content[i] === '\n') {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, column: offset - lineStart + 1 };
}

// 提取某一行（1-based）的原文
function lineAt(content, lineNo) {
  const lines = content.split(/\r?\n/);
  return lines[lineNo - 1] != null ? lines[lineNo - 1] : '';
}

// 截取一段多行片段，便于作为报告里的证据
function excerptAt(content, lineNo, context = 2) {
  const lines = content.split(/\r?\n/);
  const start = Math.max(1, lineNo - context);
  const end = Math.min(lines.length, lineNo + context);
  const width = String(end).length;
  const out = [];
  for (let n = start; n <= end; n++) {
    const marker = n === lineNo ? '>' : ' ';
    out.push(`${marker} ${String(n).padStart(width)} | ${lines[n - 1]}`);
  }
  return out.join('\n');
}

function nowIso() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const tz = -d.getTimezoneOffset();
  const sign = tz >= 0 ? '+' : '-';
  const abs = Math.abs(tz);
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}` +
    `${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
  );
}

function ensureDir(absDir) {
  fs.mkdirSync(absDir, { recursive: true });
}

function writeText(absPath, content) {
  ensureDir(path.dirname(absPath));
  fs.writeFileSync(absPath, content, 'utf8');
}

// 简易 semver 比较：返回 -1 / 0 / 1；仅比较 x.y.z 数字段
function compareVersions(a, b) {
  const pa = String(a).replace(/^[^0-9]*/, '').split('.').map((x) => parseInt(x, 10) || 0);
  const pb = String(b).replace(/^[^0-9]*/, '').split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// 判断版本是否落在 [introduced, fixed) 区间内
function inVulnRange(version, introduced, fixed) {
  if (introduced && compareVersions(version, introduced) < 0) return false;
  if (fixed && compareVersions(version, fixed) >= 0) return false;
  return true;
}

module.exports = {
  SKIP_DIRS,
  walkFiles,
  readText,
  readJson,
  lineAt,
  excerptAt,
  offsetToLineCol,
  nowIso,
  ensureDir,
  writeText,
  compareVersions,
  inVulnRange
};
