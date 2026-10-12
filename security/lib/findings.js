'use strict';

const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

const SEVERITY_ORDER = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4
};

const SEVERITY_LABEL = {
  CRITICAL: '严重',
  HIGH: '高',
  MEDIUM: '中',
  LOW: '低',
  INFO: '提示'
};

// 报告文本用的符号标记
const SEVERITY_ICON = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '⚪',
  INFO: '🔵'
};

// 终端彩色标记（ANSI）
const SEVERITY_ANSI = {
  CRITICAL: '\u001b[41;97m',
  HIGH: '\u001b[31m',
  MEDIUM: '\u001b[33m',
  LOW: '\u001b[36m',
  INFO: '\u001b[90m'
};

const ANSI_RESET = '\u001b[0m';

/**
 * 创建一个发现条目。所有字段均来自真实扫描结果，禁止编造。
 */
function createFinding({
  id,
  title,
  severity = SEVERITY.MEDIUM,
  cwe = '',
  category = '',
  scanner,
  location = {},
  description = '',
  evidence = '',
  impact = '',
  recommendation = '',
  confidence = 'medium',
  status = 'fail',
  refs = []
}) {
  return {
    id,
    title,
    severity,
    cwe,
    category,
    scanner,
    location, // { file, line, endpoint }
    description,
    evidence,
    impact,
    recommendation,
    confidence, // high | medium | low
    status, // fail | pass | error
    refs
  };
}

// 按 (id + 文件 + 行 + 接口) 去重，保留首个
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = [
      f.id,
      (f.location && f.location.file) || '',
      (f.location && f.location.line) || '',
      (f.location && f.location.endpoint) || ''
    ].join('|');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

function sortFindings(findings) {
  return findings.slice().sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 9;
    const sb = SEVERITY_ORDER[b.severity] ?? 9;
    if (sa !== sb) return sa - sb;
    const ida = String(a.id || '');
    const idb = String(b.id || '');
    if (ida !== idb) return ida < idb ? -1 : 1;
    const fa = (a.location && a.location.file) || '';
    const fb = (b.location && b.location.file) || '';
    return fa < fb ? -1 : fa > fb ? 1 : 0;
  });
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) {
    if (counts[f.severity] == null) counts[f.severity] = 0;
    counts[f.severity]++;
  }
  return counts;
}

// 按严重度排序后重新编号（用于报告中的稳定序号）
function renumber(findings) {
  return findings.map((f, i) => ({ ...f, no: i + 1 }));
}

module.exports = {
  SEVERITY,
  SEVERITY_ORDER,
  SEVERITY_LABEL,
  SEVERITY_ICON,
  SEVERITY_ANSI,
  ANSI_RESET,
  createFinding,
  dedupe,
  sortFindings,
  countBySeverity,
  renumber
};
