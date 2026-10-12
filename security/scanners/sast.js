'use strict';

const path = require('path');
const { RULES } = require('../lib/rules');
const util = require('../lib/util');
const { createFinding, dedupe, sortFindings } = require('../lib/findings');

const SCAN_EXTS = ['.js', '.mjs', '.cjs', '.ts', '.vue', '.json', '.ps1', '.sh', '.yml', '.yaml'];

// 规则目标匹配：精确路径 / 目录前缀 / 通配
function matchTarget(patterns, relPath) {
  for (const p of patterns) {
    if (p.includes('*')) {
      const rx = new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*') + '$');
      if (rx.test(relPath)) return true;
      continue;
    }
    if (p.endsWith('/')) {
      if (relPath.startsWith(p)) return true;
      continue;
    }
    if (relPath === p) return true;
  }
  return false;
}

function makeContext(rootDir, relPath) {
  const absPath = path.join(rootDir, relPath);
  const content = util.readText(absPath);
  return {
    root: rootDir,
    relPath,
    absPath,
    content: content || '',
    linePreview(n) {
      return util.lineAt(content || '', n);
    }
  };
}

/**
 * 构造单点发现。
 */
function buildFinding(rule, relPath, content, hit) {
  return createFinding({
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    cwe: rule.cwe,
    category: rule.category,
    scanner: 'sast',
    confidence: rule.confidence,
    location: { file: relPath, line: hit.line },
    description: rule.description,
    evidence:
      (hit.note ? `说明：${hit.note}\n` : '') +
      `代码片段：\n${util.excerptAt(content, hit.line, 2)}\n` +
      `原始行：${hit.evidence || util.lineAt(content, hit.line)}`,
    impact: rule.impact,
    recommendation: rule.recommendation
  });
}

/**
 * 构造聚合发现：同一规则的所有命中合并为一条，证据中逐条列出文件、行号与代码。
 */
function buildAggregatedFinding(rule, hits) {
  const list = hits
    .map(({ relPath, ctx, hit }) => {
      const label = hit.note ? `【${hit.note}】` : '';
      return `- ${relPath}:${hit.line} ${label}\n    代码：${(hit.evidence || util.lineAt(ctx.content, hit.line)).trim()}`;
    })
    .join('\n');

  const first = hits[0];
  const title = `${rule.title}（共 ${hits.length} 处）`;

  return createFinding({
    id: rule.id,
    title,
    severity: rule.severity,
    cwe: rule.cwe,
    category: rule.category,
    scanner: 'sast',
    confidence: rule.confidence,
    location: { file: first.relPath, line: first.hit.line },
    description: rule.description + `\n\n本次共命中 **${hits.length}** 处，逐条如下。`,
    evidence: `命中清单（文件:行号）：\n${list}`,
    impact: rule.impact,
    recommendation: rule.recommendation,
    refs: [`命中数量：${hits.length}`]
  });
}

/**
 * 执行 SAST 扫描。
 * @returns {{ findings: object[], meta: object }}
 */
function runSast({ rootDir, log = () => {} }) {
  log('SAST: 收集待扫描文件…');
  // security/reports 是本工具的产物目录，纳入扫描只会引入自指噪声
  const files = util
    .walkFiles(rootDir, { exts: SCAN_EXTS })
    .filter((f) => !f.startsWith('security/reports/'));
  log(`SAST: 共 ${files.length} 个文件进入扫描范围`);

  const findings = [];
  const ruleHits = new Map();
  for (const rule of RULES) ruleHits.set(rule.id, 0);

  for (const rule of RULES) {
    const targets = rule.files ? files.filter((f) => matchTarget(rule.files, f)) : files;
    // 需要聚合的规则：先把所有命中收集起来，最后合并为一条发现
    const aggregateHits = [];

    for (const relPath of targets) {
      const ctx = makeContext(rootDir, relPath);
      if (!ctx.content) continue;

      const push = (hit) => {
        if (rule.aggregate) {
          aggregateHits.push({ relPath, ctx, hit });
        } else {
          findings.push(buildFinding(rule, relPath, ctx.content, hit));
        }
        ruleHits.set(rule.id, ruleHits.get(rule.id) + 1);
      };

      if (typeof rule.check === 'function') {
        const hits = rule.check(ctx) || [];
        hits.forEach(push);
      } else if (rule.pattern) {
        const rx = new RegExp(rule.pattern.source, rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g');
        let m;
        while ((m = rx.exec(ctx.content)) !== null) {
          const { line } = util.offsetToLineCol(ctx.content, m.index);
          push({ line, evidence: util.lineAt(ctx.content, line) });
          if (m.index === rx.lastIndex) rx.lastIndex++;
        }
      }
    }

    if (rule.aggregate && aggregateHits.length) {
      findings.push(buildAggregatedFinding(rule, aggregateHits));
    }
  }

  const unique = sortFindings(dedupe(findings));
  const uncovered = RULES.map((r) => r.id).filter((id) => ruleHits.get(id) === 0);

  log(`SAST: 命中 ${unique.length} 条发现，涉及 ${new Set(unique.map((f) => f.id)).size} 条规则`);

  return {
    findings: unique,
    meta: {
      scannedFiles: files.length,
      rulesTotal: RULES.length,
      rulesHit: RULES.length - uncovered.length,
      rulesWithoutHits: uncovered,
      ruleHits: Object.fromEntries(ruleHits)
    }
  };
}

module.exports = { runSast, matchTarget };
