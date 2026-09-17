const express = require('express');
const audit = require('../services/audit');
const { verifyToken, requirePermission } = require('../middleware/auth');

const router = express.Router();

// 审计日志列表（仅审计员/管理员）
router.get('/audit-logs', verifyToken, requirePermission('audit', 'read'), (req, res) => {
  const logs = audit.readLogs();
  res.json({ success: true, logs });
});

// 导出审计报告（仅审计员/管理员）—— 生成 CSV 文本
router.get('/audit-logs/export', verifyToken, requirePermission('audit', 'export'), (req, res) => {
  const logs = audit.readLogs();
  const header = ['ID', '操作者', '角色', '动作', '资源', '详情', 'IP', '时间'];
  const rows = logs.map(l => [
    l.id,
    l.operator,
    l.role,
    l.action,
    l.resource,
    l.detail || '',
    l.ip || '',
    l.timestamp
  ]);
  const csv = [header, ...rows]
    .map(row => row.map(cell => {
      const s = String(cell == null ? '' : cell);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(','))
    .join('\n');

  res.type('text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-report.csv"');
  res.send('\uFEFF' + csv);
});

module.exports = router;