const fs = require('fs');
const path = require('path');
const store = require('./store');

function getAuditFile() {
  return path.join(store.getDataDir(), 'audit-logs.json');
}

// 读取全部审计日志（按时间倒序）
function readLogs() {
  try {
    const parsed = JSON.parse(fs.readFileSync(getAuditFile(), 'utf8'));
    if (parsed && Array.isArray(parsed.logs)) return parsed.logs;
  } catch (e) {}
  return [];
}

function writeLogs(logs) {
  try {
    fs.writeFileSync(getAuditFile(), JSON.stringify({ logs }, null, 2), 'utf8');
    return true;
  } catch (e) { return false; }
}

// 记录一条审计日志
// operator: 操作者用户名；action: 动作；resource: 资源类型；detail: 附加信息；ip: 客户端IP
function log({ operator = 'unknown', role = 'anonymous', action, resource, detail = '', ip = '' }) {
  const logs = readLogs();
  logs.push({
    id: logs.length ? Math.max(...logs.map(l => l.id)) + 1 : 1,
    operator,
    role,
    action,
    resource,
    detail,
    ip,
    timestamp: new Date().toISOString()
  });
  // 防止无限增长：最多保留 2000 条
  while (logs.length > 2000) logs.shift();
  writeLogs(logs);
}

module.exports = { readLogs, writeLogs, log };