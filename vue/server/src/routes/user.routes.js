const express = require('express');
const store = require('../services/store');
const audit = require('../services/audit');
const { verifyToken, requirePermission } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 安全返回用户信息（不暴露密码、TOTP 密钥与恢复码哈希）
function safeUser(u) {
  if (!u) return null;
  const { password, totpSecret, recoveryCodes, ...rest } = u;
  return { ...rest, totpEnabled: !!u.totpEnabled, recoveryCodesCount: (u.recoveryCodes || []).length };
}

// 用户列表（管理员）
router.get('/users', verifyToken, requirePermission('user', 'read'), (req, res) => {
  let users = store.readUsers().map(safeUser);
  // 普通用户仅能查看本人
  if (req.user.role === 'user') {
    users = users.filter(u => u.username === req.user.username);
  }
  res.json({ success: true, users });
});

// 创建用户（管理员）
router.post('/users', verifyToken, requirePermission('user', 'create'), (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ success: false, error: '用户名、密码和角色不能为空' });
  const validRoles = ['admin', 'merchant', 'user', 'auditor'];
  if (!validRoles.includes(role)) return res.status(400).json({ success: false, error: '无效角色' });
  const users = store.readUsers();
  if (users.find(u => u.username === username)) return res.status(409).json({ success: false, error: '用户名已存在' });

  const newUser = {
    id: store.getNextId(users),
    username: String(username).trim(),
    password: store.hashPassword(password),
    role,
    totpSecret: null,
    totpEnabled: false,
    shopId: role === 'merchant' ? (store.getNextId(users)) : null,
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  store.writeUsers(users);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'create', resource: 'user', detail: `创建用户 ${newUser.username}（角色 ${role}）`, ip: getClientIp(req) });
  res.status(201).json({ success: true, user: safeUser(newUser), message: '用户创建成功' });
});

// 修改用户（管理员）
router.put('/users/:id', verifyToken, requirePermission('user', 'update'), (req, res) => {
  const id = parseInt(req.params.id);
  const users = store.readUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ success: false, error: '用户不存在' });

  const { username, password, role } = req.body;
  if (role && !['admin', 'merchant', 'user', 'auditor'].includes(role)) return res.status(400).json({ success: false, error: '无效角色' });
  if (username) users[idx].username = String(username).trim();
  if (password) users[idx].password = store.hashPassword(password);
  if (role) users[idx].role = role;
  store.writeUsers(users);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'update', resource: 'user', detail: `修改用户 #${id}`, ip: getClientIp(req) });
  res.json({ success: true, user: safeUser(users[idx]), message: '用户修改成功' });
});

// 删除用户（管理员）
router.delete('/users/:id', verifyToken, requirePermission('user', 'delete'), (req, res) => {
  const id = parseInt(req.params.id);
  const users = store.readUsers();
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ success: false, error: '用户不存在' });
  const removed = users[idx];
  users.splice(idx, 1);
  store.writeUsers(users);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'delete', resource: 'user', detail: `删除用户 ${removed.username}`, ip: getClientIp(req) });
  res.json({ success: true, message: '用户删除成功' });
});

module.exports = router;