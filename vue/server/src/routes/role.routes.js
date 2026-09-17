const express = require('express');
const store = require('../services/store');
const audit = require('../services/audit');
const permissions = require('../services/permissions');
const { verifyToken, requirePermission } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 角色列表与权限矩阵（管理员可读）
router.get('/roles', verifyToken, requirePermission('role', 'read'), (req, res) => {
  res.json({
    success: true,
    roles: permissions.ROLES,
    resources: permissions.RESOURCES,
    actions: permissions.ACTIONS,
    scopes: permissions.SCOPES,
    matrix: permissions.readRolePermissions()
  });
});

// 更新角色权限（管理员）
router.put('/roles/:role', verifyToken, requirePermission('role', 'update'), (req, res) => {
  const { role } = req.params;
  if (!permissions.ROLES[role]) return res.status(400).json({ success: false, error: '无效角色' });
  const matrix = permissions.readRolePermissions();
  const { permissions: newPerms } = req.body;
  if (newPerms && typeof newPerms === 'object') {
    matrix[role] = newPerms;
    permissions.writeRolePermissions(matrix);
    audit.log({ operator: req.user.username, role: req.user.role, action: 'update', resource: 'role', detail: `修改角色 ${role} 权限`, ip: getClientIp(req) });
  }
  res.json({ success: true, matrix: permissions.readRolePermissions(), message: '角色权限更新成功' });
});

module.exports = router;