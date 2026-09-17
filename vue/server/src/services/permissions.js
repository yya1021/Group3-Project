const path = require('path');
const fs = require('fs');
const store = require('./store');

// 四种角色（英文标识 -> 中文名）
const ROLES = {
  admin: '管理员',
  merchant: '商户',
  user: '普通用户',
  auditor: '审计员'
};

// 六类资源（对应权限矩阵列）
const RESOURCES = ['product', 'order', 'user', 'role', 'system', 'audit'];

// 权限动作
const ACTIONS = ['read', 'create', 'update', 'delete', 'export'];

// 默认权限矩阵（严格遵循「权限矩阵.xlsx」）
const DEFAULT_PERMISSIONS = {
  admin: {
    product: ['read', 'create', 'update', 'delete'],
    order: ['read', 'create', 'update', 'delete'],
    user: ['read', 'create', 'update', 'delete'],
    role: ['read', 'create', 'update', 'delete'],
    system: ['read', 'create', 'update', 'delete'],
    audit: []
  },
  merchant: {
    product: ['read', 'create', 'update', 'delete'],
    order: ['read'],
    user: [],
    role: [],
    system: [],
    audit: []
  },
  user: {
    product: ['read'],
    order: ['read', 'create'],
    user: [],
    role: [],
    system: [],
    audit: []
  },
  auditor: {
    product: [],
    order: [],
    user: [],
    role: [],
    system: [],
    audit: ['read', 'export']
  }
};

// 数据范围（scope）
const SCOPES = {
  admin: 'all',       // 全部数据
  merchant: 'shop',   // 仅限本人店铺的商品和订单
  user: 'self',       // 仅限本人的订单和个人信息
  auditor: 'all'      // 全部审计日志
};

function getRolesFile() {
  return path.join(store.getDataDir(), 'roles.json');
}

// 读取角色权限配置（可被管理员动态修改）
function readRolePermissions() {
  try {
    const parsed = JSON.parse(fs.readFileSync(getRolesFile(), 'utf8'));
    if (parsed && parsed.roles && typeof parsed.roles === 'object') return parsed.roles;
  } catch (e) {}
  return JSON.parse(JSON.stringify(DEFAULT_PERMISSIONS));
}

function writeRolePermissions(roles) {
  try {
    fs.writeFileSync(getRolesFile(), JSON.stringify({ roles }, null, 2), 'utf8');
    return true;
  } catch (e) { return false; }
}

// 判断某角色是否拥有某资源上的某动作
function hasPermission(role, resource, action) {
  const roles = readRolePermissions();
  const perms = roles[role];
  if (!perms) return false;
  return Array.isArray(perms[resource]) && perms[resource].includes(action);
}

function getScope(role) {
  return SCOPES[role] || 'self';
}

module.exports = {
  ROLES,
  RESOURCES,
  ACTIONS,
  DEFAULT_PERMISSIONS,
  SCOPES,
  readRolePermissions,
  writeRolePermissions,
  hasPermission,
  getScope
};