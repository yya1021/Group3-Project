const store = require('../services/store');
const { hasPermission } = require('../services/permissions');

// 登录令牌校验中间件：解析出当前用户，挂到 req.user
function verifyToken(req, res, next) {
  const token = req.headers['authorization'] || req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ success: false, error: '未登录' });
  const tokenData = store.getTokenData(token);
  if (!tokenData) return res.status(401).json({ success: false, error: '登录已过期' });

  // 兼容旧字段 admin，新字段 user
  req.user = {
    username: tokenData.username,
    role: tokenData.role,
    userId: tokenData.userId || null,
    shopId: tokenData.shopId || null
  };
  req.token = token;
  // 保留旧接口引用，兼容既有路由
  req.admin = req.user;
  next();
}

// RBAC 权限中间件工厂：requirePermission('order', 'create')
function requirePermission(resource, action) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, error: '未登录' });
    if (!hasPermission(req.user.role, resource, action)) {
      return res.status(403).json({ success: false, error: '无权限执行此操作' });
    }
    next();
  };
}

module.exports = { verifyToken, requirePermission };