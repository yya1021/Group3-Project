const express = require('express');
const store = require('../services/store');
const audit = require('../services/audit');
const totp = require('../services/totp');
const { verifyToken } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 安全返回用户信息（不暴露密码、TOTP 密钥与恢复码哈希）
function safeUser(u) {
  if (!u) return null;
  const { password, totpSecret, recoveryCodes, ...rest } = u;
  return { ...rest, totpEnabled: !!u.totpEnabled, recoveryCodesCount: (u.recoveryCodes || []).length };
}

// 登录（第一步：验证用户名密码）
// - 普通用户/商户/审计员：直接返回 token
// - 管理员：进入 TOTP 二次认证（已绑定）或 TOTP 绑定流程（首次）
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, error: '用户名和密码不能为空' });

  const users = store.readUsers();
  const user = users.find(u => u.username === username);
  if (!user) {
    audit.log({ operator: username, role: 'anonymous', action: 'login_failed', resource: 'auth', detail: '用户不存在', ip: getClientIp(req) });
    return res.status(401).json({ success: false, error: '用户名或密码错误' });
  }

  const hashedInput = store.hashPassword(password);
  const passwordMatches = user.password === hashedInput || user.password === password;
  if (!passwordMatches) {
    audit.log({ operator: username, role: user.role, action: 'login_failed', resource: 'auth', detail: '密码错误', ip: getClientIp(req) });
    return res.status(401).json({ success: false, error: '用户名或密码错误' });
  }

  // 明文密码自动升级为哈希
  if (user.password === password) {
    const allUsers = store.readUsers();
    const idx = allUsers.findIndex(u => u.id === user.id);
    if (idx !== -1) { allUsers[idx].password = hashedInput; store.writeUsers(allUsers); }
  }

  // 管理员需要 TOTP 二次认证
  if (user.role === 'admin') {
    if (user.totpEnabled) {
      const challengeId = store.createAuthChallenge(user.username, user.role);
      audit.log({ operator: user.username, role: user.role, action: 'login_totp_required', resource: 'auth', detail: '管理员登录，要求 TOTP', ip: getClientIp(req) });
      return res.json({ success: true, requireTotp: true, challengeId, username: user.username });
    }
    // 首次登录：生成新密钥 + 一次性恢复码，引导管理员绑定 Microsoft Authenticator
    const secret = totp.generateSecret();
    const recoveryCodes = totp.generateRecoveryCodes(5);
    const challengeId = store.createAuthChallenge(user.username, user.role, { pendingRecoveryCodes: recoveryCodes });
    return res.json({
      success: true,
      requireSetup: true,
      challengeId,
      username: user.username,
      totpSecret: secret,
      otpauthUrl: totp.buildOtpauthUrl({ secret, label: user.username })
    });
  }

  // 其他角色直接登录
  const token = store.createToken(user.username, user.role, { userId: user.id, shopId: user.shopId || null });
  audit.log({ operator: user.username, role: user.role, action: 'login', resource: 'auth', detail: '登录成功', ip: getClientIp(req) });
  res.json({ success: true, token, user: safeUser(user) });
});

// 登录（第二步：TOTP 验证/绑定，或使用一次性恢复码登录）
router.post('/login/totp', (req, res) => {
  const { challengeId, code, totpSecret, recoveryCode } = req.body;
  if (!challengeId || (!code && !recoveryCode)) return res.status(400).json({ success: false, error: '缺少认证参数' });

  const challenge = store.consumeAuthChallenge(challengeId);
  if (!challenge) return res.status(401).json({ success: false, error: '认证会话已过期，请重新登录' });

  const users = store.readUsers();
  const user = users.find(u => u.username === challenge.username);
  if (!user) return res.status(401).json({ success: false, error: '用户不存在' });

  // 已绑定：优先尝试一次性恢复码，其次动态码
  if (user.totpEnabled) {
    if (recoveryCode) {
      const hashed = totp.hashRecoveryCode(recoveryCode);
      const idx = (user.recoveryCodes || []).indexOf(hashed);
      if (idx === -1) {
        audit.log({ operator: user.username, role: user.role, action: 'login_recovery_failed', resource: 'auth', detail: '恢复码验证失败', ip: getClientIp(req) });
        return res.status(401).json({ success: false, error: '恢复码无效或已被使用' });
      }
      // 一次性：使用后立即移除
      user.recoveryCodes.splice(idx, 1);
      store.writeUsers(users);
      const token = store.createToken(user.username, user.role, { userId: user.id, shopId: user.shopId || null });
      audit.log({ operator: user.username, role: user.role, action: 'login_recovery', resource: 'auth', detail: '使用恢复码登录', ip: getClientIp(req) });
      return res.json({ success: true, token, user: safeUser(user) });
    }

    // 动态码验证
    if (!totp.verifyTotp(user.totpSecret, code)) {
      audit.log({ operator: user.username, role: user.role, action: 'login_totp_failed', resource: 'auth', detail: 'TOTP 验证失败', ip: getClientIp(req) });
      return res.status(401).json({ success: false, error: '动态验证码错误' });
    }
  } else {
    // 首次绑定：用前端传来的临时 secret 完成绑定确认
    const secret = totpSecret || user.totpSecret;
    if (!totp.verifyTotp(secret, code)) {
      return res.status(400).json({ success: false, error: '验证码错误，绑定失败，请重新登录' });
    }
    if (!user.totpSecret && totpSecret) {
      user.totpSecret = totpSecret;
      user.totpEnabled = true;
      // 持久化恢复码哈希（明文仅在此处一次性返回给前端展示）
      const codes = challenge.pendingRecoveryCodes || [];
      user.recoveryCodes = codes.map(c => totp.hashRecoveryCode(c));
      store.writeUsers(users);
      const token = store.createToken(user.username, user.role, { userId: user.id, shopId: user.shopId || null });
      audit.log({ operator: user.username, role: user.role, action: 'login', resource: 'auth', detail: '管理员 TOTP 绑定成功', ip: getClientIp(req) });
      return res.json({ success: true, token, user: safeUser(user), recoveryCodes: codes });
    }
  }

  const token = store.createToken(user.username, user.role, { userId: user.id, shopId: user.shopId || null });
  audit.log({ operator: user.username, role: user.role, action: 'login', resource: 'auth', detail: '管理员 TOTP 认证成功', ip: getClientIp(req) });
  res.json({ success: true, token, user: safeUser(user) });
});

// 重新生成一次性恢复码（管理员，仅限本人）
router.post('/recovery-codes/regenerate', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: '仅管理员可重新生成恢复码' });
  }
  const users = store.readUsers();
  const user = users.find(u => u.username === req.user.username);
  if (!user) return res.status(404).json({ success: false, error: '用户不存在' });

  const codes = totp.generateRecoveryCodes(5);
  user.recoveryCodes = codes.map(c => totp.hashRecoveryCode(c));
  store.writeUsers(users);
  audit.log({ operator: user.username, role: user.role, action: 'recovery_codes_regenerate', resource: 'auth', detail: '重新生成恢复码', ip: getClientIp(req) });
  res.json({ success: true, recoveryCodes: codes });
});

// 公开注册（普通用户 / 商户；管理员与审计员不允许公开注册）
router.post('/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, error: '用户名和密码不能为空' });
  // 仅允许公开注册 user 和 merchant
  const requestedRole = role || 'user';
  if (!['user', 'merchant'].includes(requestedRole)) {
    return res.status(400).json({ success: false, error: '不允许公开注册该角色' });
  }
  const users = store.readUsers();
  if (users.find(u => u.username === username)) {
    return res.status(409).json({ success: false, error: '用户名已存在' });
  }
  const isMerchant = requestedRole === 'merchant';
  const newUser = {
    id: store.getNextId(users),
    username: String(username).trim(),
    password: store.hashPassword(password),
    role: requestedRole,
    totpSecret: null,
    totpEnabled: false,
    // 商户分配店铺 ID（当前为自增 ID，作为简单店铺标识）
    shopId: isMerchant ? store.getNextId(users) : null,
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  store.writeUsers(users);
  audit.log({ operator: newUser.username, role: requestedRole, action: 'register', resource: 'user', detail: (isMerchant ? '商户' : '普通用户') + '注册', ip: getClientIp(req) });
  const token = store.createToken(newUser.username, newUser.role, { userId: newUser.id, shopId: newUser.shopId || null });
  res.status(201).json({ success: true, token, user: safeUser(newUser) });
});

// 当前用户信息
router.get('/me', verifyToken, (req, res) => {
  const user = store.readUsers().find(u => u.username === req.user.username);
  res.json({ success: true, user: safeUser(user) });
});

// 登出
router.post('/logout', verifyToken, (req, res) => {
  audit.log({ operator: req.user.username, role: req.user.role, action: 'logout', resource: 'auth', detail: '登出', ip: getClientIp(req) });
  store.destroyToken(req.token);
  res.json({ success: true, message: '登出成功' });
});

module.exports = router;