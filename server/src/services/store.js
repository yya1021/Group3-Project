const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');

// 数据与上传目录（测试时可注入临时目录）
let DATA_DIR = config.DATA_DIR;
let UPLOADS_DIR = config.UPLOADS_DIR;

const POSTS_FILE = () => path.join(DATA_DIR, 'posts.json');
const PENDING_FILE = () => path.join(DATA_DIR, 'pending-posts.json');
const ADMIN_FILE = () => path.join(DATA_DIR, 'admin.json');
const FILES_FILE = () => path.join(DATA_DIR, 'files.json');
const COMMENTS_FILE = () => path.join(DATA_DIR, 'comments.json');
const USERS_FILE = () => path.join(DATA_DIR, 'users.json');
const PRODUCTS_FILE = () => path.join(DATA_DIR, 'products.json');
const ORDERS_FILE = () => path.join(DATA_DIR, 'orders.json');

// 登录令牌存储（内存）
const validTokens = new Map();
// TOTP 两步登录的临时挑战（内存）：authChallengeId -> { username, role, expiresAt }
const authChallenges = new Map();

function configure(dirs) {
  if (dirs.dataDir) DATA_DIR = dirs.dataDir;
  if (dirs.uploadsDir) UPLOADS_DIR = dirs.uploadsDir;
  ensureStructure();
}

function ensureStructure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

  const files = [
    [POSTS_FILE(), { posts: [] }],
    [PENDING_FILE(), { posts: [] }],
    [FILES_FILE(), { files: [] }],
    [COMMENTS_FILE(), { comments: [] }],
    [USERS_FILE(), { users: [] }],
    [PRODUCTS_FILE(), { products: [] }],
    [ORDERS_FILE(), { orders: [] }]
  ];
  for (const [file, def] of files) {
    if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(def, null, 2), 'utf8');
  }

  // 初始化默认管理员（四角色中的 admin）
  const users = readUsers();
  if (!users.find(u => u.username === 'admin')) {
    users.push({
      id: getNextId(users),
      username: 'admin',
      password: hashPassword('admin123'),
      role: 'admin',
      totpSecret: null,
      totpEnabled: false,
      shopId: null,
      createdAt: new Date().toISOString()
    });
    writeUsers(users);
  }

  // 兼容旧 admin.json：若存在旧管理员且 users 为空，迁移之
  if (!fs.existsSync(ADMIN_FILE())) {
    fs.writeFileSync(ADMIN_FILE(), JSON.stringify({
      admins: [{
        id: 1,
        username: 'admin',
        password: hashPassword('admin123'),
        role: 'admin',
        createdAt: new Date().toISOString()
      }]
    }, null, 2), 'utf8');
  }

  // 初始化商品数据（迁移自第二个系统的演示商品）
  if (readProducts().length === 0) {
    const products = [
      { type: 'hand', name: '防滑防护手套', id: 1, price: 15, stock: 86, photo: '/api/products/photo/1' },
      { type: 'hand', name: '透气耐磨防护手套', id: 2, price: 15, stock: 92, photo: '/api/products/photo/2' },
      { type: 'knife', name: '多功能便携水果刀', id: 3, price: 20, stock: 45, photo: '/api/products/photo/3' },
      { type: 'hamu', name: '精品烟熏火腿', id: 4, price: 25, stock: 11, photo: '/api/products/photo/4' },
      { type: 'other', name: '创意解压小摆件', id: 5, price: 30, stock: 67, photo: '/api/products/photo/5' },
      { type: 'other', name: '原味香飘飘奶茶', id: 6, price: 12, stock: 120, photo: '/api/products/photo/6' }
    ];
    writeProducts(products);
  }
}

// 通用读取/写入
function readJson(file, key) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && Array.isArray(parsed[key])) return parsed[key];
    return [];
  } catch (e) { return []; }
}

function writeJson(file, key, items) {
  try { fs.writeFileSync(file, JSON.stringify({ [key]: items }, null, 2), 'utf8'); return true; }
  catch (e) { return false; }
}

function getNextId(items) {
  if (items.length === 0) return 1;
  return Math.max(...items.map(i => i.id)) + 1;
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(String(password)).digest('hex');
}

function generateToken(username) {
  return crypto.createHash('sha256').update(username + Date.now() + Math.random()).digest('hex');
}

// ============ 文章 ============
const readPosts = () => readJson(POSTS_FILE(), 'posts');
const writePosts = (posts) => writeJson(POSTS_FILE(), 'posts', posts);
const readPendingPosts = () => readJson(PENDING_FILE(), 'posts');
const writePendingPosts = (posts) => writeJson(PENDING_FILE(), 'posts', posts);

// ============ 用户（四角色统一）============
const readUsers = () => readJson(USERS_FILE(), 'users');
const writeUsers = (users) => writeJson(USERS_FILE(), 'users', users);

// ============ 商品 ============
const readProducts = () => readJson(PRODUCTS_FILE(), 'products');
const writeProducts = (products) => writeJson(PRODUCTS_FILE(), 'products', products);

// ============ 订单 ============
const readOrders = () => readJson(ORDERS_FILE(), 'orders');
const writeOrders = (orders) => writeJson(ORDERS_FILE(), 'orders', orders);

// ============ 管理员（兼容旧数据）============
function readAdmins() {
  try {
    const parsed = JSON.parse(fs.readFileSync(ADMIN_FILE(), 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Array.isArray(parsed.admins)) return parsed.admins;
    if (Array.isArray(parsed)) return parsed;
    return [];
  } catch (e) { return []; }
}
function writeAdmins(admins) {
  try { fs.writeFileSync(ADMIN_FILE(), JSON.stringify({ admins }, null, 2), 'utf8'); return true; }
  catch (e) { return false; }
}

// ============ 文件 ============
const readFiles = () => readJson(FILES_FILE(), 'files');
const writeFiles = (files) => writeJson(FILES_FILE(), 'files', files);
const getUploadsDir = () => UPLOADS_DIR;

// ============ 评论 ============
const readComments = () => readJson(COMMENTS_FILE(), 'comments');
const writeComments = (comments) => writeJson(COMMENTS_FILE(), 'comments', comments);

// 当前数据目录（供其他服务动态获取，测试隔离时跟随 configure）
const getDataDir = () => DATA_DIR;

// ============ 令牌 ============
function createToken(username, role, extra = {}) {
  const token = generateToken(username);
  const record = { username, role: role || 'user', ...extra, expiresAt: Date.now() + config.TOKEN_TTL };
  validTokens.set(token, record);
  return token;
}

function getTokenData(token) {
  const data = validTokens.get(token);
  if (!data || data.expiresAt < Date.now()) {
    validTokens.delete(token);
    return null;
  }
  return data;
}

function destroyToken(token) {
  validTokens.delete(token);
}

function getValidTokens() {
  return validTokens;
}

// ============ TOTP 两步登录挑战 ============
function createAuthChallenge(username, role, extra = {}) {
  const id = generateToken('challenge' + username);
  authChallenges.set(id, { username, role, ...extra, expiresAt: Date.now() + 5 * 60 * 1000 });
  return id;
}

function consumeAuthChallenge(id) {
  const data = authChallenges.get(id);
  if (!data || data.expiresAt < Date.now()) {
    authChallenges.delete(id);
    return null;
  }
  authChallenges.delete(id);
  return data;
}

module.exports = {
  configure,
  ensureStructure,
  getNextId,
  hashPassword,
  readPosts,
  writePosts,
  readPendingPosts,
  writePendingPosts,
  readUsers,
  writeUsers,
  readProducts,
  writeProducts,
  readOrders,
  writeOrders,
  readAdmins,
  writeAdmins,
  readFiles,
  writeFiles,
  readComments,
  writeComments,
  getDataDir,
  getUploadsDir,
  createToken,
  getTokenData,
  destroyToken,
  getValidTokens,
  createAuthChallenge,
  consumeAuthChallenge,
  DATA_DIR,
  UPLOADS_DIR
};