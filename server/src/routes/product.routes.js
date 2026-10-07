const express = require('express');
const store = require('../services/store');
const audit = require('../services/audit');
const { verifyToken, requirePermission } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 审计员在权限矩阵中对商品无任何权限：已登录审计员访问商品一律拒绝
function blockAuditor(req, res, next) {
  const token = req.headers['authorization'] || req.headers['x-auth-token'];
  if (token) {
    const tokenData = store.getTokenData(token);
    if (tokenData && tokenData.role === 'auditor') {
      return res.status(403).json({ success: false, error: '审计员无权访问商品' });
    }
  }
  next();
}

// 商品类型（对应第二个系统的 4 个分类）
const PRODUCT_TYPES = {
  hand: '手忍',
  knife: '刀忍',
  hamu: '哈姆',
  other: '其他'
};

// 公开：商品列表支持按类型过滤（普通用户/管理员/商户均可查看）
router.get('/products', blockAuditor, (req, res) => {
  let products = store.readProducts();
  const { type } = req.query;
  if (type && PRODUCT_TYPES[type]) {
    products = products.filter(p => p.type === type);
  }
  res.json({ success: true, products });
});

// 公开：按类型获取商品（兼容第二个系统 /hamu 等接口）
router.get('/products/type/:type', blockAuditor, (req, res) => {
  const { type } = req.params;
  if (!PRODUCT_TYPES[type]) return res.status(400).json({ success: false, error: '未知商品类型' });
  res.json({ success: true, products: store.readProducts().filter(p => p.type === type) });
});

// 商品图片（生成 SVG 占位图，按 id 着色）—— 必须放在 /products/:id 之前，避免被捕获
router.get('/products/photo/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const product = store.readProducts().find(p => p.id === id);
  const name = product ? product.name : `商品 ${id}`;
  const colors = ['#457b9d', '#e63946', '#2a9d8f', '#e76f51', '#6d597a', '#b56576'];
  const color = colors[id % colors.length];
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300" viewBox="0 0 300 300"><rect width="300" height="300" fill="${color}"/><text x="150" y="150" font-size="22" fill="#fff" text-anchor="middle" font-family="sans-serif">${name}</text></svg>`;
  res.type('image/svg+xml').send(svg);
});

// 公开：商品详情
router.get('/products/:id', blockAuditor, (req, res) => {
  const product = store.readProducts().find(p => p.id === parseInt(req.params.id));
  if (!product) return res.status(404).json({ success: false, error: '商品不存在' });
  res.json({ success: true, product });
});

// 新增商品（管理员/商户）
router.post('/products', verifyToken, requirePermission('product', 'create'), (req, res) => {
  const { type, name, price, stock, photo } = req.body;
  if (!type || !name) return res.status(400).json({ success: false, error: '商品类型和名称不能为空' });
  if (!PRODUCT_TYPES[type]) return res.status(400).json({ success: false, error: '未知商品类型' });
  const products = store.readProducts();
  const newProduct = {
    id: store.getNextId(products),
    type,
    name: String(name).trim(),
    price: Number(price) || 0,
    stock: Number(stock) || 0,
    photo: photo || `/api/products/photo/${store.getNextId(products)}`,
    shopId: req.user.shopId || null,
    createdAt: new Date().toISOString()
  };
  products.push(newProduct);
  store.writeProducts(products);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'create', resource: 'product', detail: `新增商品 #${newProduct.id} ${newProduct.name}`, ip: getClientIp(req) });
  res.status(201).json({ success: true, product: newProduct, message: '商品新增成功' });
});

// 修改商品（管理员全量 / 商户仅本人店铺）
router.put('/products/:id', verifyToken, requirePermission('product', 'update'), (req, res) => {
  const id = parseInt(req.params.id);
  const products = store.readProducts();
  const idx = products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ success: false, error: '商品不存在' });
  // 商户数据范围：仅限本人店铺
  if (req.user.role === 'merchant' && products[idx].shopId !== req.user.shopId) {
    return res.status(403).json({ success: false, error: '无权限操作其他店铺商品' });
  }
  const { type, name, price, stock, photo } = req.body;
  if (type && !PRODUCT_TYPES[type]) return res.status(400).json({ success: false, error: '未知商品类型' });
  products[idx] = {
    ...products[idx],
    ...(type && { type }),
    ...(name !== undefined && { name: String(name).trim() }),
    ...(price !== undefined && { price: Number(price) }),
    ...(stock !== undefined && { stock: Number(stock) }),
    ...(photo !== undefined && { photo }),
    updatedAt: new Date().toISOString()
  };
  store.writeProducts(products);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'update', resource: 'product', detail: `修改商品 #${id}`, ip: getClientIp(req) });
  res.json({ success: true, product: products[idx], message: '商品修改成功' });
});

// 删除商品（管理员全量 / 商户仅本人店铺）
router.delete('/products/:id', verifyToken, requirePermission('product', 'delete'), (req, res) => {
  const id = parseInt(req.params.id);
  const products = store.readProducts();
  const idx = products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ success: false, error: '商品不存在' });
  if (req.user.role === 'merchant' && products[idx].shopId !== req.user.shopId) {
    return res.status(403).json({ success: false, error: '无权限操作其他店铺商品' });
  }
  products.splice(idx, 1);
  store.writeProducts(products);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'delete', resource: 'product', detail: `删除商品 #${id}`, ip: getClientIp(req) });
  res.json({ success: true, message: '商品删除成功' });
});

module.exports = router;