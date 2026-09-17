const express = require('express');
const store = require('../services/store');
const audit = require('../services/audit');
const { verifyToken, requirePermission } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 根据商品库补全购物车条目的名称/价格/图片/类型（保证前端展示与计价正确）
function enrichCart(cart) {
  if (!Array.isArray(cart)) return [];
  const products = store.readProducts();
  return cart
    .map(item => {
      const product = products.find(p => p.id === Number(item.id));
      if (!product) return null;
      return {
        id: product.id,
        name: product.name,
        price: product.price,
        photo: product.photo,
        type: product.type,
        amount: Number(item.amount) || 1
      };
    })
    .filter(Boolean);
}

// 购物车（挂在用户记录上）
// 获取当前用户购物车（补全商品信息）
router.get('/cart', verifyToken, (req, res) => {
  const users = store.readUsers();
  const user = users.find(u => u.username === req.user.username);
  const rawCart = (user && Array.isArray(user.cart)) ? user.cart : [];
  res.json({ success: true, cart: enrichCart(rawCart) });
});

// 更新当前用户购物车（只接收 id + amount，服务端补全商品信息后存储）
router.post('/cart', verifyToken, (req, res) => {
  const { cart } = req.body;
  if (!Array.isArray(cart)) return res.status(400).json({ success: false, error: '购物车数据格式错误' });
  const fullCart = enrichCart(cart);
  const users = store.readUsers();
  const idx = users.findIndex(u => u.username === req.user.username);
  if (idx === -1) return res.status(404).json({ success: false, error: '用户不存在' });
  users[idx].cart = fullCart;
  store.writeUsers(users);
  res.json({ success: true, cart: fullCart, message: '购物车已更新' });
});

// 创建订单（普通用户 / 管理员）
router.post('/orders', verifyToken, requirePermission('order', 'create'), async (req, res) => {
  // 模拟向银行发送支付认证请求：随机等待 1.5~3.5 秒
  const bankDelay = 1500 + Math.random() * 2000;
  await new Promise(resolve => setTimeout(resolve, bankDelay));

  const { products } = req.body;
  if (!products || !products.length) return res.status(400).json({ success: false, error: '商品列表不能为空' });

  const productList = store.readProducts();
  let totalAmount = 0;
  const insufficientItems = [];
  const updateStockList = [];

  for (const item of products) {
    const { id, amount } = item;
    const product = productList.find(p => p.id === Number(id));
    if (!product) { insufficientItems.push(`ID为${id}的商品不存在`); continue; }
    const buyAmount = Number(amount);
    if (!buyAmount || buyAmount <= 0) { insufficientItems.push(`${product.name} 购买数量无效`); continue; }
    if (product.stock < buyAmount) { insufficientItems.push(`${product.name} 库存不足，库存：${product.stock}，购买：${buyAmount}`); continue; }
    totalAmount += product.price * buyAmount;
    updateStockList.push({ product, buyAmount });
  }

  if (insufficientItems.length > 0) {
    return res.json({ success: false, message: '部分商品库存不足', details: insufficientItems });
  }

  for (const { product, buyAmount } of updateStockList) {
    product.stock -= buyAmount;
  }
  store.writeProducts(productList);

  const orders = store.readOrders();
  const order = {
    id: store.getNextId(orders),
    orderNumber: String(Date.now()),
    username: req.user.username,
    userId: req.user.userId,
    products: products.map(p => {
      const prod = productList.find(x => x.id === Number(p.id));
      return { id: Number(p.id), name: prod ? prod.name : String(p.id), price: prod ? prod.price : 0, amount: Number(p.amount) };
    }),
    totalAmount,
    status: 'paid',
    createdAt: new Date().toISOString()
  };
  orders.push(order);
  store.writeOrders(orders);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'create', resource: 'order', detail: `创建订单 #${order.id}，金额 ${totalAmount}`, ip: getClientIp(req) });
  res.status(201).json({ success: true, order, totalAmount, message: '订单创建成功' });
});

// 订单列表（按数据范围过滤）
router.get('/orders', verifyToken, requirePermission('order', 'read'), (req, res) => {
  let orders = store.readOrders();
  if (req.user.role === 'user') {
    orders = orders.filter(o => o.username === req.user.username);
  } else if (req.user.role === 'merchant') {
    // 商户仅看本人店铺商品相关订单
    const myProductIds = store.readProducts().filter(p => p.shopId === req.user.shopId).map(p => p.id);
    orders = orders.filter(o => o.products.some(p => myProductIds.includes(p.id)));
  }
  res.json({ success: true, orders });
});

// 取消订单（管理员可取消任意订单；下单者本人可取消自己的订单）
router.delete('/orders/:id', verifyToken, (req, res) => {
  const id = parseInt(req.params.id);
  const orders = store.readOrders();
  const idx = orders.findIndex(o => o.id === id);
  if (idx === -1) return res.status(404).json({ success: false, error: '订单不存在' });

  const order = orders[idx];
  const isAdmin = req.user.role === 'admin';
  const isOwner = order.username === req.user.username;
  if (!isAdmin && !isOwner) {
    return res.status(403).json({ success: false, error: '无权取消该订单' });
  }

  // 恢复库存
  const products = store.readProducts();
  for (const item of order.products || []) {
    const p = products.find(x => x.id === Number(item.id));
    if (p) p.stock += Number(item.amount) || 0;
  }
  store.writeProducts(products);

  orders.splice(idx, 1);
  store.writeOrders(orders);
  audit.log({ operator: req.user.username, role: req.user.role, action: 'delete', resource: 'order', detail: `取消订单 #${id}`, ip: getClientIp(req) });
  res.json({ success: true, message: '订单已取消' });
});

module.exports = router;