const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const store = require('../src/services/store');
const totp = require('../src/services/totp');
const { createApp } = require('../src/app');

let tmpDataDir;
let tmpUploadsDir;
let app;
let adminToken;
let adminTotpSecret;

before(() => {
  tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-rbac-'));
  tmpUploadsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-uploads-'));
  store.configure({ dataDir: tmpDataDir, uploadsDir: tmpUploadsDir });
  app = createApp();
});

after(() => {
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (e) {}
  try { fs.rmSync(tmpUploadsDir, { recursive: true, force: true }); } catch (e) {}
});

// 管理员 TOTP 两步登录
async function loginAdmin() {
  if (adminToken) return adminToken;
  const res = await request(app).post('/api/login').send({ username: 'admin', password: 'admin123' });
  assert.equal(res.body.success, true);
  if (res.body.requireSetup) adminTotpSecret = res.body.totpSecret;
  const code = totp.generateTotp(adminTotpSecret);
  const r = await request(app).post('/api/login/totp').send({ challengeId: res.body.challengeId, code, totpSecret: adminTotpSecret });
  adminToken = r.body.token;
  return adminToken;
}

// 管理员创建三个角色账号
async function createUser(username, role) {
  const token = await loginAdmin();
  return request(app).post('/api/users').set('Authorization', token).send({ username, password: '123456', role });
}

async function loginNonAdmin(username) {
  const res = await request(app).post('/api/login').send({ username, password: '123456' });
  return res;
}

// ============ 管理员 TOTP 认证 ============
test('TOTP：错误动态码被拒绝', async () => {
  // 先完成管理员绑定
  await loginAdmin();
  // 已绑定后登录会要求 TOTP 验证
  const res = await request(app).post('/api/login').send({ username: 'admin', password: 'admin123' });
  assert.equal(res.body.requireTotp, true, '已绑定管理员登录应要求 TOTP');
  const bad = await request(app).post('/api/login/totp')
    .send({ challengeId: res.body.challengeId, code: '000000' });
  assert.equal(bad.status, 401);
  assert.equal(bad.body.success, false);
});

test('TOTP：未绑定管理员首次登录返回 otpauth 绑定信息', async () => {
  const token = await loginAdmin();
  const res = await request(app).post('/api/users').set('Authorization', token)
    .send({ username: 'admin2', password: '123456', role: 'admin' });
  assert.equal(res.status, 201);
  const login = await request(app).post('/api/login').send({ username: 'admin2', password: '123456' });
  assert.equal(login.body.requireSetup, true);
  assert.ok(login.body.otpauthUrl.startsWith('otpauth://totp/'));
  assert.ok(login.body.totpSecret);
});

// ============ 四角色权限矩阵 ============
test('用户管理：审计员不可访问', async () => {
  await createUser('auditor1', 'auditor');
  const login = await loginNonAdmin('auditor1');
  assert.equal(login.body.success, true);
  assert.equal(login.body.user.role, 'auditor');
  const res = await request(app).get('/api/users').set('Authorization', login.body.token);
  assert.equal(res.status, 403);
});

test('普通用户：可查看商品、创建订单、取消本人订单，不可取消他人订单', async () => {
  await createUser('user1', 'user');
  const login = await loginNonAdmin('user1');
  assert.equal(login.body.success, true);

  const products = await request(app).get('/api/products');
  assert.equal(products.status, 200);
  assert.ok(products.body.products.length > 0);

  const order = await request(app).post('/api/orders')
    .set('Authorization', login.body.token)
    .send({ products: [{ id: 1, amount: 1 }] });
  assert.equal(order.status, 201);
  assert.equal(order.body.success, true);

  // 下单者本人可取消自己的订单
  const del = await request(app).delete(`/api/orders/${order.body.order.id}`).set('Authorization', login.body.token);
  assert.equal(del.status, 200, '下单者本人可取消自己的订单');
  assert.equal(del.body.success, true);
});

test('普通用户：不可取消他人的订单', async () => {
  await createUser('user_owner', 'user');
  await createUser('user_other', 'user');
  const owner = await loginNonAdmin('user_owner');
  const other = await loginNonAdmin('user_other');

  const order = await request(app).post('/api/orders')
    .set('Authorization', owner.body.token)
    .send({ products: [{ id: 1, amount: 1 }] });
  assert.equal(order.status, 201);

  const del = await request(app).delete(`/api/orders/${order.body.order.id}`).set('Authorization', other.body.token);
  assert.equal(del.status, 403, '普通用户不可取消他人订单');
});

test('管理员：可查看所有订单并取消任意订单', async () => {
  await createUser('user_for_admin', 'user');
  const u = await loginNonAdmin('user_for_admin');
  const order = await request(app).post('/api/orders')
    .set('Authorization', u.body.token)
    .send({ products: [{ id: 2, amount: 1 }] });
  assert.equal(order.status, 201);

  const token = await loginAdmin();
  const list = await request(app).get('/api/orders').set('Authorization', token);
  assert.equal(list.status, 200);
  assert.ok(Array.isArray(list.body.orders));
  assert.ok(list.body.orders.some(o => o.username === 'user_for_admin'), '管理员能看到下单者');

  const del = await request(app).delete(`/api/orders/${order.body.order.id}`).set('Authorization', token);
  assert.equal(del.status, 200, '管理员可取消任意订单');
});

test('商户：可查看订单(读)、新增商品，但不可查看用户', async () => {
  await createUser('merchant1', 'merchant');
  const login = await loginNonAdmin('merchant1');
  assert.equal(login.body.success, true);

  const orders = await request(app).get('/api/orders').set('Authorization', login.body.token);
  assert.equal(orders.status, 200);

  const create = await request(app).post('/api/products')
    .set('Authorization', login.body.token)
    .send({ type: 'hand', name: '商户商品', price: 10, stock: 5 });
  assert.equal(create.status, 201, '商户应可新增商品');

  const users = await request(app).get('/api/users').set('Authorization', login.body.token);
  assert.equal(users.status, 403, '商户无用户管理权限');
});

test('管理员：可访问用户管理和角色管理', async () => {
  const token = await loginAdmin();
  const users = await request(app).get('/api/users').set('Authorization', token);
  assert.equal(users.status, 200);
  const roles = await request(app).get('/api/roles').set('Authorization', token);
  assert.equal(roles.status, 200);
  assert.ok(roles.body.matrix.admin.product.includes('create'));
});

// ============ 审计日志 ============
test('审计日志：审计员可查看并导出，普通用户不可访问', async () => {
  // 触发操作生成审计日志
  const token = await loginAdmin();
  await request(app).post('/api/products').set('Authorization', token).send({ type: 'other', name: '审计测试商品', price: 1, stock: 1 });

  // 审计员可查看
  await createUser('auditor2', 'auditor');
  const login = await loginNonAdmin('auditor2');
  const logs = await request(app).get('/api/audit-logs').set('Authorization', login.body.token);
  assert.equal(logs.status, 200);
  assert.ok(logs.body.logs.length > 0);

  // 审计员可导出 CSV
  const exportRes = await request(app).get('/api/audit-logs/export').set('Authorization', login.body.token);
  assert.equal(exportRes.status, 200);
  assert.ok(exportRes.text.includes('ID,操作者'));

  // 普通用户不可访问
  await createUser('user2', 'user');
  const userLogin = await loginNonAdmin('user2');
  const denied = await request(app).get('/api/audit-logs').set('Authorization', userLogin.body.token);
  assert.equal(denied.status, 403);
});

test('管理员：无审计日志查看权限（按权限矩阵）', async () => {
  const token = await loginAdmin();
  const res = await request(app).get('/api/audit-logs').set('Authorization', token);
  assert.equal(res.status, 403, '管理员在权限矩阵中审计日志为「无」');
});

// ============ 公开注册 ============
test('公开注册：新普通用户可注册并登录', async () => {
  const reg = await request(app).post('/api/register').send({ username: 'newbie', password: 'abc123' });
  assert.equal(reg.status, 201);
  assert.equal(reg.body.user.role, 'user');
  assert.ok(reg.body.token);

  const login = await request(app).post('/api/login').send({ username: 'newbie', password: 'abc123' });
  assert.equal(login.body.success, true);
});