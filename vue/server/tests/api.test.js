const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const request = require('supertest');

const store = require('../src/services/store');
const totp = require('../src/services/totp');
const { createApp } = require('../src/app');

// ============ 测试隔离：使用临时数据目录 ============
let tmpDataDir;
let tmpUploadsDir;
let app;
let token;

before(() => {
  tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-data-'));
  tmpUploadsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-uploads-'));
  store.configure({ dataDir: tmpDataDir, uploadsDir: tmpUploadsDir });
  app = createApp();
});

after(() => {
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (e) {}
  try { fs.rmSync(tmpUploadsDir, { recursive: true, force: true }); } catch (e) {}
});

// 管理员登录（供受保护接口使用）—— 管理员需经过 TOTP 两步认证
let adminTotpSecret = null;

async function loginAsAdmin() {
  const res = await request(app).post('/api/login').send({ username: 'admin', password: 'admin123' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  // 首次登录进入 TOTP 绑定流程
  if (res.body.requireSetup) {
    adminTotpSecret = res.body.totpSecret;
  }
  assert.ok(adminTotpSecret, '应取得管理员 TOTP 密钥');
  const code = totp.generateTotp(adminTotpSecret);
  const totpRes = await request(app).post('/api/login/totp')
    .send({ challengeId: res.body.challengeId, code, totpSecret: adminTotpSecret });
  assert.equal(totpRes.status, 200);
  assert.equal(totpRes.body.success, true);
  return totpRes.body.token;
}

// ============ 认证 ============
test('登录：用户名密码错误返回 401', async () => {
  const res = await request(app).post('/api/login').send({ username: 'admin', password: 'wrong' });
  assert.equal(res.status, 401);
  assert.equal(res.body.success, false);
});

test('登录：缺少参数返回 400', async () => {
  const res = await request(app).post('/api/login').send({ username: 'admin' });
  assert.equal(res.status, 400);
});

test('登录：管理员正确凭据进入 TOTP 二次认证', async () => {
  const res = await request(app).post('/api/login').send({ username: 'admin', password: 'admin123' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  // 首次进入绑定流程，后续进入验证流程
  assert.ok(res.body.requireSetup || res.body.requireTotp);
  assert.ok(res.body.challengeId);
  assert.ok(!res.body.token, '管理员登录不应直接返回 token');
});

test('受保护接口：未登录返回 401', async () => {
  const res = await request(app).get('/api/pending');
  assert.equal(res.status, 401);
});

test('登出后令牌失效', async () => {
  const t = await loginAsAdmin();
  await request(app).post('/api/logout').set('Authorization', t).expect(200);
  const res = await request(app).get('/api/pending').set('Authorization', t);
  assert.equal(res.status, 401);
});

// ============ 文章 ============
test('文章：初始列表为空', async () => {
  const res = await request(app).get('/api/posts');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.posts, []);
});

test('文章：提交文章进入待审核', async () => {
  const res = await request(app).post('/api/posts')
    .send({ title: '测试文章', content: '<p>内容</p>', author: '小明', category: '技术', tags: ['vue', 'test'] });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
});

test('文章：缺少标题/内容返回 400', async () => {
  const res = await request(app).post('/api/posts').send({ title: '只有标题' });
  assert.equal(res.status, 400);
});

test('文章：未审核前公开列表不包含该文章', async () => {
  const res = await request(app).get('/api/posts');
  assert.equal(res.body.posts.length, 0);
});

test('文章：审核通过后进入公开列表', async () => {
  token = await loginAsAdmin();
  const pendingRes = await request(app).get('/api/pending').set('Authorization', token);
  const pending = pendingRes.body.posts.find(p => p.title === '测试文章');
  assert.ok(pending, '应存在待审核文章');
  const approveRes = await request(app).post(`/api/approve/${pending.id}`).set('Authorization', token);
  assert.equal(approveRes.status, 200);
  const listRes = await request(app).get('/api/posts');
  assert.equal(listRes.body.posts.length, 1);
  assert.equal(listRes.body.posts[0].title, '测试文章');
});

test('文章：按 id 获取与 404', async () => {
  const listRes = await request(app).get('/api/posts');
  const post = listRes.body.posts[0];
  const res = await request(app).get(`/api/posts/${post.id}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.post.title, '测试文章');
  const miss = await request(app).get('/api/posts/99999');
  assert.equal(miss.status, 404);
});

test('文章：管理员更新已发布文章', async () => {
  const listRes = await request(app).get('/api/posts');
  const post = listRes.body.posts[0];
  const res = await request(app).put(`/api/update/${post.id}`)
    .set('Authorization', token)
    .send({ title: '测试文章-改', author: '小红', category: '哲学', content: '<p>新内容</p>', tags: ['更新'], type: 'published' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  const after = await request(app).get(`/api/posts/${post.id}`);
  assert.equal(after.body.post.title, '测试文章-改');
});

test('文章：拒绝待审核文章', async () => {
  await request(app).post('/api/posts').send({ title: '将被拒绝', content: '内容' });
  const pendingRes = await request(app).get('/api/pending').set('Authorization', token);
  const pending = pendingRes.body.posts.find(p => p.title === '将被拒绝');
  const res = await request(app).post(`/api/reject/${pending.id}`).set('Authorization', token);
  assert.equal(res.status, 200);
  const after = await request(app).get('/api/pending').set('Authorization', token);
  assert.equal(after.body.posts.find(p => p.title === '将被拒绝'), undefined);
});

test('文章：管理员删除文章', async () => {
  const listRes = await request(app).get('/api/posts');
  const post = listRes.body.posts[0];
  const res = await request(app).delete(`/api/posts/${post.id}`).set('Authorization', token);
  assert.equal(res.status, 200);
  const after = await request(app).get('/api/posts');
  assert.equal(after.body.posts.find(p => p.id === post.id), undefined);
});

// ============ 文件 ============
test('文件：未登录上传返回 401', async () => {
  const res = await request(app).post('/api/files').send({ title: 'x', fileName: 'a.txt', fileData: 'aGVsbG8=' });
  assert.equal(res.status, 401);
});

test('文件：上传成功并出现在列表', async () => {
  token = await loginAsAdmin();
  const res = await request(app).post('/api/files')
    .set('Authorization', token)
    .send({ title: '测试文件', author: '小明', category: '技术', description: '说明', fileName: 'hello.txt', fileData: Buffer.from('hello world').toString('base64'), fileType: 'text/plain' });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
  assert.ok(res.body.data.id);

  const list = await request(app).get('/api/files');
  assert.equal(list.body.files.length, 1);
  assert.equal(list.body.files[0].title, '测试文件');
});

test('文件：下载成功', async () => {
  const list = await request(app).get('/api/files');
  const file = list.body.files[0];
  const res = await request(app).get(`/api/files/${file.id}/download`);
  assert.equal(res.status, 200);
  assert.equal(res.text, 'hello world');
});

test('文件：缺少标题返回 400', async () => {
  const res = await request(app).post('/api/files')
    .set('Authorization', token)
    .send({ fileName: 'a.txt', fileData: 'YQ==' });
  assert.equal(res.status, 400);
});

test('文件：管理员删除文件', async () => {
  const list = await request(app).get('/api/files');
  const file = list.body.files[0];
  const res = await request(app).delete(`/api/files/${file.id}`).set('Authorization', token);
  assert.equal(res.status, 200);
  const after = await request(app).get('/api/files');
  assert.equal(after.body.files.length, 0);
});

// ============ 评论 ============
test('评论：发表后进入待审核，公开不可见', async () => {
  const post = await request(app).post('/api/posts').send({ title: '评论目标', content: '内容' });
  assert.equal(post.status, 201);

  const add = await request(app).post('/api/comments').send({ contentType: 'article', contentId: Date.now(), author: '访客', content: '好文章！' });
  assert.equal(add.status, 201);
  assert.equal(add.body.success, true);
  assert.equal(add.body.data.status, 'pending');

  const contentId = add.body.data.contentId;
  const list = await request(app).get(`/api/comments/article/${contentId}`);
  assert.equal(list.status, 200);
  assert.equal(list.body.comments.length, 0);
});

test('评论：未登录不能获取全部评论', async () => {
  const res = await request(app).get('/api/comments');
  assert.equal(res.status, 401);
});

test('评论：管理员查看全部并审核通过后公开可见', async () => {
  token = await loginAsAdmin();
  const all = await request(app).get('/api/comments').set('Authorization', token);
  assert.equal(all.status, 200);
  const comment = all.body.comments.find(c => c.content === '好文章！');
  assert.ok(comment, '应存在待审核评论');
  assert.equal(comment.status, 'pending');

  const approveRes = await request(app).post(`/api/comments/${comment.id}/approve`).set('Authorization', token);
  assert.equal(approveRes.status, 200);

  const list = await request(app).get(`/api/comments/article/${comment.contentId}`);
  assert.ok(list.body.comments.find(c => c.content === '好文章！'));
});

test('评论：空内容返回 400', async () => {
  const res = await request(app).post('/api/comments').send({ contentType: 'article', contentId: 1, content: '' });
  assert.equal(res.status, 400);
});

test('评论：管理员拒绝评论（删除）', async () => {
  token = await loginAsAdmin();
  const add = await request(app).post('/api/comments').send({ contentType: 'article', contentId: 42, author: '路人', content: '待拒绝评论' });
  assert.equal(add.status, 201);
  const commentId = add.body.data.id;

  const res = await request(app).post(`/api/comments/${commentId}/reject`).set('Authorization', token);
  assert.equal(res.status, 200);
  const after = await request(app).get('/api/comments').set('Authorization', token);
  assert.equal(after.body.comments.find(c => c.id === commentId), undefined);
});

test('评论：管理员删除评论', async () => {
  token = await loginAsAdmin();
  const add = await request(app).post('/api/comments').send({ contentType: 'article', contentId: 42, author: '路人', content: '待删除评论' });
  assert.equal(add.status, 201);
  const commentId = add.body.data.id;

  const res = await request(app).delete(`/api/comments/${commentId}`).set('Authorization', token);
  assert.equal(res.status, 200);
  const after = await request(app).get('/api/comments').set('Authorization', token);
  assert.equal(after.body.comments.find(c => c.id === commentId), undefined);
});

test('404：未知接口返回 JSON 404', async () => {
  const res = await request(app).get('/api/not-exist');
  assert.equal(res.status, 404);
});
