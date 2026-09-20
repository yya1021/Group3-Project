const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const request = require('supertest');
const { sm2 } = require('sm-crypto');

const store = require('../src/services/store');
const { createApp } = require('../src/app');
const { gcmEncrypt, gcmDecrypt, mulGF128 } = require('../src/services/sm4-gcm');
const envelope = require('../src/services/envelope');
const replay = require('../src/services/replay');

// ============ 测试隔离：临时数据目录 + 独立 app ============
let tmpDataDir;
let tmpUploadsDir;
let app;

before(() => {
  tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-env-data-'));
  tmpUploadsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lib-env-uploads-'));
  store.configure({ dataDir: tmpDataDir, uploadsDir: tmpUploadsDir });
  app = createApp();
});

after(() => {
  try { fs.rmSync(tmpDataDir, { recursive: true, force: true }); } catch (e) {}
  try { fs.rmSync(tmpUploadsDir, { recursive: true, force: true }); } catch (e) {}
});

beforeEach(() => {
  replay.reset(); // 隔离各用例的重放缓存
});

// 模拟客户端封装（与 client/src/api/envelope.js 同构）
function seal(plainObject, { method = 'POST', path = '/api/register', ts = Date.now() } = {}) {
  const nonce = crypto.randomBytes(12);
  const sessionKey = crypto.randomBytes(16);
  const nonceB64 = nonce.toString('base64');
  const aad = Buffer.from(envelope.buildAad({ method, path, ts, nonce: nonceB64 }), 'utf8');
  const plaintext = Buffer.from(JSON.stringify(plainObject), 'utf8');
  const { ciphertext, tag } = gcmEncrypt(sessionKey, nonce, plaintext, aad);
  const ek = sm2.doEncrypt(Array.from(sessionKey), envelope.PUBLIC_KEY, 1);
  return {
    enc: envelope.ALG,
    v: envelope.VERSION,
    ts,
    nonce: nonceB64,
    ek,
    ct: Buffer.from(ciphertext).toString('base64'),
    tag: Buffer.from(tag).toString('base64')
  };
}

// ============ SM4-GCM 正确性 ============
test('SM4-GCM：加解密往返一致', () => {
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify({ 中文: '内容', n: 123 }));
  const aad = Buffer.from('auth-data');
  const { ciphertext, tag } = gcmEncrypt(key, iv, plaintext, aad);
  const back = gcmDecrypt(key, iv, ciphertext, aad, tag);
  assert.equal(Buffer.from(back).toString('utf8'), plaintext.toString('utf8'));
});

test('SM4-GCM：篡改密文导致认证失败', () => {
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from('secret');
  const aad = Buffer.from('aad');
  const { ciphertext, tag } = gcmEncrypt(key, iv, plaintext, aad);
  const tampered = ciphertext.slice();
  tampered[0] ^= 0xff;
  assert.throws(() => gcmDecrypt(key, iv, tampered, aad, tag), /GCM 认证失败/);
});

test('SM4-GCM：篡改 AAD 导致认证失败', () => {
  const key = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from('secret');
  const { ciphertext, tag } = gcmEncrypt(key, iv, plaintext, Buffer.from('aad'));
  assert.throws(() => gcmDecrypt(key, iv, ciphertext, Buffer.from('bad'), tag), /GCM 认证失败/);
});

test('SM4-GCM：GF(2^128) 乘法与 NIST 测试向量一致', () => {
  const hex = (s) => Array.from({ length: s.length / 2 }, (_, i) => parseInt(s.substr(i * 2, 2), 16));
  const H = hex('66e94bd4ef8a2c3b884cfa59ca342b2e');
  const X = hex('0388dace60b6a392f328c2b971b2fe78');
  const Y = mulGF128(X, H);
  const out = Y.map((b) => (b < 16 ? '0' : '') + b.toString(16)).join('');
  assert.equal(out, '5e2ec746917062882c85b0685353deb7');
});

// ============ 数字信封解封 ============
test('数字信封：解封后还原明文对象', () => {
  const body = seal({ username: 'alice', password: 's3cret' });
  const plaintext = envelope.openEnvelope(body, { method: 'POST', path: '/api/register' });
  assert.deepEqual(plaintext, { username: 'alice', password: 's3cret' });
});

test('数字信封：篡改时间戳导致完整性校验失败', () => {
  const body = seal({ username: 'alice', password: 's3cret' });
  body.ts += 1; // 改变 ts 会使 AAD 不匹配
  assert.throws(
    () => envelope.openEnvelope(body, { method: 'POST', path: '/api/register' }),
    (err) => err.code === 'INTEGRITY_FAILED'
  );
});

test('数字信封：非信封对象被拒绝', () => {
  assert.throws(() => envelope.openEnvelope({ username: 'alice' }, {}), (err) => err.code === 'BAD_ENVELOPE');
});

// ============ 中间件集成（HTTP 层） ============
test('集成：加密的注册请求被解密并成功处理', async () => {
  const envelopeBody = seal({ username: 'enc_user', password: 'enc_pass', role: 'user' });
  const res = await request(app).post('/api/register').send(envelopeBody);
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
});

test('集成：抓包层面敏感字段不以明文出现', () => {
  const envelopeBody = seal({ username: 'enc_user', password: 'SENSITIVE_PLAINTEXT' });
  const wire = JSON.stringify(envelopeBody);
  assert.ok(!wire.includes('SENSITIVE_PLAINTEXT'), '线上报文不应包含明文敏感字段');
});

test('集成：明文请求仍兼容（向后兼容）', async () => {
  const res = await request(app).post('/api/register').send({ username: 'plain_user', password: 'plain_pass', role: 'user' });
  assert.equal(res.status, 201);
  assert.equal(res.body.success, true);
});

test('集成：重放同一信封被拒绝（409）', async () => {
  const envelopeBody = seal({ username: 'replay_user', password: 'replay_pass', role: 'user' });
  const first = await request(app).post('/api/register').send(envelopeBody);
  assert.equal(first.status, 201);

  const second = await request(app).post('/api/register').send(envelopeBody);
  assert.equal(second.status, 409);
  assert.equal(second.body.code, 'REPLAY');
});

test('集成：过期时间窗被拒绝（400）', async () => {
  const envelopeBody = seal(
    { username: 'old_user', password: 'old_pass', role: 'user' },
    { ts: Date.now() - 6 * 60 * 1000 }
  );
  const res = await request(app).post('/api/register').send(envelopeBody);
  assert.equal(res.status, 400);
  assert.equal(res.body.code, 'EXPIRED');
});
