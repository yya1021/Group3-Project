// 数字信封服务：SM2 封装会话密钥 + SM4-GCM 加密 Body
//
// 流程（客户端加密封装 / 服务端解封）：
//   1) 客户端生成随机 SM4 会话密钥 K 与 96-bit nonce；
//   2) 用 SM4-GCM 以 K 加密 Body，得到密文 ct 与认证标签 tag；
//   3) 用服务端 SM2 公钥加密 K，得到数字信封 ek；
//   4) 服务端用 SM2 私钥解封得到 K，再用 K 解密并校验 GCM 标签。
//
// 安全边界（务必知悉）：
//   - 本机制属于应用层加密，仅保护 Body 的机密性与完整性，不能替代 HTTPS；
//   - SM2 公钥若经明文信道下发可被中间人替换，生产环境必须走 HTTPS 或预置公钥；
//   - 私钥应由环境变量注入或托管于 KMS/HSM，禁止硬编码。
const crypto = require('crypto');
const { sm2 } = require('sm-crypto');
const { gcmDecrypt } = require('./sm4-gcm');

const ALG = 'sm2-sm4-gcm';
const VERSION = 1;
const NONCE_LEN = 12; // 96 bit
const KEY_LEN = 16; // SM4 128 bit
const TAG_LEN = 16; // GCM 128 bit

// 默认 SM2 私钥（仅用于演示/测试；生产必须通过环境变量 SM2_PRIVATE_KEY 覆盖）
const DEFAULT_PRIVATE_KEY = '5c72bb61a45ba08f66a33725e5aa127949f94f17e994a5f5158b6dc7d3697ca4';
const PRIVATE_KEY = process.env.SM2_PRIVATE_KEY || DEFAULT_PRIVATE_KEY;

if (!process.env.SM2_PRIVATE_KEY) {
  // 演示环境提示：硬编码私钥仅用于本地演示，不具备生产安全性
  console.warn('[envelope] 警告：正在使用内置默认 SM2 私钥，请在生产环境通过 SM2_PRIVATE_KEY 注入。');
}

// 服务端 SM2 公钥（供前端使用，或经由 HTTPS 下发）
const PUBLIC_KEY = sm2.getPublicKeyFromPrivateKey(PRIVATE_KEY);

// 构造 AAD：将密文绑定到算法/版本/方法/路径/时间戳/nonce，防止跨请求搬移或篡改
function buildAad({ method, path, ts, nonce }) {
  return `${ALG}|v${VERSION}|${method}|${path}|${ts}|${nonce}`;
}

// 判断请求体是否为数字信封
function isEnvelope(body) {
  return body && typeof body === 'object' && !Array.isArray(body) && body.enc === ALG;
}

// 解封：返回明文对象；任何失败抛出带 code 的错误
function openEnvelope(body, { method, path } = {}) {
  if (!isEnvelope(body)) {
    const err = new Error('请求体不是有效的数字信封');
    err.code = 'BAD_ENVELOPE';
    throw err;
  }

  const { v, ts, nonce, ek, ct, tag } = body;
  if (v !== VERSION) {
    const err = new Error('不支持的加密协议版本');
    err.code = 'BAD_ENVELOPE';
    throw err;
  }
  if (typeof nonce !== 'string' || typeof ek !== 'string' || typeof ct !== 'string' || typeof tag !== 'string') {
    const err = new Error('信封字段缺失或类型非法');
    err.code = 'BAD_ENVELOPE';
    throw err;
  }

  const methodUpper = String(method || '').toUpperCase();
  const fullPath = String(path || '').split('?')[0];
  const aad = Buffer.from(buildAad({ method: methodUpper, path: fullPath, ts, nonce }), 'utf8');

  // 1) SM2 解封会话密钥
  let sessionKey;
  try {
    sessionKey = sm2.doDecrypt(ek, PRIVATE_KEY, 1, { output: 'array' });
  } catch (e) {
    const err = new Error('数字信封解封失败');
    err.code = 'DECRYPT_FAILED';
    throw err;
  }
  if (!Array.isArray(sessionKey) || sessionKey.length !== KEY_LEN) {
    const err = new Error('数字信封解封失败');
    err.code = 'DECRYPT_FAILED';
    throw err;
  }

  // 2) SM4-GCM 解密并校验
  let plaintextBytes;
  try {
    plaintextBytes = gcmDecrypt(
      sessionKey,
      Buffer.from(nonce, 'base64'),
      Buffer.from(ct, 'base64'),
      aad,
      Buffer.from(tag, 'base64')
    );
  } catch (e) {
    const err = new Error('密文解密或完整性校验失败');
    err.code = 'INTEGRITY_FAILED';
    throw err;
  }

  // 3) 还原 JSON
  try {
    return JSON.parse(Buffer.from(plaintextBytes).toString('utf8'));
  } catch (e) {
    const err = new Error('明文不是合法 JSON');
    err.code = 'BAD_ENVELOPE';
    throw err;
  }
}

module.exports = {
  ALG,
  VERSION,
  NONCE_LEN,
  KEY_LEN,
  TAG_LEN,
  PRIVATE_KEY,
  PUBLIC_KEY,
  buildAad,
  isEnvelope,
  openEnvelope
};
