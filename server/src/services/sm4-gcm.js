// SM4-GCM（Galois/Counter Mode，认证加密）实现
//
// 背景：Node 原生 OpenSSL 仅提供 sm4-ecb/cbc/cfb/ctr/ofb，未暴露 sm4-gcm；
// 浏览器 WebCrypto 亦不支持国密算法。故此处基于 sm-crypto 的 SM4 分组加密原语，
// 按 NIST SP 800-38D 的 GCM 定义自行实现「CTR 流加密 + GHASH 认证」。
//
// 安全约束：
//   - 同一密钥下 nonce（IV）绝不能复用，否则 GHASH 认证安全性崩溃。
//   - 本模块只负责加解密与认证，不负责 nonce 的唯一性管理（由调用方保证随机且唯一）。
const { sm4 } = require('sm-crypto');

const BLOCK = 16; // 128 bit
const TAG_LEN = 16; // 128 bit 认证标签

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------
function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  return out;
}

function toArray(bytes) {
  return Array.prototype.slice.call(bytes);
}

// SM4 分组加密原语：E_K(block)，block 必须为 16 字节
function sm4BlockEncrypt(keyBytes, blockBytes) {
  return sm4.encrypt(toArray(blockBytes), bytesToHex(toArray(keyBytes)), {
    padding: 'none',
    output: 'array'
  });
}

// ---------------------------------------------------------------------------
// GHASH：GF(2^128) 乘法与认证
// 约减多项式 x^128 + x^7 + x^2 + x + 1，最高字节为 0xe1
// ---------------------------------------------------------------------------
const R = 0xe1;

// GF(2^128) 乘法（MSB 在前，按位右移实现）
function mulGF128(x, y) {
  const z = new Array(BLOCK).fill(0);
  const v = y.slice();
  for (let i = 0; i < BLOCK; i++) {
    for (let j = 7; j >= 0; j--) {
      if ((x[i] >> j) & 1) {
        for (let k = 0; k < BLOCK; k++) z[k] ^= v[k];
      }
      const lsb = v[BLOCK - 1] & 1;
      for (let k = BLOCK - 1; k > 0; k--) {
        v[k] = (v[k] >>> 1) | ((v[k - 1] & 1) << 7);
      }
      v[0] >>>= 1;
      if (lsb) v[0] ^= R;
    }
  }
  return z;
}

// GHASH_H(A || C || [len(A)]64 || [len(C)]64)
function ghash(h, data) {
  let y = new Array(BLOCK).fill(0);
  for (let off = 0; off < data.length; off += BLOCK) {
    const block = data.slice(off, off + BLOCK);
    for (let i = 0; i < BLOCK; i++) y[i] ^= block[i];
    y = mulGF128(y, h);
  }
  return y;
}

// 按 16 字节对齐，末尾补 0
function pad16(bytes) {
  const out = bytes.slice();
  while (out.length % BLOCK !== 0) out.push(0);
  return out;
}

// 将 64 位长度值以大端写入 16 字节块的指定偏移
function writeBigUInt64BE(arr, offset, value) {
  let v = BigInt(value);
  for (let i = 7; i >= 0; i--) {
    arr[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

// 长度块：len(AAD)（比特） || len(C)（比特），各 64 位大端
function lenBlock(aadBitLen, cipherBitLen) {
  const out = new Array(BLOCK).fill(0);
  writeBigUInt64BE(out, 0, aadBitLen);
  writeBigUInt64BE(out, 8, cipherBitLen);
  return out;
}

// 计数器块：低 32 位自增
function inc32(block) {
  const b = block.slice();
  for (let i = BLOCK - 1; i >= BLOCK - 4; i--) {
    b[i] = (b[i] + 1) & 0xff;
    if (b[i] !== 0) break;
  }
  return b;
}

// J0：96-bit IV -> IV || 0^31 || 1
function buildJ0(ivBytes) {
  const j0 = toArray(ivBytes);
  for (let i = 0; i < 3; i++) j0.push(0);
  j0.push(1);
  return j0;
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------
// 加密：返回 { ciphertext, tag }，均为普通数组（字节）
function gcmEncrypt(keyBytes, ivBytes, plaintextBytes, aadBytes, tagLength = TAG_LEN) {
  const key = toArray(keyBytes);
  const h = sm4BlockEncrypt(key, new Array(BLOCK).fill(0)); // H = E_K(0^128)
  const j0 = buildJ0(ivBytes);

  // CTR 加密
  const ciphertext = [];
  let counter = inc32(j0);
  for (let i = 0; i < plaintextBytes.length; i += BLOCK) {
    const ks = sm4BlockEncrypt(key, counter);
    const block = toArray(plaintextBytes).slice(i, i + BLOCK);
    for (let j = 0; j < block.length; j++) ciphertext.push(block[j] ^ ks[j]);
    counter = inc32(counter);
  }

  // GHASH 输入：pad(AAD) || pad(C) || len64(AAD) || len64(C)
  const ghashData = []
    .concat(pad16(toArray(aadBytes)))
    .concat(pad16(ciphertext))
    .concat(lenBlock(toArray(aadBytes).length * 8, ciphertext.length * 8));

  const s = ghash(h, ghashData);
  const ekj0 = sm4BlockEncrypt(key, j0);

  const tag = [];
  for (let i = 0; i < tagLength; i++) tag.push(s[i] ^ ekj0[i]);

  return { ciphertext, tag };
}

// 解密：校验认证标签，失败抛错；成功返回明文字节数组
function gcmDecrypt(keyBytes, ivBytes, ciphertextBytes, aadBytes, tagBytes) {
  const key = toArray(keyBytes);
  const ciphertext = toArray(ciphertextBytes);
  const aad = toArray(aadBytes);
  const tag = toArray(tagBytes);

  const h = sm4BlockEncrypt(key, new Array(BLOCK).fill(0));
  const j0 = buildJ0(ivBytes);

  // 先校验认证标签，通过后才返回明文（encrypt-then-authenticate）
  const ghashData = []
    .concat(pad16(aad))
    .concat(pad16(ciphertext))
    .concat(lenBlock(aad.length * 8, ciphertext.length * 8));
  const s = ghash(h, ghashData);
  const ekj0 = sm4BlockEncrypt(key, j0);

  const expect = [];
  for (let i = 0; i < tag.length; i++) expect.push(s[i] ^ ekj0[i]);

  if (tag.length !== expect.length) throw new Error('GCM 认证失败：标签长度不匹配');
  let diff = 0;
  for (let i = 0; i < expect.length; i++) diff |= (tag[i] ^ expect[i]);
  if (diff !== 0) throw new Error('GCM 认证失败：数据完整性校验未通过');

  // CTR 解密
  const plaintext = [];
  let counter = inc32(j0);
  for (let i = 0; i < ciphertext.length; i += BLOCK) {
    const ks = sm4BlockEncrypt(key, counter);
    const block = ciphertext.slice(i, i + BLOCK);
    for (let j = 0; j < block.length; j++) plaintext.push(block[j] ^ ks[j]);
    counter = inc32(counter);
  }

  return plaintext;
}

module.exports = {
  BLOCK,
  TAG_LEN,
  sm4BlockEncrypt,
  mulGF128,
  ghash,
  gcmEncrypt,
  gcmDecrypt
};
