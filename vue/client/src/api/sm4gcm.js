// SM4-GCM（认证加密）——浏览器侧实现
//
// 与 server/src/services/sm4-gcm.js 逻辑保持一致（同一 GCM 定义）。
// 浏览器 WebCrypto 不支持国密算法，故基于 sm-crypto 的 SM4 分组原语实现
// CTR 流加密 + GHASH 认证。
import smCrypto from 'sm-crypto'

const { sm4 } = smCrypto

const BLOCK = 16
const TAG_LEN = 16

function toArray(bytes) {
  return Array.prototype.slice.call(bytes)
}

function bytesToHex(bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16)
  return out
}

// SM4 分组加密原语：E_K(block)
function sm4BlockEncrypt(keyBytes, blockBytes) {
  return sm4.encrypt(toArray(blockBytes), bytesToHex(toArray(keyBytes)), {
    padding: 'none',
    output: 'array'
  })
}

const R = 0xe1

function mulGF128(x, y) {
  const z = new Array(BLOCK).fill(0)
  const v = y.slice()
  for (let i = 0; i < BLOCK; i++) {
    for (let j = 7; j >= 0; j--) {
      if ((x[i] >> j) & 1) {
        for (let k = 0; k < BLOCK; k++) z[k] ^= v[k]
      }
      const lsb = v[BLOCK - 1] & 1
      for (let k = BLOCK - 1; k > 0; k--) {
        v[k] = (v[k] >>> 1) | ((v[k - 1] & 1) << 7)
      }
      v[0] >>>= 1
      if (lsb) v[0] ^= R
    }
  }
  return z
}

function ghash(h, data) {
  let y = new Array(BLOCK).fill(0)
  for (let off = 0; off < data.length; off += BLOCK) {
    const block = data.slice(off, off + BLOCK)
    for (let i = 0; i < BLOCK; i++) y[i] ^= block[i]
    y = mulGF128(y, h)
  }
  return y
}

function pad16(bytes) {
  const out = bytes.slice()
  while (out.length % BLOCK !== 0) out.push(0)
  return out
}

function writeBigUInt64BE(arr, offset, value) {
  let v = BigInt(value)
  for (let i = 7; i >= 0; i--) {
    arr[offset + i] = Number(v & 0xffn)
    v >>= 8n
  }
}

function lenBlock(aadBitLen, cipherBitLen) {
  const out = new Array(BLOCK).fill(0)
  writeBigUInt64BE(out, 0, aadBitLen)
  writeBigUInt64BE(out, 8, cipherBitLen)
  return out
}

function inc32(block) {
  const b = block.slice()
  for (let i = BLOCK - 1; i >= BLOCK - 4; i--) {
    b[i] = (b[i] + 1) & 0xff
    if (b[i] !== 0) break
  }
  return b
}

function buildJ0(ivBytes) {
  const j0 = toArray(ivBytes)
  for (let i = 0; i < 3; i++) j0.push(0)
  j0.push(1)
  return j0
}

// 加密：返回 { ciphertext, tag }
function gcmEncrypt(keyBytes, ivBytes, plaintextBytes, aadBytes, tagLength = TAG_LEN) {
  const key = toArray(keyBytes)
  const plaintext = toArray(plaintextBytes)
  const aad = toArray(aadBytes)
  const h = sm4BlockEncrypt(key, new Array(BLOCK).fill(0))
  const j0 = buildJ0(ivBytes)

  const ciphertext = []
  let counter = inc32(j0)
  for (let i = 0; i < plaintext.length; i += BLOCK) {
    const ks = sm4BlockEncrypt(key, counter)
    const block = plaintext.slice(i, i + BLOCK)
    for (let j = 0; j < block.length; j++) ciphertext.push(block[j] ^ ks[j])
    counter = inc32(counter)
  }

  const ghashData = []
    .concat(pad16(aad))
    .concat(pad16(ciphertext))
    .concat(lenBlock(aad.length * 8, ciphertext.length * 8))
  const s = ghash(h, ghashData)
  const ekj0 = sm4BlockEncrypt(key, j0)

  const tag = []
  for (let i = 0; i < tagLength; i++) tag.push(s[i] ^ ekj0[i])

  return { ciphertext, tag }
}

// 解密：校验认证标签，失败抛错；成功返回明文字节数组
function gcmDecrypt(keyBytes, ivBytes, ciphertextBytes, aadBytes, tagBytes) {
  const key = toArray(keyBytes)
  const ciphertext = toArray(ciphertextBytes)
  const aad = toArray(aadBytes)
  const tag = toArray(tagBytes)

  const h = sm4BlockEncrypt(key, new Array(BLOCK).fill(0))
  const j0 = buildJ0(ivBytes)

  const ghashData = []
    .concat(pad16(aad))
    .concat(pad16(ciphertext))
    .concat(lenBlock(aad.length * 8, ciphertext.length * 8))
  const s = ghash(h, ghashData)
  const ekj0 = sm4BlockEncrypt(key, j0)

  const expect = []
  for (let i = 0; i < tag.length; i++) expect.push(s[i] ^ ekj0[i])

  if (tag.length !== expect.length) throw new Error('GCM 认证失败：标签长度不匹配')
  let diff = 0
  for (let i = 0; i < expect.length; i++) diff |= (tag[i] ^ expect[i])
  if (diff !== 0) throw new Error('GCM 认证失败：数据完整性校验未通过')

  const plaintext = []
  let counter = inc32(j0)
  for (let i = 0; i < ciphertext.length; i += BLOCK) {
    const ks = sm4BlockEncrypt(key, counter)
    const block = ciphertext.slice(i, i + BLOCK)
    for (let j = 0; j < block.length; j++) plaintext.push(block[j] ^ ks[j])
    counter = inc32(counter)
  }
  return plaintext
}

// 随机字节（CSPRNG）
function randomBytes(len) {
  const arr = new Uint8Array(len)
  crypto.getRandomValues(arr)
  return arr
}

// 字节数组 <-> Base64
function bytesToBase64(bytes) {
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin)
}

export { gcmEncrypt, gcmDecrypt, randomBytes, bytesToBase64, BLOCK, TAG_LEN }
