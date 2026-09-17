const crypto = require('crypto');

// RFC 4648 Base32（无填充），用于 otpauth secret
const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += B32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const output = [];
  for (let i = 0; i < clean.length; i++) {
    value = (value << 5) | B32_ALPHABET.indexOf(clean[i]);
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

// 生成随机的 TOTP 密钥（base32，20 字节密钥 -> 32 字符）
function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

// 计算 TOTP 动态码（RFC 6238，默认 6 位 / 30 秒窗口）
function generateTotp(secret, { step = 30, digits = 6, time = Date.now() } = {}) {
  const key = base32Decode(secret);
  const counter = Math.floor(time / 1000 / step);
  // 将 counter 编码为大端 8 字节
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = binary % Math.pow(10, digits);
  return String(code).padStart(digits, '0');
}

// 校验 TOTP 码（允许前后 1 个时间窗口的偏差）
function verifyTotp(secret, token, step = 30, digits = 6) {
  if (!secret || !token) return false;
  const now = Date.now();
  for (let drift = -1; drift <= 1; drift++) {
    if (generateTotp(secret, { step, digits, time: now + drift * step * 1000 }) === String(token)) {
      return true;
    }
  }
  return false;
}

// 生成 otpauth URI（供 Microsoft Authenticator 扫码）
function buildOtpauthUrl({ secret, label, issuer = '优选商城' }) {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// 生成一次性恢复码（用于 TOTP 丢失时登录），默认 5 个，格式 XXXX-XXXX-XXXX-XXXX
function generateRecoveryCodes(count = 5) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const hex = crypto.randomBytes(8).toString('hex').toUpperCase();
    codes.push(`${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`);
  }
  return codes;
}

// 恢复码只存哈希，不存明文（与密码相同的 sha256 策略，统一大写后哈希）
function hashRecoveryCode(code) {
  return crypto.createHash('sha256').update(String(code).trim().toUpperCase()).digest('hex');
}

module.exports = { generateSecret, generateTotp, verifyTotp, buildOtpauthUrl, generateRecoveryCodes, hashRecoveryCode };