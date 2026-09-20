// 数字信封封装（客户端侧）：SM2 封装会话密钥 + SM4-GCM 加密 Body
//
// 说明：
//   - 仅加密敏感请求的 Body，响应保持明文（生产环境应叠加 HTTPS）。
//   - 服务端 SM2 公钥在此预置（pinning）。生产环境应由服务端经 HTTPS 下发或预置并轮换；
//     经明文信道下发公钥存在被中间人替换的风险。
import smCrypto from 'sm-crypto'
import { gcmEncrypt, randomBytes, bytesToBase64 } from './sm4gcm'

const { sm2 } = smCrypto

const ALG = 'sm2-sm4-gcm'
const VERSION = 1
const NONCE_LEN = 12 // 96 bit
const KEY_LEN = 16 // SM4 128 bit

// 服务端 SM2 公钥（与服务端私钥配对，需保持一致）
const SERVER_SM2_PUBLIC_KEY =
  '040a91162e0fe03d7959e1e3cdf5f9839ee2509ce705ff7f68876e705cd1c44c03b224c259724d3782847ddd544896deef44458151b3334ac242a45c86c87421a4'

// 与服务端 envelope.js 保持一致的 AAD 构造
function buildAad({ method, path, ts, nonce }) {
  return `${ALG}|v${VERSION}|${method}|${path}|${ts}|${nonce}`
}

// 将明文对象封装为数字信封
function sealBody(plainObject, { method, path }) {
  const nonce = randomBytes(NONCE_LEN)
  const sessionKey = randomBytes(KEY_LEN)
  const ts = Date.now()
  const nonceB64 = bytesToBase64(nonce)

  const methodUpper = String(method || 'GET').toUpperCase()
  const fullPath = String(path || '').split('?')[0]

  const aadStr = buildAad({ method: methodUpper, path: fullPath, ts, nonce: nonceB64 })
  const aad = new TextEncoder().encode(aadStr)
  const plaintext = new TextEncoder().encode(JSON.stringify(plainObject))

  const { ciphertext, tag } = gcmEncrypt(sessionKey, nonce, plaintext, aad)

  // SM2 加密会话密钥（数字信封，C1C3C2）
  const ek = sm2.doEncrypt(Array.from(sessionKey), SERVER_SM2_PUBLIC_KEY, 1)

  return {
    enc: ALG,
    v: VERSION,
    ts,
    nonce: nonceB64,
    ek,
    ct: bytesToBase64(ciphertext),
    tag: bytesToBase64(tag)
  }
}

export { sealBody, SERVER_SM2_PUBLIC_KEY, ALG, VERSION }
