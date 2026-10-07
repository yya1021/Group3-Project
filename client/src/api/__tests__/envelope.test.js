import { describe, it, expect } from 'vitest'
import smCrypto from 'sm-crypto'
import { sealBody, ALG, VERSION } from '../envelope.js'
import { gcmDecrypt } from '../sm4gcm.js'

const { sm2 } = smCrypto

// 与服务端默认 SM2 私钥一致（演示密钥，仅用于测试解封）
const PRIVATE_KEY = '5c72bb61a45ba08f66a33725e5aa127949f94f17e994a5f5158b6dc7d3697ca4'

function base64ToBytes(b64) {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function buildAad({ method, path, ts, nonce }) {
  return `sm2-sm4-gcm|v1|${method}|${path}|${ts}|${nonce}`
}

describe('数字信封（客户端）', () => {
  it('封装后为信封结构且不含明文', () => {
    const env = sealBody({ password: 'TOPSECRET', username: 'u' }, { method: 'POST', path: '/api/login' })
    expect(env.enc).toBe(ALG)
    expect(env.v).toBe(VERSION)
    expect(env.ts).toBeTypeOf('number')
    expect(env.nonce).toBeTruthy()
    expect(env.ek).toBeTruthy()
    expect(env.ct).toBeTruthy()
    expect(env.tag).toBeTruthy()
    expect(JSON.stringify(env)).not.toContain('TOPSECRET')
  })

  it('两次封装产生不同 nonce 与密文（随机性）', () => {
    const a = sealBody({ x: 1 }, { method: 'POST', path: '/api/x' })
    const b = sealBody({ x: 1 }, { method: 'POST', path: '/api/x' })
    expect(a.nonce).not.toBe(b.nonce)
    expect(a.ct).not.toBe(b.ct)
  })

  it('封装结果可用服务端私钥解封还原', () => {
    const plain = { username: 'u', password: 'p', role: 'user' }
    const method = 'POST'
    const path = '/api/register'
    const env = sealBody(plain, { method, path })

    // 用服务端 SM2 私钥解封会话密钥
    const sessionKey = sm2.doDecrypt(env.ek, PRIVATE_KEY, 1, { output: 'array' })
    const aad = new TextEncoder().encode(buildAad({ method, path, ts: env.ts, nonce: env.nonce }))
    const back = gcmDecrypt(
      sessionKey,
      base64ToBytes(env.nonce),
      base64ToBytes(env.ct),
      aad,
      base64ToBytes(env.tag)
    )
    expect(JSON.parse(new TextDecoder().decode(new Uint8Array(back)))).toEqual(plain)
  })
})
