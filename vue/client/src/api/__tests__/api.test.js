import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { api, setToken, getToken } from '../index.js'

// 在 Node 环境下模拟 localStorage
const memoryStore = {}
globalThis.localStorage = {
  getItem: (k) => (k in memoryStore ? memoryStore[k] : null),
  setItem: (k, v) => { memoryStore[k] = String(v) },
  removeItem: (k) => { delete memoryStore[k] }
}

describe('api 客户端', () => {
  beforeEach(() => {
    Object.keys(memoryStore).forEach(k => delete memoryStore[k])
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('setToken 存储与清除', () => {
    setToken('abc123')
    expect(getToken()).toBe('abc123')
    setToken(null)
    expect(getToken()).toBe(null)
  })

  it('携带登录令牌发送 Authorization 头', async () => {
    setToken('my-token')
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ posts: [] }) })
    vi.stubGlobal('fetch', fetchMock)

    await api.getPosts()

    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/posts')
    expect(opts.headers['Authorization']).toBe('my-token')
  })

  it('无令牌时不发送 Authorization 头', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ posts: [] }) })
    vi.stubGlobal('fetch', fetchMock)

    await api.getPosts()

    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.headers['Authorization']).toBeUndefined()
  })

  it('请求失败时抛出带状态码与错误信息的异常', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: '未登录' })
    }))

    await expect(api.getPending()).rejects.toMatchObject({ status: 401, message: '未登录' })
  })

  it('登录接口发送正确的请求体', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ success: true, token: 't' }) })
    vi.stubGlobal('fetch', fetchMock)

    await api.login('admin', 'admin123')

    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/login')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ username: 'admin', password: 'admin123' })
  })
})
