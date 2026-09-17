// 前端 API 客户端：统一封装 fetch，自动携带登录令牌
const API_BASE = '/api'
const TOKEN_KEY = 'library_token'
const USER_KEY = 'library_user'

// 401 未授权回调（由认证 store 注册，用于清理登录态并跳转登录）
let onUnauthorized = null
function setOnUnauthorized(fn) { onUnauthorized = fn }

function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

function getUser() {
  try {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  } catch (e) { return null }
}

function setUser(user) {
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user))
  else localStorage.removeItem(USER_KEY)
}

function clearAuth() {
  setToken(null)
  setUser(null)
}

function getTokenSafe() {
  try { return getToken() } catch (e) { return null }
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  const token = getTokenSafe()
  if (token) headers['Authorization'] = token
  const res = await fetch(API_BASE + path, { ...options, headers })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(data.error || data.message || '请求失败')
    err.status = res.status
    err.data = data
    // 登录已过期：通知全局清理登录态并跳转登录
    if (res.status === 401 && onUnauthorized) onUnauthorized()
    throw err
  }
  return data
}

export const api = {
  // 认证
  login: (username, password) => request('/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  loginTotp: (challengeId, code, totpSecret, recoveryCode) => request('/login/totp', { method: 'POST', body: JSON.stringify({ challengeId, code, totpSecret, recoveryCode }) }),
  register: (username, password, role) => request('/register', { method: 'POST', body: JSON.stringify({ username, password, role }) }),
  logout: () => request('/logout', { method: 'POST' }),
  me: () => request('/me'),

  // 文章
  getPosts: () => request('/posts'),
  getPost: (id) => request(`/posts/${id}`),
  submitPost: (data) => request('/posts', { method: 'POST', body: JSON.stringify(data) }),
  getPending: () => request('/pending'),
  approve: (id) => request(`/approve/${id}`, { method: 'POST' }),
  reject: (id) => request(`/reject/${id}`, { method: 'POST' }),
  updatePost: (id, data) => request(`/update/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deletePost: (id) => request(`/posts/${id}`, { method: 'DELETE' }),

  // 文件
  getFiles: () => request('/files'),
  getFile: (id) => request(`/files/${id}`),
  uploadFile: (data) => request('/files', { method: 'POST', body: JSON.stringify(data) }),
  deleteFile: (id) => request(`/files/${id}`, { method: 'DELETE' }),

  // 评论
  getComments: (type, id) => request(`/comments/${type}/${id}`),
  addComment: (data) => request('/comments', { method: 'POST', body: JSON.stringify(data) }),
  getAllComments: () => request('/comments'),
  approveComment: (id) => request(`/comments/${id}/approve`, { method: 'POST' }),
  rejectComment: (id) => request(`/comments/${id}/reject`, { method: 'POST' }),
  deleteComment: (id) => request(`/comments/${id}`, { method: 'DELETE' }),

  // 商品
  getProducts: (type) => request(type ? `/products?type=${type}` : '/products'),
  getProduct: (id) => request(`/products/${id}`),
  createProduct: (data) => request('/products', { method: 'POST', body: JSON.stringify(data) }),
  updateProduct: (id, data) => request(`/products/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteProduct: (id) => request(`/products/${id}`, { method: 'DELETE' }),

  // 购物车
  getCart: () => request('/cart'),
  saveCart: (cart) => request('/cart', { method: 'POST', body: JSON.stringify({ cart }) }),

  // 订单
  getOrders: () => request('/orders'),
  createOrder: (products) => request('/orders', { method: 'POST', body: JSON.stringify({ products }) }),
  deleteOrder: (id) => request(`/orders/${id}`, { method: 'DELETE' }),

  // 用户管理（管理员）
  getUsers: () => request('/users'),
  createUser: (data) => request('/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id, data) => request(`/users/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteUser: (id) => request(`/users/${id}`, { method: 'DELETE' }),

  // 角色管理（管理员）
  getRoles: () => request('/roles'),
  updateRole: (role, permissions) => request(`/roles/${role}`, { method: 'PUT', body: JSON.stringify({ permissions }) }),

  // 审计日志（审计员）
  getAuditLogs: () => request('/audit-logs'),

  // 恢复码（管理员重新生成）
  regenerateRecoveryCodes: () => request('/recovery-codes/regenerate', { method: 'POST' })
}

export { setToken, getTokenSafe as getToken, setUser, getUser, clearAuth, setOnUnauthorized }
