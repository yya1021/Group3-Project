import { reactive, ref, computed } from 'vue'
import { getUser, setUser, clearAuth as clearStored, setOnUnauthorized } from '@/api'

// 简单的前端认证状态（内存 + localStorage 持久化）
const state = reactive({
  user: getUser() || null,
  token: localStorage.getItem('library_token') || null
})

// 登录过期信号：任何接口返回 401 时自增，App 监听到后跳转登录
const authExpired = ref(0)

const isLoggedIn = computed(() => !!state.token)
const role = computed(() => state.user?.role || null)
const username = computed(() => state.user?.username || '')

// 角色中文名映射
const ROLE_NAMES = {
  admin: '管理员',
  merchant: '商户',
  user: '普通用户',
  auditor: '审计员'
}

function setAuth(token, user) {
  state.token = token
  state.user = user
  if (token) localStorage.setItem('library_token', token)
  setUser(user)
}

function clearAuth() {
  state.token = null
  state.user = null
  clearStored()
}

// 登录过期处理：清理登录态并触发跳转信号
function handleUnauthorized() {
  if (state.token) {
    clearAuth()
    authExpired.value++
  }
}

// 注册 401 回调：当任一接口返回 401 时触发
setOnUnauthorized(handleUnauthorized)

function roleName(r) {
  return ROLE_NAMES[r] || r
}

// 根据角色跳转到对应首页
function homePathFor(roleValue) {
  if (roleValue === 'admin') return '/admin'
  if (roleValue === 'auditor') return '/audit'
  if (roleValue === 'merchant') return '/merchant'
  return '/shop'
}

export { state, isLoggedIn, role, username, authExpired, ROLE_NAMES, roleName, setAuth, clearAuth, homePathFor }
