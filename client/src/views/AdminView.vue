<template>
  <main class="admin-page" style="max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; flex: 1;">
    <h2 class="admin-title">管理员后台</h2>

    <div class="admin-tabs">
      <button v-for="t in tabs" :key="t.key" class="tab" :class="{ active: currentTab === t.key }" @click="switchTab(t.key)">
        {{ t.label }}
      </button>
    </div>

    <!-- 用户管理 -->
    <section v-if="currentTab === 'users'" class="panel">
      <h3>用户管理</h3>
      <div class="create-form">
        <input type="text" v-model="userForm.username" placeholder="用户名">
        <input type="password" v-model="userForm.password" placeholder="密码">
        <select v-model="userForm.role">
          <option value="user">普通用户</option>
          <option value="merchant">商户</option>
          <option value="auditor">审计员</option>
          <option value="admin">管理员</option>
        </select>
        <button class="btn-primary" @click="createUser">新增用户</button>
      </div>
      <table class="data-table">
        <thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>店铺ID</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td>{{ u.id }}</td>
            <td>{{ u.username }}</td>
            <td>{{ roleName(u.role) }}</td>
            <td>{{ u.shopId || '-' }}</td>
            <td><button class="btn-danger" @click="deleteUser(u)">删除</button></td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 商品管理 -->
    <section v-if="currentTab === 'products'" class="panel">
      <h3>商品管理</h3>
      <div class="create-form">
        <select v-model="productForm.type">
          <option value="hand">手忍</option>
          <option value="knife">刀忍</option>
          <option value="hamu">哈姆</option>
          <option value="other">其他</option>
        </select>
        <input type="text" v-model="productForm.name" placeholder="商品名称">
        <input type="number" v-model="productForm.price" placeholder="价格">
        <input type="number" v-model="productForm.stock" placeholder="库存">
        <button class="btn-primary" @click="createProduct">新增商品</button>
      </div>
      <table class="data-table">
        <thead><tr><th>ID</th><th>类型</th><th>名称</th><th>价格</th><th>库存</th><th>店铺ID</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="p in products" :key="p.id">
            <td>{{ p.id }}</td>
            <td>{{ p.type }}</td>
            <td>{{ p.name }}</td>
            <td>¥{{ p.price }}</td>
            <td>{{ p.stock }}</td>
            <td>{{ p.shopId || '-' }}</td>
            <td><button class="btn-danger" @click="deleteProduct(p)">删除</button></td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 订单管理 -->
    <section v-if="currentTab === 'orders'" class="panel">
      <h3>订单管理</h3>
      <table class="data-table">
        <thead><tr><th>订单号</th><th>下单者</th><th>商品</th><th>金额</th><th>时间</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="o in orders" :key="o.id">
            <td>{{ o.orderNumber }}</td>
            <td>{{ o.username }}</td>
            <td>{{ o.products.map(p => `${p.name}×${p.amount}`).join('、') }}</td>
            <td>¥{{ o.totalAmount }}</td>
            <td>{{ o.createdAt }}</td>
            <td><button class="btn-danger" @click="cancelOrder(o)">取消订单</button></td>
          </tr>
          <tr v-if="orders.length === 0"><td colspan="6" class="empty-cell">暂无订单</td></tr>
        </tbody>
      </table>
    </section>

    <!-- 角色管理 -->
    <section v-if="currentTab === 'roles'" class="panel">
      <h3>角色权限矩阵</h3>
      <table class="data-table matrix">
        <thead>
          <tr><th>角色</th><th v-for="r in resources" :key="r">{{ resourceName(r) }}</th><th>数据范围</th></tr>
        </thead>
        <tbody>
          <tr v-for="(roleLabel, roleKey) in rolesMap" :key="roleKey">
            <td>{{ roleLabel }}</td>
            <td v-for="r in resources" :key="r">
              {{ formatActions(roleKey, r) }}
            </td>
            <td>{{ scopeText(roleKey) }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- 安全设置（恢复码） -->
    <section v-if="currentTab === 'security'" class="panel">
      <h3>安全设置 · 恢复码</h3>
      <p class="panel-hint">恢复码用于在无法使用动态验证码时登录。重新生成后，旧恢复码将立即失效。</p>
      <button class="btn-primary" @click="regenerateRecoveryCodes">重新生成恢复码</button>

      <div v-if="newRecoveryCodes.length" class="recovery-box">
        <p class="panel-hint">以下恢复码仅显示一次，请立即保存：</p>
        <ul class="recovery-list">
          <li v-for="(c, i) in newRecoveryCodes" :key="i"><code>{{ c }}</code></li>
        </ul>
        <button class="btn-primary" @click="newRecoveryCodes = []">我已保存</button>
      </div>
    </section>
  </main>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api } from '@/api'
import { ROLE_NAMES } from '@/stores/auth'

const currentTab = ref('users')
const users = ref([])
const products = ref([])
const orders = ref([])
const matrix = ref({})
const resources = ref([])
const scopes = ref({})
const rolesMap = ROLE_NAMES
const newRecoveryCodes = ref([])

const ACTION_NAMES = { read: '查看', create: '新增', update: '修改', delete: '删除', export: '导出' }

const tabs = [
  { key: 'users', label: '用户管理' },
  { key: 'products', label: '商品管理' },
  { key: 'orders', label: '订单管理' },
  { key: 'roles', label: '角色管理' },
  { key: 'security', label: '安全设置' }
]

const userForm = reactive({ username: '', password: '', role: 'user' })
const productForm = reactive({ type: 'hand', name: '', price: 0, stock: 0 })

function roleName(r) { return ROLE_NAMES[r] || r }
function resourceName(r) {
  const map = { product: '商品管理', order: '订单管理', user: '用户管理', role: '角色管理', system: '系统配置', audit: '审计日志' }
  return map[r] || r
}
function actionsFor(roleKey, res) {
  return (matrix.value[roleKey] && matrix.value[roleKey][res]) || []
}

function formatActions(roleKey, res) {
  const actions = actionsFor(roleKey, res)
  if (!actions.length) return '无'
  return actions.map(a => ACTION_NAMES[a] || a).join('、')
}

function scopeText(roleKey) {
  const s = scopes.value[roleKey]
  if (roleKey === 'auditor') return '全部审计日志'
  if (s === 'all') return '全部数据'
  if (s === 'shop') return '仅限本人店铺的商品和订单'
  if (s === 'self') return '仅限本人的订单和个人信息'
  return s || '-'
}

function switchTab(key) {
  currentTab.value = key
  if (key === 'users') loadUsers()
  if (key === 'products') loadProducts()
  if (key === 'orders') loadOrders()
  if (key === 'roles') loadRoles()
}

async function loadUsers() {
  try { users.value = (await api.getUsers()).users || [] } catch (e) { users.value = [] }
}

async function loadProducts() {
  try { products.value = (await api.getProducts()).products || [] } catch (e) { products.value = [] }
}

async function loadOrders() {
  try { orders.value = (await api.getOrders()).orders || [] } catch (e) { orders.value = [] }
}

async function cancelOrder(o) {
  if (!confirm(`确定取消订单 ${o.orderNumber}？取消后将恢复商品库存。`)) return
  try {
    await api.deleteOrder(o.id)
    alert('订单已取消')
    await loadOrders()
  } catch (e) { alert(e.message || '取消失败') }
}

async function loadRoles() {
  try {
    const data = await api.getRoles()
    matrix.value = data.matrix || {}
    resources.value = data.resources || []
    scopes.value = data.scopes || {}
  } catch (e) { matrix.value = {} }
}

async function createUser() {
  if (!userForm.username || !userForm.password) { alert('请填写用户名和密码'); return }
  try {
    await api.createUser({ username: userForm.username, password: userForm.password, role: userForm.role })
    alert('用户创建成功')
    userForm.username = ''
    userForm.password = ''
    loadUsers()
  } catch (e) { alert(e.message || '创建失败') }
}

async function deleteUser(u) {
  if (!confirm(`确定删除用户 ${u.username}？`)) return
  try { await api.deleteUser(u.id); loadUsers() } catch (e) { alert(e.message || '删除失败') }
}

async function createProduct() {
  if (!productForm.name) { alert('请填写商品名称'); return }
  try {
    await api.createProduct({ ...productForm, price: Number(productForm.price), stock: Number(productForm.stock) })
    alert('商品创建成功')
    productForm.name = ''
    loadProducts()
  } catch (e) { alert(e.message || '创建失败') }
}

async function deleteProduct(p) {
  if (!confirm(`确定删除商品 ${p.name}？`)) return
  try { await api.deleteProduct(p.id); loadProducts() } catch (e) { alert(e.message || '删除失败') }
}

async function regenerateRecoveryCodes() {
  if (!confirm('重新生成恢复码后，旧恢复码将立即失效。确定继续？')) return
  try {
    const res = await api.regenerateRecoveryCodes()
    newRecoveryCodes.value = res.recoveryCodes || []
  } catch (e) { alert(e.message || '生成失败') }
}

onMounted(() => {
  loadUsers()
  loadRoles()
})
</script>

<style scoped>
.admin-title { margin: 0 0 1.5rem; }
.admin-tabs { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
.tab { padding: .5rem 1.2rem; border: 1px solid #ccc; background: #fff; border-radius: 4px; cursor: pointer; }
.tab.active { background: #457b9d; color: #fff; border-color: #457b9d; }
.panel { background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); }
.panel h3 { margin: 0 0 1rem; }
.create-form { display: flex; gap: .5rem; margin-bottom: 1rem; flex-wrap: wrap; }
.create-form input, .create-form select { padding: .5rem .8rem; border: 1px solid #ccc; border-radius: 4px; }
.btn-primary { background: #457b9d; color: #fff; border: none; border-radius: 4px; padding: .5rem 1rem; cursor: pointer; }
.btn-danger { background: #e63946; color: #fff; border: none; border-radius: 4px; padding: .3rem .7rem; cursor: pointer; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th, .data-table td { padding: .6rem .8rem; border-bottom: 1px solid #eee; text-align: left; font-size: .9rem; }
.data-table th { background: #f8f8f8; }
.matrix td { font-size: .85rem; }
.empty-cell { text-align: center; color: #999; }
.panel-hint { color: #666; font-size: .9rem; margin: 0 0 1rem; }
.recovery-box { margin-top: 1.5rem; }
.recovery-list { list-style: none; padding: 0; margin: 0 0 1rem; display: grid; gap: .5rem; max-width: 480px; }
.recovery-list li { background: #f5f5f5; border: 1px dashed #ccc; border-radius: 4px; padding: .4rem .6rem; }
.recovery-list code { font-size: 1rem; letter-spacing: 1px; }
</style>