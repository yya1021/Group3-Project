<template>
  <main class="merchant-page" style="max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; flex: 1;">
    <div class="merchant-header">
      <h2 class="merchant-title">商户管理后台</h2>
      <p class="welcome">欢迎，{{ username }}（商户）· 店铺ID：{{ shopId || '未分配' }}</p>
    </div>

    <div class="merchant-tabs">
      <button v-for="t in tabs" :key="t.key" class="tab" :class="{ active: currentTab === t.key }" @click="switchTab(t.key)">
        {{ t.label }}
      </button>
    </div>

    <!-- 我的商品 -->
    <section v-if="currentTab === 'products'" class="panel">
      <h3>{{ editingId ? '编辑商品' : '新增商品' }}</h3>
      <div class="edit-form">
        <select v-model="productForm.type">
          <option value="hand">手忍</option>
          <option value="knife">刀忍</option>
          <option value="hamu">哈姆</option>
          <option value="other">其他</option>
        </select>
        <input type="text" v-model="productForm.name" placeholder="商品名称">
        <input type="number" v-model="productForm.price" placeholder="价格">
        <input type="number" v-model="productForm.stock" placeholder="库存">
        <button class="btn-primary" @click="saveProduct">{{ editingId ? '保存修改' : '新增商品' }}</button>
        <button v-if="editingId" class="btn-secondary" @click="cancelEdit">取消</button>
      </div>

      <table class="data-table">
        <thead><tr><th>ID</th><th>类型</th><th>名称</th><th>价格</th><th>库存</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="p in myProducts" :key="p.id">
            <td>{{ p.id }}</td>
            <td>{{ p.type }}</td>
            <td>{{ p.name }}</td>
            <td>¥{{ p.price }}</td>
            <td>{{ p.stock }}</td>
            <td>
              <button class="btn-edit" @click="editProduct(p)">编辑</button>
              <button class="btn-danger" @click="deleteProduct(p)">删除</button>
            </td>
          </tr>
          <tr v-if="myProducts.length === 0"><td colspan="6" class="empty-cell">暂无商品，请新增商品</td></tr>
        </tbody>
      </table>
    </section>

    <!-- 订单管理 -->
    <section v-if="currentTab === 'orders'" class="panel">
      <h3>本店订单</h3>
      <table class="data-table">
        <thead><tr><th>订单号</th><th>买家</th><th>商品</th><th>金额</th><th>时间</th></tr></thead>
        <tbody>
          <tr v-for="o in orders" :key="o.id">
            <td>{{ o.orderNumber }}</td>
            <td>{{ o.username }}</td>
            <td>{{ o.products.map(p => `${p.name}×${p.amount}`).join('、') }}</td>
            <td>¥{{ o.totalAmount }}</td>
            <td>{{ o.createdAt }}</td>
          </tr>
          <tr v-if="orders.length === 0"><td colspan="5" class="empty-cell">暂无订单</td></tr>
        </tbody>
      </table>
    </section>
  </main>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { api } from '@/api'
import { state } from '@/stores/auth'

const currentTab = ref('products')
const products = ref([])
const orders = ref([])
const editingId = ref(null)

const username = computed(() => state.user?.username || '')
const shopId = computed(() => state.user?.shopId || null)

// 商户仅能看到本人店铺的商品
const myProducts = computed(() => products.value.filter(p => p.shopId === shopId.value))

const tabs = [
  { key: 'products', label: '我的商品' },
  { key: 'orders', label: '订单管理' }
]

const productForm = reactive({ type: 'hand', name: '', price: 0, stock: 0 })

function switchTab(key) {
  currentTab.value = key
  if (key === 'products') loadProducts()
  if (key === 'orders') loadOrders()
}

async function loadProducts() {
  try { products.value = (await api.getProducts()).products || [] } catch (e) { products.value = [] }
}

async function loadOrders() {
  try { orders.value = (await api.getOrders()).orders || [] } catch (e) { orders.value = [] }
}

function clearForm() {
  editingId.value = null
  productForm.type = 'hand'
  productForm.name = ''
  productForm.price = 0
  productForm.stock = 0
}

function editProduct(p) {
  editingId.value = p.id
  productForm.type = p.type
  productForm.name = p.name
  productForm.price = p.price
  productForm.stock = p.stock
}

function cancelEdit() {
  clearForm()
}

async function saveProduct() {
  if (!productForm.name) { alert('请填写商品名称'); return }
  try {
    const data = {
      type: productForm.type,
      name: productForm.name,
      price: Number(productForm.price),
      stock: Number(productForm.stock)
    }
    if (editingId.value) {
      await api.updateProduct(editingId.value, data)
      alert('商品修改成功')
    } else {
      await api.createProduct(data)
      alert('商品新增成功')
    }
    clearForm()
    loadProducts()
  } catch (e) { alert(e.message || '操作失败') }
}

async function deleteProduct(p) {
  if (!confirm(`确定删除商品 ${p.name}？`)) return
  try { await api.deleteProduct(p.id); loadProducts() } catch (e) { alert(e.message || '删除失败') }
}

onMounted(() => {
  loadProducts()
  loadOrders()
})
</script>

<style scoped>
.merchant-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; flex-wrap: wrap; gap: .5rem; }
.merchant-title { margin: 0; }
.welcome { color: #666; margin: .5rem 0 0; }
.merchant-tabs { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
.tab { padding: .5rem 1.2rem; border: 1px solid #ccc; background: #fff; border-radius: 4px; cursor: pointer; }
.tab.active { background: #457b9d; color: #fff; border-color: #457b9d; }
.panel { background: #fff; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,.06); }
.panel h3 { margin: 0 0 1rem; }
.edit-form { display: flex; gap: .5rem; margin-bottom: 1rem; flex-wrap: wrap; }
.edit-form input, .edit-form select { padding: .5rem .8rem; border: 1px solid #ccc; border-radius: 4px; }
.btn-primary { background: #457b9d; color: #fff; border: none; border-radius: 4px; padding: .5rem 1rem; cursor: pointer; }
.btn-secondary { background: #eee; color: #333; border: none; border-radius: 4px; padding: .5rem 1rem; cursor: pointer; }
.btn-edit { background: #ffc107; color: #000; border: none; border-radius: 4px; padding: .3rem .7rem; cursor: pointer; margin-right: .3rem; }
.btn-danger { background: #e63946; color: #fff; border: none; border-radius: 4px; padding: .3rem .7rem; cursor: pointer; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th, .data-table td { padding: .6rem .8rem; border-bottom: 1px solid #eee; text-align: left; font-size: .9rem; }
.data-table th { background: #f8f8f8; }
.empty-cell { text-align: center; color: #999; }
</style>