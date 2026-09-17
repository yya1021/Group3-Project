<template>
  <main class="shop-page" style="max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; flex: 1;">
    <div class="shop-header">
      <div>
        <h2 class="shop-title">商品商城</h2>
        <p class="welcome">欢迎，{{ username }}（{{ roleName(role) }}）</p>
      </div>
      <button class="cart-btn" @click="$router.push('/cart')">购物车 ({{ cartCount }})</button>
    </div>

    <!-- 分类切换 -->
    <div class="type-tabs">
      <button v-for="t in types" :key="t.key" class="type-tab" :class="{ active: currentType === t.key }" @click="switchType(t.key)">
        {{ t.label }}
      </button>
    </div>

    <div v-if="loading" class="loading">加载中...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="products.length === 0" class="empty">暂无商品</div>
    <div v-else class="product-grid">
      <div v-for="item in products" :key="item.id" class="product-item">
        <div class="product-image"><img :src="item.photo" :alt="item.name"></div>
        <div class="product-info">
          <h3 class="product-name">{{ item.name }}</h3>
          <p class="product-price">¥{{ item.price }}</p>
          <p class="product-stock">库存：{{ item.stock }}</p>
          <p v-if="item.shopId" class="product-shop">店铺ID：{{ item.shopId }}</p>
          <button class="add-btn" @click="addToCart(item)">加入购物车</button>
        </div>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api'
import { state, roleName } from '@/stores/auth'

const route = useRoute()

const role = computed(() => state.user?.role || 'user')
const username = computed(() => state.user?.username || '')
const currentType = ref('all')
const products = ref([])
const cart = ref([])
const loading = ref(true)
const error = ref('')

const types = [
  { key: 'all', label: '全部' },
  { key: 'hand', label: '手忍' },
  { key: 'knife', label: '刀忍' },
  { key: 'hamu', label: '哈姆' },
  { key: 'other', label: '其他' }
]

const cartCount = computed(() => cart.value.reduce((sum, i) => sum + (i.amount || 1), 0))

async function loadProducts() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.getProducts(currentType.value === 'all' ? null : currentType.value)
    products.value = data.products || []
  } catch (e) {
    error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}

async function loadCart() {
  try {
    const data = await api.getCart()
    cart.value = data.cart || []
  } catch (e) { cart.value = [] }
}

function switchType(key) {
  currentType.value = key
  loadProducts()
}

function addToCart(item) {
  const existing = cart.value.find(p => p.id === item.id)
  if (existing) {
    existing.amount = (existing.amount || 1) + 1
  } else {
    cart.value.push({ id: item.id, name: item.name, price: item.price, photo: item.photo, amount: 1 })
  }
  saveCart()
}

async function saveCart() {
  try {
    await api.saveCart(cart.value.map(i => ({ id: i.id, amount: i.amount || 1 })))
  } catch (e) {
    // 失败时回滚本地购物车变动并提示
    alert(e.message || '加入购物车失败，请先登录')
  }
}

onMounted(() => {
  const t = route.query.type
  if (t && types.some(x => x.key === t)) currentType.value = t
  loadProducts()
  loadCart()
})
</script>

<style scoped>
.shop-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
.shop-title { margin: 0; }
.welcome { color: #666; margin: .5rem 0 0; }
.cart-btn { background: #457b9d; color: #fff; border: none; border-radius: 4px; padding: .6rem 1.2rem; cursor: pointer; }
.type-tabs { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
.type-tab { padding: .5rem 1.2rem; border: 1px solid #ccc; background: #fff; border-radius: 20px; cursor: pointer; }
.type-tab.active { background: #457b9d; color: #fff; border-color: #457b9d; }
.product-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.2rem; }
.product-item { background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); display: flex; flex-direction: column; }
.product-image { aspect-ratio: 1; background: #f5f5f5; display: flex; align-items: center; justify-content: center; }
.product-image img { max-width: 80%; max-height: 80%; object-fit: contain; }
.product-info { padding: .8rem; display: flex; flex-direction: column; flex: 1; }
.product-name { margin: 0 0 .4rem; font-size: 1rem; }
.product-price { color: #e63946; font-weight: bold; margin: 0 0 .3rem; }
.product-stock { color: #666; font-size: .85rem; margin: 0 0 .3rem; }
.product-shop { color: #457b9d; font-size: .8rem; margin: 0 0 .5rem; }
.add-btn { margin-top: auto; padding: .5rem; background: #457b9d; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
.add-btn:hover { background: #1d3557; }
.loading, .error, .empty { padding: 2rem; text-align: center; color: #666; }
.error { color: #e63946; }
@media (max-width: 900px) { .product-grid { grid-template-columns: repeat(2, 1fr); } }
</style>