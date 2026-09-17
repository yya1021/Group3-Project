<template>
  <main class="home-ecommerce">
    <!-- 顶部横幅（纯色占位） -->
    <section class="hero-banner">
      <div class="hero-text">
        <h1>优选商城</h1>
        <p>精选好物 · 一键下单 · 安全交易</p>
        <router-link to="/shop" class="hero-btn">立即选购</router-link>
      </div>
    </section>

    <!-- 商品分类入口 -->
    <section class="category-section">
      <h2 class="section-title">商品分类</h2>
      <div class="category-grid">
        <router-link v-for="c in categories" :key="c.key" :to="`/shop?type=${c.key}`" class="category-card" :style="{ background: c.color }">
          <span class="category-name">{{ c.label }}</span>
        </router-link>
      </div>
    </section>

    <!-- 热门商品 -->
    <section class="hot-section">
      <h2 class="section-title">热门商品</h2>
      <div v-if="loading" class="status-box">加载中...</div>
      <div v-else-if="error" class="status-box error">{{ error }}</div>
      <div v-else-if="products.length === 0" class="status-box">暂无商品</div>
      <div v-else class="hot-grid">
        <div v-for="item in products.slice(0, 8)" :key="item.id" class="hot-card">
          <div class="hot-image" :style="{ background: colorOf(item.id) }"></div>
          <div class="hot-info">
            <h3 class="hot-name">{{ item.name }}</h3>
            <p class="hot-price">¥{{ item.price }}</p>
            <p v-if="item.shopId" class="hot-shop">店铺ID：{{ item.shopId }}</p>
          </div>
        </div>
      </div>
    </section>
  </main>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '@/api'

const categories = [
  { key: 'hand', label: '手忍', color: '#457b9d' },
  { key: 'knife', label: '刀忍', color: '#e63946' },
  { key: 'hamu', label: '哈姆', color: '#2a9d8f' },
  { key: 'other', label: '其他', color: '#e76f51' }
]

const products = ref([])
const loading = ref(true)
const error = ref('')

const palette = ['#457b9d', '#e63946', '#2a9d8f', '#e76f51', '#6d597a', '#b56576', '#4d908e', '#f4a261']
function colorOf(id) { return palette[id % palette.length] }

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.getProducts()
    products.value = data.products || []
  } catch (e) {
    error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.home-ecommerce { padding: 0 1rem 2rem; }
.hero-banner {
  min-height: 260px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #1d3557, #457b9d);
  border-radius: 8px;
  margin: 1.5rem 0;
  text-align: center;
}
.hero-text h1 { color: #fff; font-size: 3rem; margin: 0 0 .5rem; letter-spacing: 4px; }
.hero-text p { color: #e0e0e0; margin: 0 0 1.5rem; }
.hero-btn { display: inline-block; background: #e63946; color: #fff; padding: .7rem 2rem; border-radius: 30px; text-decoration: none; font-size: 1rem; }
.hero-btn:hover { background: #c41e1e; }
.section-title { font-size: 1.5rem; margin: 2rem 0 1rem; border-left: 4px solid #457b9d; padding-left: .8rem; }
.category-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
.category-card { height: 100px; border-radius: 8px; display: flex; align-items: center; justify-content: center; text-decoration: none; }
.category-name { color: #fff; font-size: 1.2rem; font-weight: bold; letter-spacing: 2px; }
.hot-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.2rem; }
.hot-card { background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,.08); }
.hot-image { aspect-ratio: 1; }
.hot-info { padding: .8rem; }
.hot-name { margin: 0 0 .4rem; font-size: 1rem; }
.hot-price { margin: 0; color: #e63946; font-weight: bold; }
.hot-shop { margin: .3rem 0 0; color: #457b9d; font-size: .8rem; }
.status-box { padding: 2rem; text-align: center; color: #666; }
.status-box.error { color: #e63946; }
@media (max-width: 900px) { .category-grid, .hot-grid { grid-template-columns: repeat(2, 1fr); } }
</style>