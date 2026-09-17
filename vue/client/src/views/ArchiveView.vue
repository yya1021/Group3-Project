<template>
  <main style="flex: 1; max-width: 800px; width: 100%; margin: 0 auto; padding: 2rem 1rem;">
    <div class="archive-container">
      <div class="archive-banner">
        <img src="/images/banner_2.png" alt="文章归档">
      </div>

      <div class="archive-header">
        <h2>文章归档</h2>
        <p>这里收录了所有文章</p>
      </div>

      <!-- 搜索框 -->
      <div class="search-container">
        <div class="search-input-wrapper">
          <span class="search-icon">🔍</span>
          <input type="text" v-model="search" class="search-input" placeholder="搜索标题、作者或标签..." @input="applySearch">
        </div>
        <div class="search-info">{{ searchInfo }}</div>
      </div>

      <!-- 文章列表 -->
      <div class="post-list">
        <div v-if="loading" class="loading">加载中...</div>
        <div v-else-if="error" class="error">加载文章失败: {{ error }}</div>
        <div v-else-if="filteredPosts.length === 0" class="empty">暂无文章</div>
        <div v-for="post in pagePosts" :key="post.id" class="post-item" @click="$router.push(`/post/${post.id}`)">
          <h3>{{ post.title || '无标题' }}</h3>
          <div class="post-meta">作者: {{ post.author || '未知作者' }} | 分类: {{ post.category || '未分类' }} | 发布时间: {{ formatDate(post.createdAt) }}</div>
          <div class="post-excerpt">{{ plainText(post.content).substring(0, 100) }}...</div>
          <div v-if="post.tags && post.tags.length" class="post-tags">
            <span v-for="tag in post.tags" :key="tag" class="post-tag">{{ tag }}</span>
          </div>
        </div>
      </div>

      <!-- 分页器 -->
      <div class="pagination">
        <button class="page-btn" :disabled="currentPage === 1" @click="goPage(currentPage - 1)">上一页</button>
        <template v-for="(p, i) in pageNumbers" :key="i">
          <button v-if="p !== '...'" class="page-btn" :class="{ active: p === currentPage }" @click="goPage(p)">{{ p }}</button>
          <span v-else class="page-ellipsis">...</span>
        </template>
        <button class="page-btn" :disabled="currentPage === totalPages" @click="goPage(currentPage + 1)">下一页</button>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '@/api'
import '@/styles/archive.css'

const allPosts = ref([])
const filteredPosts = ref([])
const search = ref('')
const searchInfo = ref('')
const currentPage = ref(1)
const loading = ref(true)
const error = ref('')
const postsPerPage = 5

const totalPages = computed(() => Math.max(1, Math.ceil(filteredPosts.value.length / postsPerPage)))

const pagePosts = computed(() => {
  const start = (currentPage.value - 1) * postsPerPage
  return filteredPosts.value.slice(start, start + postsPerPage)
})

const pageNumbers = computed(() => {
  const pages = []
  const total = totalPages.value
  for (let i = 1; i <= total; i++) {
    if (i === currentPage.value || Math.abs(i - currentPage.value) <= 2 || i === 1 || i === total) {
      pages.push(i)
    } else if (Math.abs(i - currentPage.value) === 3) {
      pages.push('...')
    }
  }
  return pages
})

function plainText(html) {
  const div = document.createElement('div')
  div.innerHTML = html || ''
  return div.textContent || ''
}

function formatDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('zh-CN') } catch (e) { return '未知日期' }
}

function applySearch() {
  const term = search.value.trim().toLowerCase()
  if (!term) {
    filteredPosts.value = [...allPosts.value]
    searchInfo.value = ''
  } else {
    filteredPosts.value = allPosts.value.filter(post => {
      if (post.title && post.title.toLowerCase().includes(term)) return true
      if (post.author && post.author.toLowerCase().includes(term)) return true
      if (post.tags && Array.isArray(post.tags)) return post.tags.some(t => t.toLowerCase().includes(term))
      if (post.category && post.category.toLowerCase().includes(term)) return true
      return false
    })
    searchInfo.value = '找到 ' + filteredPosts.value.length + ' 篇相关文章'
  }
  currentPage.value = 1
}

function goPage(page) {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
}

async function load() {
  loading.value = true
  try {
    const data = await api.getPosts()
    allPosts.value = (data.posts || []).sort((a, b) => b.id - a.id)
    filteredPosts.value = [...allPosts.value]
  } catch (e) {
    error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
