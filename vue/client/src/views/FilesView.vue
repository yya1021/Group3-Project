<template>
  <main style="flex: 1; max-width: 900px; width: 100%; margin: 2rem auto; padding: 0 1rem;">
    <h1 class="page-title">文件阅览</h1>

    <div class="search-container">
      <input type="text" class="search-input" v-model="search" placeholder="搜索文件标题、作者或分类...">
    </div>

    <div class="file-list">
      <div v-if="loading" class="empty-state">加载中...</div>
      <div v-else-if="filteredFiles.length === 0" class="empty-state">暂无文件</div>
      <div v-for="file in filteredFiles" :key="file.id" class="file-item">
        <h3>{{ file.title }}</h3>
        <div class="file-meta">
          作者: {{ file.author || '匿名' }} | 分类: {{ file.category || '其他' }} | 大小: {{ formatSize(file.fileSize) }} | 上传时间: {{ formatDate(file.createdAt) }}
        </div>
        <div v-if="file.description" class="file-description">{{ file.description }}</div>
        <a :href="`/api/files/${file.id}/download`" class="btn-download">⬇ 下载</a>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { api } from '@/api'
import '@/styles/files.css'

const allFiles = ref([])
const search = ref('')
const loading = ref(true)

const filteredFiles = computed(() => {
  const term = search.value.toLowerCase().trim()
  if (!term) return allFiles.value
  return allFiles.value.filter(f =>
    (f.title && f.title.toLowerCase().includes(term)) ||
    (f.author && f.author.toLowerCase().includes(term)) ||
    (f.category && f.category.toLowerCase().includes(term))
  )
})

function formatSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}

function formatDate(dateStr) {
  try { return new Date(dateStr).toLocaleDateString('zh-CN') } catch (e) { return '' }
}

async function load() {
  loading.value = true
  try {
    const data = await api.getFiles()
    allFiles.value = data.files || []
  } catch (e) {
    allFiles.value = []
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
