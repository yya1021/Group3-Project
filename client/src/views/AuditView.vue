<template>
  <main class="audit-page" style="max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; flex: 1;">
    <div class="audit-header">
      <h2 class="audit-title">审计日志</h2>
      <button class="btn-export" @click="exportReport">导出报告 (CSV)</button>
    </div>

    <div v-if="loading" class="loading">加载中...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="logs.length === 0" class="empty">暂无审计日志</div>
    <table v-else class="data-table">
      <thead>
        <tr><th>ID</th><th>操作者</th><th>角色</th><th>动作</th><th>资源</th><th>详情</th><th>IP</th><th>时间</th></tr>
      </thead>
      <tbody>
        <tr v-for="log in logs" :key="log.id">
          <td>{{ log.id }}</td>
          <td>{{ log.operator }}</td>
          <td>{{ roleName(log.role) }}</td>
          <td>{{ log.action }}</td>
          <td>{{ log.resource }}</td>
          <td>{{ log.detail || '-' }}</td>
          <td>{{ log.ip || '-' }}</td>
          <td>{{ log.timestamp }}</td>
        </tr>
      </tbody>
    </table>
  </main>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { api } from '@/api'
import { ROLE_NAMES } from '@/stores/auth'

const logs = ref([])
const loading = ref(true)
const error = ref('')

function roleName(r) { return ROLE_NAMES[r] || r }

async function load() {
  loading.value = true
  error.value = ''
  try {
    const data = await api.getAuditLogs()
    logs.value = data.logs || []
  } catch (e) {
    error.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}

async function exportReport() {
  try {
    const token = localStorage.getItem('library_token')
    const res = await fetch('/api/audit-logs/export', { headers: { 'Authorization': token } })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      throw new Error(data.error || '导出失败')
    }
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'audit-report.csv'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  } catch (e) {
    alert(e.message || '导出失败')
  }
}

onMounted(load)
</script>

<style scoped>
.audit-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
.audit-title { margin: 0; }
.btn-export { background: #2a9d8f; color: #fff; border: none; border-radius: 4px; padding: .6rem 1.2rem; cursor: pointer; }
.data-table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; }
.data-table th, .data-table td { padding: .6rem .8rem; border-bottom: 1px solid #eee; text-align: left; font-size: .85rem; }
.data-table th { background: #f8f8f8; }
.loading, .error, .empty { padding: 2rem; text-align: center; color: #666; }
.error { color: #e63946; }
</style>