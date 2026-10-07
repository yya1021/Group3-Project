<template>
  <main style="flex: 1; max-width: 900px; width: 100%; margin: 2rem auto; padding: 0 1rem;">
    <h1 class="page-title">审核管理</h1>

    <div v-if="feedback.msg" class="feedback" :class="feedback.type">{{ feedback.msg }}</div>

    <!-- 登录界面 -->
    <div v-if="!isLoggedIn" class="login-container">
      <h2>管理员登录</h2>
      <div class="form-group"><label>用户名</label><input type="text" v-model="loginForm.username"></div>
      <div class="form-group"><label>密码</label><input type="password" v-model="loginForm.password" @keyup.enter="doLogin"></div>
      <button class="btn-login" @click="doLogin">登 录</button>
    </div>

    <!-- 控制面板 -->
    <div v-else class="dashboard" style="display:block;">
      <div class="dashboard-header">
        <div class="user-info">
          <span>欢迎，<strong>{{ username }}</strong></span>
          <button class="btn-logout" @click="doLogout">登出</button>
        </div>
      </div>

      <div class="tab-bar">
        <button class="tab-btn" :class="{ active: currentTab === 'pending' }" @click="switchTab('pending')">待审核文章</button>
        <button class="tab-btn" :class="{ active: currentTab === 'published' }" @click="switchTab('published')">已发布文章</button>
        <button class="tab-btn" :class="{ active: currentTab === 'comments' }" @click="switchTab('comments')">评论审核</button>
        <button class="tab-btn" :class="{ active: currentTab === 'files' }" @click="switchTab('files')">文件管理</button>
      </div>

      <div class="review-list">
        <div v-if="loading" class="empty-state">加载中...</div>
        <div v-else-if="currentItems.length === 0" class="empty-state">{{ emptyText }}</div>

        <!-- 评论审核 -->
        <template v-if="currentTab === 'comments'">
          <div v-for="comment in currentItems" :key="comment.id" class="review-item">
            <div class="review-meta">
              评论者: {{ comment.author || '匿名' }}
              | 状态: <strong>{{ comment.status === 'pending' ? '待审核' : '已通过' }}</strong>
              | 所属: {{ contentTypeLabel(comment.contentType) }} #{{ comment.contentId }}
              | 时间: {{ formatDateTime(comment.createdAt) }}
            </div>
            <div class="review-content">{{ comment.content }}</div>
            <div class="review-actions">
              <button v-if="comment.status === 'pending'" class="btn btn-approve" @click="approveComment(comment.id)">通过</button>
              <button class="btn btn-delete" @click="rejectComment(comment.id)">拒绝</button>
            </div>
          </div>
        </template>

        <!-- 文件管理 -->
        <template v-if="currentTab === 'files'">
          <div v-for="file in currentItems" :key="file.id" class="review-item">
            <h3>{{ file.title }}</h3>
            <div class="review-meta">
              作者: {{ file.author || '匿名' }} | 分类: {{ file.category || '其他' }} | 大小: {{ formatSize(file.fileSize) }} | 上传者: {{ file.uploadedBy || '未知' }} | 上传时间: {{ formatDateTime(file.createdAt) }}
            </div>
            <div v-if="file.description" class="review-content">{{ file.description }}</div>
            <div class="review-actions">
              <a :href="`/api/files/${file.id}/download`" class="btn btn-view">下载</a>
              <button class="btn btn-delete" @click="deleteFile(file.id)">下架</button>
            </div>
          </div>
        </template>

        <!-- 文章 -->
        <template v-else>
          <div v-for="post in currentItems" :key="post.id" class="review-item">
            <h3>{{ post.title }}</h3>
            <div class="review-meta">作者: {{ post.author || '匿名' }} | 分类: {{ post.category || '未分类' }} | ID: {{ post.id }}</div>
            <div v-if="post.tags && post.tags.length" style="margin-bottom:0.5rem;">
              <span v-for="tag in post.tags" :key="tag" style="display:inline-block;background:#000;color:#FFF;padding:0.2rem 0.6rem;margin-right:0.3rem;font-size:0.8rem;">{{ tag }}</span>
            </div>
            <div class="review-content" v-html="truncateContent(post.content)"></div>
            <div class="review-actions">
              <template v-if="currentTab === 'pending'">
                <button class="btn btn-view" @click="viewPost(post)">查看</button>
                <button class="btn btn-edit" @click="openEditModal(post)">编辑</button>
                <button class="btn btn-approve" @click="approvePost(post.id)">通过</button>
                <button class="btn btn-reject" @click="rejectPost(post.id)">拒绝</button>
              </template>
              <template v-else>
                <button class="btn btn-view" @click="viewPost(post)">查看</button>
                <button class="btn btn-edit" @click="openEditModal(post)">编辑</button>
                <button class="btn btn-delete" @click="deletePost(post.id)">删除</button>
              </template>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- 编辑弹窗 -->
    <div v-if="editModalOpen" class="modal-overlay" style="display:flex;">
      <div class="modal">
        <h3>编辑文章</h3>
        <div class="form-group"><label>标题</label><input type="text" v-model="editForm.title"></div>
        <div class="form-group"><label>作者</label><input type="text" v-model="editForm.author"></div>
        <div class="form-group">
          <label>分类</label>
          <select v-model="editForm.category">
            <option value="">未分类</option>
            <option value="技术">技术</option>
            <option value="自然科学">自然科学</option>
            <option value="哲学">哲学</option>
            <option value="科社">科社</option>
            <option value="政经">政经</option>
          </select>
        </div>
        <div class="form-group"><label>标签（逗号分隔）</label><input type="text" v-model="editForm.tags"></div>
        <div class="form-group"><label>内容</label><textarea v-model="editForm.content" rows="8"></textarea></div>
        <div class="modal-actions">
          <button class="btn btn-approve" @click="saveEdit">保存</button>
          <button class="btn btn-reject" @click="editModalOpen = false">取消</button>
        </div>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { api, getToken, setToken } from '@/api'
import '@/styles/review.css'

const isLoggedIn = ref(false)
const username = ref('admin')
const currentTab = ref('pending')
const currentItems = ref([])
const loading = ref(false)
const feedback = ref({ msg: '', type: '' })
const editModalOpen = ref(false)
const editForm = reactive({ id: null, type: 'published', title: '', author: '', category: '', tags: '', content: '' })
const loginForm = reactive({ username: '', password: '' })

const emptyText = computed(() => {
  if (currentTab.value === 'pending') return '暂无待审核文章'
  if (currentTab.value === 'published') return '暂无已发布文章'
  if (currentTab.value === 'files') return '暂无文件'
  return '暂无评论'
})

function showFeedback(msg, type) {
  feedback.value = { msg, type }
  setTimeout(() => { feedback.value = { msg: '', type: '' } }, 3000)
}

async function doLogin() {
  const u = loginForm.username.trim()
  const p = loginForm.password.trim()
  if (!u || !p) { showFeedback('请输入用户名和密码', 'error'); return }
  try {
    const result = await api.login(u, p)
    if (result.success) {
      setToken(result.token)
      username.value = result.user.username
      isLoggedIn.value = true
      showFeedback('✅ 登录成功', 'success')
      loadContent()
    } else {
      showFeedback('⚠️ ' + (result.error || '登录失败'), 'error')
    }
  } catch (e) {
    showFeedback('⚠️ ' + (e.message || '网络错误'), 'error')
  }
}

function doLogout() {
  try { api.logout() } catch (e) {}
  setToken(null)
  isLoggedIn.value = false
  loginForm.password = ''
}

function switchTab(tab) {
  currentTab.value = tab
  loadContent()
}

function formatSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1024 / 1024).toFixed(2) + ' MB'
}

function formatDateTime(str) {
  try { return new Date(str).toLocaleString('zh-CN') } catch (e) { return '' }
}

function truncateContent(html) {
  return (html || '').substring(0, 300)
}

async function loadContent() {
  if (!isLoggedIn.value) return
  loading.value = true
  try {
    let data
    if (currentTab.value === 'pending') data = await api.getPending()
    else if (currentTab.value === 'published') data = await api.getPosts()
    else if (currentTab.value === 'comments') data = await api.getAllComments()
    else data = await api.getFiles()

    if (currentTab.value === 'files') currentItems.value = data.files || []
    else if (currentTab.value === 'comments') currentItems.value = data.comments || []
    else currentItems.value = data.posts || []
  } catch (e) {
    if (e.status === 401) {
      setToken(null)
      isLoggedIn.value = false
      showFeedback('登录已过期，请重新登录', 'error')
    } else {
      currentItems.value = []
      showFeedback('加载失败: ' + e.message, 'error')
    }
  } finally {
    loading.value = false
  }
}

function viewPost(post) {
  alert('标题: ' + post.title + '\n\n' + post.content)
}

function openEditModal(post) {
  editForm.id = post.id
  editForm.type = currentTab.value === 'pending' ? 'pending' : 'published'
  editForm.title = post.title || ''
  editForm.author = post.author || ''
  editForm.category = post.category || ''
  editForm.tags = (post.tags || []).join(', ')
  editForm.content = post.content || ''
  editModalOpen.value = true
}

async function saveEdit() {
  const title = editForm.title.trim()
  const content = editForm.content.trim()
  if (!title || !content) { showFeedback('标题和内容不能为空', 'error'); return }
  try {
    const tags = editForm.tags ? editForm.tags.split(',').map(t => t.trim()).filter(t => t) : []
    const result = await api.updatePost(editForm.id, {
      title, author: editForm.author, category: editForm.category, content, tags, type: editForm.type
    })
    if (result.success) {
      showFeedback('✅ 更新成功', 'success')
      editModalOpen.value = false
      loadContent()
    } else {
      showFeedback('⚠️ ' + (result.error || '更新失败'), 'error')
    }
  } catch (e) {
    showFeedback('⚠️ ' + (e.message || '网络错误'), 'error')
  }
}

async function approvePost(id) {
  if (!confirm('确定要通过这篇文章吗？')) return
  try {
    const result = await api.approve(id)
    if (result.success) { showFeedback('✅ 审核通过', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '操作失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

async function rejectPost(id) {
  if (!confirm('确定要拒绝这篇文章吗？')) return
  try {
    const result = await api.reject(id)
    if (result.success) { showFeedback('已拒绝', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '操作失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

async function deletePost(id) {
  if (!confirm('确定要删除这篇文章吗？')) return
  try {
    const result = await api.deletePost(id)
    if (result.success) { showFeedback('✅ 已删除', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '删除失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

async function deleteFile(id) {
  if (!confirm('确定要下架这个文件吗？此操作不可恢复！')) return
  try {
    const result = await api.deleteFile(id)
    if (result.success) { showFeedback('✅ 文件已下架', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '下架失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

function contentTypeLabel(type) {
  return type === 'article' ? '文章' : (type === 'file' ? '文件' : (type || '内容'))
}

async function approveComment(id) {
  try {
    const result = await api.approveComment(id)
    if (result.success) { showFeedback('✅ 评论已通过', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '操作失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

async function rejectComment(id) {
  if (!confirm('确定要拒绝并删除这条评论吗？')) return
  try {
    const result = await api.rejectComment(id)
    if (result.success) { showFeedback('已拒绝', 'success'); loadContent() }
    else showFeedback('⚠️ ' + (result.error || '操作失败'), 'error')
  } catch (e) { showFeedback('⚠️ ' + (e.message || '网络错误'), 'error') }
}

onMounted(() => {
  if (getToken()) {
    isLoggedIn.value = true
    loadContent()
  }
})
</script>
