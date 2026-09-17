<template>
  <main style="flex: 1; max-width: 800px; width: 100%; margin: 2rem auto; padding: 0 1rem;">
    <h1 class="page-title">文件上传</h1>
    <div v-if="feedback.msg" class="feedback" :class="feedback.type">{{ feedback.msg }}</div>

    <!-- 登录界面 -->
    <div v-if="!isLoggedIn" class="login-container">
      <h2>管理员登录</h2>
      <div class="form-group"><label>用户名</label><input type="text" v-model="loginForm.username"></div>
      <div class="form-group"><label>密码</label><input type="password" v-model="loginForm.password" @keyup.enter="doLogin"></div>
      <button class="btn btn-login" @click="doLogin">登 录</button>
    </div>

    <!-- 上传界面 -->
    <div v-else class="upload-container" style="display:block;">
      <div class="dashboard-header">
        <span>欢迎，<strong>{{ username }}</strong></span>
        <button class="btn btn-logout" @click="doLogout">登出</button>
      </div>

      <form @submit.prevent="doUpload">
        <div class="form-group"><label>文件标题 *</label><input type="text" v-model="form.title" required></div>
        <div class="form-group"><label>作者</label><input type="text" v-model="form.author"></div>
        <div class="form-group">
          <label>分类</label>
          <select v-model="form.category">
            <option value="">选择分类</option>
            <option value="论文">论文</option>
            <option value="书籍">书籍</option>
            <option value="报告">报告</option>
            <option value="其他">其他</option>
          </select>
        </div>
        <div class="form-group">
          <label>文件 *</label>
          <div class="file-upload-area" @click="fileInputEl?.click()">
            <p>点击选择文件</p>
            <input ref="fileInputEl" type="file" style="display:none;" @change="onFileChange">
          </div>
          <div v-if="selectedFile" class="file-info" style="display:block;">
            文件名: {{ selectedFile.name }} | 大小: {{ (selectedFile.size / 1024 / 1024).toFixed(2) }} MB
          </div>
        </div>
        <div class="form-group"><label>简介</label><textarea v-model="form.description" rows="4"></textarea></div>
        <button type="submit" class="btn btn-submit" :disabled="uploading">{{ uploading ? '上传中...' : '上传文件' }}</button>
      </form>
    </div>
  </main>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { api, getToken, setToken } from '@/api'
import '@/styles/upload.css'

const isLoggedIn = ref(false)
const username = ref('admin')
const selectedFile = ref(null)
const uploading = ref(false)
const feedback = ref({ msg: '', type: '' })
const fileInputEl = ref(null)

const loginForm = reactive({ username: '', password: '' })
const form = reactive({ title: '', author: '', category: '', description: '' })

function showFeedback(msg, type) {
  feedback.value = { msg, type }
  setTimeout(() => { feedback.value = { msg: '', type: '' } }, 4000)
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

function onFileChange(e) {
  if (e.target.files.length > 0) selectedFile.value = e.target.files[0]
}

async function doUpload() {
  const title = form.title.trim()
  if (!title || !selectedFile.value) { showFeedback('请填写标题并选择文件', 'error'); return }
  if (selectedFile.value.size > 50 * 1024 * 1024) { showFeedback('文件大小不能超过50MB', 'error'); return }

  const reader = new FileReader()
  reader.onload = async () => {
    const fileData = reader.result.split(',')[1]
    uploading.value = true
    try {
      const result = await api.uploadFile({
        title,
        author: form.author.trim(),
        category: form.category,
        description: form.description.trim(),
        fileName: selectedFile.value.name,
        fileType: selectedFile.value.type,
        fileData
      })
      if (result.success) {
        showFeedback('✅ 文件上传成功', 'success')
        form.title = ''; form.author = ''; form.category = ''; form.description = ''
        selectedFile.value = null
        if (fileInputEl.value) fileInputEl.value.value = ''
      } else {
        showFeedback('⚠️ ' + (result.error || '上传失败'), 'error')
      }
    } catch (e) {
      showFeedback('⚠️ ' + (e.message || '网络错误'), 'error')
    } finally {
      uploading.value = false
    }
  }
  reader.readAsDataURL(selectedFile.value)
}

onMounted(() => {
  if (getToken()) isLoggedIn.value = true
})
</script>
