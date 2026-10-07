<template>
  <main class="register-page" style="max-width: 480px; margin: 3rem auto; padding: 2rem; flex: 1;">
    <div class="register-card">
      <h2 class="register-title">用户注册</h2>
      <div class="form-group">
        <label>账号类型</label>
        <select v-model="form.role">
          <option value="user">普通用户</option>
          <option value="merchant">商户</option>
        </select>
      </div>
      <div class="form-group">
        <label>用户名</label>
        <input type="text" v-model="form.username" placeholder="请输入用户名">
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" v-model="form.password" placeholder="请输入密码">
      </div>
      <div class="form-group">
        <label>确认密码</label>
        <input type="password" v-model="form.confirm" placeholder="再次输入密码">
      </div>
      <div v-if="error" class="form-error">{{ error }}</div>
      <button class="btn btn-primary" :disabled="loading" @click="doRegister">{{ loading ? '注册中...' : '注册' }}</button>
      <div class="login-link">
        已有账号？<a @click.prevent="$router.push('/login')">点此登录</a>
      </div>
    </div>
  </main>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api'
import { setAuth, homePathFor } from '@/stores/auth'

const router = useRouter()
const form = reactive({ username: '', password: '', confirm: '', role: 'user' })
const error = ref('')
const loading = ref(false)

async function doRegister() {
  error.value = ''
  if (!form.username.trim() || !form.password) { error.value = '请输入用户名和密码'; return }
  if (form.password !== form.confirm) { error.value = '两次输入的密码不一致'; return }
  loading.value = true
  try {
    const res = await api.register(form.username.trim(), form.password, form.role)
    setAuth(res.token, res.user)
    router.push(homePathFor(res.user.role))
  } catch (e) {
    error.value = e.message || '注册失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.register-card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 2rem; }
.register-title { text-align: center; margin: 0 0 1.5rem; }
.form-group { margin-bottom: 1rem; display: flex; flex-direction: column; }
.form-group label { margin-bottom: .4rem; font-weight: 600; }
.form-group input, .form-group select { padding: .6rem .8rem; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
.btn { display: inline-block; padding: .6rem 1.2rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
.btn-primary { background: #457b9d; color: #fff; width: 100%; }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.form-error { color: #e63946; margin-bottom: .8rem; font-size: .9rem; }
.login-link { margin-top: 1rem; text-align: center; font-size: .9rem; }
.login-link a { color: #457b9d; cursor: pointer; }
</style>