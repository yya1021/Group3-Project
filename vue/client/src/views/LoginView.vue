<template>
  <main class="login-page" style="max-width: 480px; margin: 3rem auto; padding: 2rem; flex: 1;">
    <div class="login-card">

      <!-- 恢复码一次性展示（绑定成功后） -->
      <div v-if="recoveryCodes.length" class="recovery-codes">
        <h2 class="login-title">请保存恢复码</h2>
        <p class="totp-hint">以下恢复码仅显示一次，请立即妥善保存。当你无法使用动态验证码时，可用恢复码登录。</p>
        <ul class="recovery-list">
          <li v-for="(c, i) in recoveryCodes" :key="i"><code>{{ c }}</code></li>
        </ul>
        <button class="btn btn-primary" @click="finishRecoverySetup">我已保存恢复码，进入系统</button>
      </div>

      <!-- 第一步：用户名密码 -->
      <div v-else-if="!totpChallenge" class="login-form">
        <div class="form-group">
          <label>用户名</label>
          <input type="text" v-model="form.username" placeholder="请输入用户名" @keyup.enter="doLogin">
        </div>
        <div class="form-group">
          <label>密码</label>
          <input type="password" v-model="form.password" placeholder="请输入密码" @keyup.enter="doLogin">
        </div>
        <div v-if="error" class="form-error">{{ error }}</div>
        <button class="btn btn-primary" :disabled="loading" @click="doLogin">{{ loading ? '登录中...' : '登录' }}</button>
        <div class="register-link">
          没有账号？<a @click.prevent="$router.push('/register')">点此注册</a>
        </div>
      </div>

      <!-- 第二步：TOTP 认证 / 绑定 -->
      <div v-else class="login-form">
        <template v-if="totpChallenge.requireSetup">
          <p class="totp-hint">管理员首次登录需绑定 Microsoft Authenticator。</p>
          <p class="totp-hint">请使用 Microsoft Authenticator 扫描下方二维码完成绑定。</p>
          <div v-if="otpauthUrl" class="qr-box">
            <div ref="qrRef" class="qr-container"></div>
            <p class="qr-fallback">无法扫码？手动输入密钥：<code>{{ totpChallenge.totpSecret }}</code></p>
          </div>
        </template>
        <template v-else>
          <p class="totp-hint">请输入 Microsoft Authenticator 中的 6 位动态验证码。</p>
        </template>

        <div class="form-group">
          <label>{{ useRecovery ? '恢复码' : '动态验证码' }}</label>
          <input v-if="!useRecovery" type="text" v-model="totpCode" maxlength="6" placeholder="6 位数字" @keyup.enter="doTotp">
          <input v-else type="text" v-model="recoveryCode" placeholder="例如 XXXX-XXXX-XXXX-XXXX" @keyup.enter="doTotp">
        </div>

        <div v-if="!totpChallenge.requireSetup" class="recovery-toggle">
          <a href="#" @click.prevent="useRecovery = !useRecovery">{{ useRecovery ? '返回动态码验证' : '使用恢复码登录' }}</a>
        </div>

        <div v-if="error" class="form-error">{{ error }}</div>
        <div class="btn-row">
          <button class="btn btn-secondary" @click="reset">返回上一步</button>
          <button class="btn btn-primary" :disabled="loading" @click="doTotp">{{ loading ? '验证中...' : '验证并登录' }}</button>
        </div>
      </div>
    </div>
  </main>
</template>

<script setup>
import { ref, reactive, onMounted, nextTick, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api'
import { setAuth, homePathFor } from '@/stores/auth'

const router = useRouter()
const qrRef = ref(null)
const form = reactive({ username: '', password: '' })
const totpChallenge = ref(null)
const totpCode = ref('')
const otpauthUrl = ref('')
const error = ref('')
const loading = ref(false)
const useRecovery = ref(false)
const recoveryCode = ref('')
const recoveryCodes = ref([])
const pendingHomePath = ref('')

function reset() {
  totpChallenge.value = null
  totpCode.value = ''
  recoveryCode.value = ''
  useRecovery.value = false
  error.value = ''
}

async function doLogin() {
  error.value = ''
  if (!form.username.trim() || !form.password) { error.value = '请输入用户名和密码'; return }
  loading.value = true
  try {
    const res = await api.login(form.username.trim(), form.password)
    if (res.requireTotp || res.requireSetup) {
      totpChallenge.value = res
      otpauthUrl.value = res.otpauthUrl || ''
      renderQr()
    } else if (res.token) {
      setAuth(res.token, res.user)
      router.push(homePathFor(res.user.role))
    }
  } catch (e) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}

async function doTotp() {
  error.value = ''
  if (useRecovery.value && !recoveryCode.value) { error.value = '请输入恢复码'; return }
  if (!useRecovery.value && !totpCode.value) { error.value = '请输入动态验证码'; return }
  loading.value = true
  try {
    const res = await api.loginTotp(
      totpChallenge.value.challengeId,
      totpCode.value,
      totpChallenge.value.totpSecret,
      useRecovery.value ? recoveryCode.value : undefined
    )
    setAuth(res.token, res.user)
    if (res.recoveryCodes && res.recoveryCodes.length) {
      // 绑定成功：一次性展示恢复码
      recoveryCodes.value = res.recoveryCodes
      pendingHomePath.value = homePathFor(res.user.role)
    } else {
      router.push(homePathFor(res.user.role))
    }
  } catch (e) {
    error.value = e.message || '验证失败'
  } finally {
    loading.value = false
  }
}

function finishRecoverySetup() {
  const target = pendingHomePath.value || '/'
  recoveryCodes.value = []
  pendingHomePath.value = ''
  router.push(target)
}

function renderQr() {
  if (!otpauthUrl.value || !qrRef.value) return
  nextTick(() => {
    const el = qrRef.value
    if (!el) return
    el.innerHTML = ''
    if (window.QRCode) {
      new window.QRCode(el, {
        text: otpauthUrl.value,
        width: 180,
        height: 180,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: window.QRCode.CorrectLevel ? window.QRCode.CorrectLevel.M : 0
      })
    }
  })
}

watch(qrRef, () => renderQr())
</script>

<style scoped>
.login-card { background: #fff; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,.1); padding: 2rem; }
.login-title { text-align: center; margin: 0 0 1.5rem; }
.form-group { margin-bottom: 1rem; display: flex; flex-direction: column; }
.form-group label { margin-bottom: .4rem; font-weight: 600; }
.form-group input { padding: .6rem .8rem; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
.btn { display: inline-block; padding: .6rem 1.2rem; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
.btn-primary { background: #457b9d; color: #fff; width: 100%; }
.btn-secondary { background: #eee; color: #333; }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.btn-row { display: flex; gap: .5rem; }
.btn-row .btn { flex: 1; }
.form-error { color: #e63946; margin-bottom: .8rem; font-size: .9rem; }
.register-link { margin-top: 1rem; text-align: center; font-size: .9rem; }
.register-link a { color: #457b9d; cursor: pointer; }
.totp-hint { font-size: .9rem; color: #555; margin: 0 0 1rem; }
.totp-hint code { background: #f5f5f5; padding: .2rem .4rem; border-radius: 3px; }
.qr-box { background: #fafafa; border: 1px solid #eee; border-radius: 6px; padding: 1rem; text-align: center; margin-bottom: 1rem; }
.qr-container { display: inline-block; padding: 8px; background: #fff; border-radius: 4px; }
.qr-fallback { font-size: .85rem; color: #666; margin: .8rem 0 0; }
.qr-fallback code { background: #f5f5f5; padding: .2rem .4rem; border-radius: 3px; }
.recovery-codes { text-align: left; }
.recovery-list { list-style: none; padding: 0; margin: 0 0 1rem; display: grid; gap: .5rem; }
.recovery-list li { background: #f5f5f5; border: 1px dashed #ccc; border-radius: 4px; padding: .4rem .6rem; }
.recovery-list code { font-size: 1rem; letter-spacing: 1px; }
.recovery-toggle { margin: 0 0 1rem; text-align: right; font-size: .9rem; }
.recovery-toggle a { color: #457b9d; cursor: pointer; }
</style>