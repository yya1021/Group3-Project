<template>
  <header class="top-header">
    <nav class="navbar">
      <div class="nav-container">
        <router-link to="/" class="nav-logo"><span class="logo-text">优选商城</span></router-link>
        <ul class="nav-menu" :class="{ active: menuOpen }">
          <li class="nav-item"><router-link to="/" class="nav-link" exact-active-class="active" @click="menuOpen = false">首页</router-link></li>
          <li class="nav-item"><router-link to="/shop" class="nav-link" exact-active-class="active" @click="menuOpen = false">全部商品</router-link></li>
          <li class="nav-item"><router-link to="/cart" class="nav-link" exact-active-class="active" @click="menuOpen = false">购物车</router-link></li>

          <!-- 所有用户类型统一显示的入口，无权限访问时由路由守卫返回 403 -->
          <li class="nav-item"><router-link to="/admin" class="nav-link" exact-active-class="active" @click="menuOpen = false">后台管理</router-link></li>
          <li class="nav-item"><router-link to="/merchant" class="nav-link" exact-active-class="active" @click="menuOpen = false">商户后台</router-link></li>
          <li class="nav-item"><router-link to="/audit" class="nav-link" exact-active-class="active" @click="menuOpen = false">审计日志</router-link></li>
        </ul>

        <div class="nav-auth">
          <template v-if="isLoggedIn">
            <span class="user-badge">{{ username }}（{{ roleLabel }}）</span>
            <button class="btn-logout" @click="doLogout">退出</button>
          </template>
          <template v-else>
            <router-link to="/login" class="nav-link nav-login">登录</router-link>
            <router-link to="/register" class="nav-link nav-login">注册</router-link>
          </template>
        </div>

        <button class="nav-toggle" :class="{ active: menuOpen }" @click="menuOpen = !menuOpen" aria-label="切换导航菜单">
          <span></span><span></span><span></span>
        </button>
      </div>
    </nav>
  </header>

  <router-view />
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api'
import { isLoggedIn, role, username, roleName, clearAuth, authExpired } from '@/stores/auth'

const menuOpen = ref(false)
const router = useRouter()

const roleLabel = computed(() => roleName(role.value))

async function doLogout() {
  try { await api.logout() } catch (e) {}
  clearAuth()
  router.push('/login')
}

// 路由切换后自动关闭移动端菜单
router.afterEach(() => { menuOpen.value = false })

// 登录过期：任何接口返回 401 时，跳转登录页
watch(authExpired, () => {
  if (router.currentRoute.value.name !== 'login') {
    router.push({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
  }
})
</script>