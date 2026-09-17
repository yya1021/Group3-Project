<template>
  <main class="error-page" style="flex: 1; padding: 2rem;">
    <div class="error-container">
      <div class="error-code">404</div>
      <div class="error-title">页面未找到</div>
      <p class="error-message">你访问的页面不存在或已被移动</p>
      <router-link to="/" class="btn-home">返回首页</router-link>
    </div>
  </main>
</template>

<script setup>
import '@/styles/404.css'
</script>
