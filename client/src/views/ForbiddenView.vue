<template>
  <main class="error-page" style="flex: 1; padding: 2rem;">
    <div class="error-container error-container--wide">
      <div class="error-code">403</div>
      <div class="error-title">无权限访问</div>
      <p class="error-message">你没有权限访问该页面</p>
      <router-link to="/" class="btn-home">返回首页</router-link>
    </div>
  </main>
</template>

<script setup>
import '@/styles/404.css'
</script>

<style scoped>
/* 仅对 403 页面生效：将矩形横向加长（原 404.css 中为 max-width: 500px） */
.error-container--wide {
  width: 100%;
  max-width: 900px;
}
</style>
