<template>
  <main style="flex: 1; max-width: 800px; width: 100%; margin: 2rem auto; padding: 0 1rem;">
    <div class="content-container">
      <p v-if="loading">加载中...</p>
      <p v-else-if="error">{{ error }}</p>

      <template v-else-if="item">
        <!-- 文章 -->
        <template v-if="contentType === 'article'">
          <h1 class="content-title">{{ item.title }}</h1>
          <div class="content-meta">
            作者: {{ item.author || '匿名' }} | 分类: {{ item.category || '未分类' }} | 发布时间: {{ formatDateTime(item.createdAt) }}
          </div>
          <div class="content-body" v-html="item.content"></div>
          <div v-if="item.tags && item.tags.length" class="content-tags">
            <span v-for="tag in item.tags" :key="tag" class="content-tag">{{ tag }}</span>
          </div>
          <div v-if="item.ip" class="ip-note">IP: {{ item.ip }}</div>
        </template>

        <!-- 文件 -->
        <template v-else>
          <h1 class="content-title">{{ item.title }}</h1>
          <div class="content-meta">
            作者: {{ item.author || '匿名' }} | 分类: {{ item.category || '其他' }} | 上传时间: {{ formatDateTime(item.createdAt) }}
          </div>
          <div v-if="item.description" class="content-body">{{ item.description }}</div>
          <a :href="`/api/files/${item.id}/download`" class="btn-download">⬇ 下载文件</a>
          <div v-if="item.ip" class="ip-note">IP: {{ item.ip }}</div>
        </template>
      </template>
    </div>

    <div class="comments-container">
      <h2 class="comments-title">评论</h2>
      <div class="comment-form">
        <div class="form-group"><label>昵称</label><input type="text" v-model="commentAuthor" placeholder="你的昵称（可选）"></div>
        <div class="form-group"><label>评论内容</label><textarea v-model="commentContent" rows="3" placeholder="写下你的评论..."></textarea></div>
        <button class="btn-comment" @click="submitComment">发表评论</button>
      </div>
      <div class="comment-list">
        <p v-if="comments.length === 0" class="empty-comments">暂无评论，来抢沙发！</p>
        <div v-for="c in comments" :key="c.id" class="comment-item">
          <div class="comment-author">{{ c.author || '匿名' }}</div>
          <div class="comment-date">{{ formatDateTime(c.createdAt) }}</div>
          <div class="comment-content">{{ c.content }}</div>
          <div v-if="c.ip" class="comment-ip">IP: {{ c.ip }}</div>
        </div>
      </div>
    </div>

    <a @click="$router.back()" class="back-link" style="cursor:pointer;">← 返回</a>
  </main>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/api'
import '@/styles/post.css'

const props = defineProps({
  contentType: { type: String, default: 'article' }
})

const route = useRoute()
const item = ref(null)
const loading = ref(true)
const error = ref('')
const comments = ref([])
const commentAuthor = ref('')
const commentContent = ref('')

const contentId = computed(() => parseInt(route.params.id))

async function load() {
  loading.value = true
  error.value = ''
  try {
    if (props.contentType === 'article') {
      const data = await api.getPost(contentId.value)
      if (!data.post) { error.value = '文章未找到'; item.value = null; return }
      item.value = data.post
      document.title = data.post.title + ' - 优选商城'
    } else {
      const data = await api.getFile(contentId.value)
      if (!data.file) { error.value = '文件未找到'; item.value = null; return }
      item.value = data.file
      document.title = data.file.title + ' - 优选商城'
    }
    await loadComments()
  } catch (e) {
    error.value = '加载失败: ' + e.message
    item.value = null
  } finally {
    loading.value = false
  }
}

async function loadComments() {
  try {
    const data = await api.getComments(props.contentType, contentId.value)
    comments.value = data.comments || []
  } catch (e) {
    comments.value = []
  }
}

async function submitComment() {
  const content = commentContent.value.trim()
  if (!content) { alert('请输入评论内容'); return }
  try {
    const result = await api.addComment({
      contentType: props.contentType,
      contentId: contentId.value,
      author: commentAuthor.value.trim() || '匿名',
      content
    })
    if (result.success) {
      commentContent.value = ''
      await loadComments()
    } else {
      alert(result.error || '评论失败')
    }
  } catch (e) {
    alert('评论失败: ' + e.message)
  }
}

function formatDateTime(str) {
  try { return new Date(str).toLocaleString('zh-CN') } catch (e) { return '' }
}

watch(() => [route.params.id, props.contentType], load)

onMounted(load)
</script>
