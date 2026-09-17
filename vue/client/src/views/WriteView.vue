<template>
  <main style="flex: 1; max-width: 800px; width: 100%; margin: 2rem auto; padding: 0 1rem;">
    <h1 class="page-title">发布文章</h1>
    <div v-if="feedback.msg" class="feedback" :class="feedback.type">{{ feedback.msg }}</div>
    <div class="form-container">
      <form @submit.prevent="publishPost">
        <div class="form-group"><label>文章标题 *</label><input type="text" v-model="form.title" required placeholder="请输入文章标题"></div>
        <div class="form-group"><label>作者</label><input type="text" v-model="form.author" placeholder="请输入作者名称"></div>
        <div class="form-group">
          <label>分类</label>
          <select v-model="form.category">
            <option value="">选择分类</option>
            <option value="技术">技术</option>
            <option value="自然科学">自然科学</option>
            <option value="哲学">哲学</option>
            <option value="科社">科社</option>
            <option value="政经">政经</option>
          </select>
        </div>
        <div class="form-group">
          <label>标签</label>
          <div class="tags-input-container" @click.self="focusTagsInput">
            <span v-for="(tag, index) in tags" :key="tag" class="tag-item">
              {{ tag }}<span class="remove-tag" @click="removeTag(index)">×</span>
            </span>
            <input ref="tagsInputEl" type="text" v-model="tagDraft" class="tags-input" placeholder="输入标签后按回车添加"
              @keydown="onTagKeydown">
          </div>
        </div>
        <div class="form-group">
          <label>文章内容 *</label>
          <div class="html-toolbar">
            <button v-for="btn in toolbar" :key="btn.tag" type="button" @click="insertTag(btn.tag)">{{ btn.label }}</button>
          </div>
          <textarea ref="contentEl" v-model="form.content" required placeholder="请输入文章内容"></textarea>
        </div>
        <button type="submit" class="btn-submit" :disabled="publishing">{{ publishing ? '发布中...' : '发布文章' }}</button>
      </form>
    </div>
  </main>
</template>

<script setup>
import { ref, reactive, nextTick } from 'vue'
import { api } from '@/api'
import '@/styles/write.css'

const form = reactive({ title: '', author: '', category: '', content: '' })
const tags = ref([])
const tagDraft = ref('')
const publishing = ref(false)
const feedback = ref({ msg: '', type: '' })

const tagsInputEl = ref(null)
const contentEl = ref(null)

const toolbar = [
  { tag: 'h1', label: '大标题' }, { tag: 'h2', label: '中标题' }, { tag: 'h3', label: '小标题' },
  { tag: 'p', label: '段落' }, { tag: 'strong', label: '粗体' }, { tag: 'em', label: '斜体' },
  { tag: 'blockquote', label: '引用' }, { tag: 'ul', label: '无序列表' }, { tag: 'ol', label: '有序列表' },
  { tag: 'a', label: '链接' }, { tag: 'br', label: '换行' }, { tag: 'hr', label: '分隔线' }
]

function showFeedback(msg, type) {
  feedback.value = { msg, type }
  setTimeout(() => { feedback.value = { msg: '', type: '' } }, 4000)
}

// ============ 标签 ============
function removeTag(index) {
  tags.value.splice(index, 1)
}

function focusTagsInput() {
  tagsInputEl.value?.focus()
}

function onTagKeydown(e) {
  if (e.key === 'Enter' || e.key === ',') {
    e.preventDefault()
    const tag = tagDraft.value.trim()
    if (tag && !tags.value.includes(tag)) tags.value.push(tag)
    tagDraft.value = ''
  } else if (e.key === 'Backspace' && tagDraft.value === '' && tags.value.length > 0) {
    tags.value.pop()
  }
}

// ============ HTML 工具栏 ============
function insertTag(tag) {
  const el = contentEl.value
  if (!el) return
  const start = el.selectionStart
  const end = el.selectionEnd
  const selected = form.content.substring(start, end)
  const defaults = {
    h1: '大标题', h2: '中标题', h3: '小标题', p: '段落内容',
    strong: '粗体文字', em: '斜体文字', blockquote: '引用内容'
  }
  let html = ''
  switch (tag) {
    case 'h1': html = `<h1>${selected || defaults.h1}</h1>`; break
    case 'h2': html = `<h2>${selected || defaults.h2}</h2>`; break
    case 'h3': html = `<h3>${selected || defaults.h3}</h3>`; break
    case 'p': html = `<p>${selected || defaults.p}</p>`; break
    case 'strong': html = `<strong>${selected || defaults.strong}</strong>`; break
    case 'em': html = `<em>${selected || defaults.em}</em>`; break
    case 'blockquote': html = `<blockquote>${selected || defaults.blockquote}</blockquote>`; break
    case 'ul': html = `<ul>\n  <li>${selected || '列表项'}</li>\n</ul>`; break
    case 'ol': html = `<ol>\n  <li>${selected || '列表项'}</li>\n</ol>`; break
    case 'a': html = `<a href="https://">${selected || '链接文字'}</a>`; break
    case 'br': html = '<br>'; break
    case 'hr': html = '<hr>'; break
  }
  form.content = form.content.substring(0, start) + html + form.content.substring(end)
  nextTick(() => {
    el.focus()
    el.selectionStart = start + html.length
    el.selectionEnd = start + html.length
  })
}

// ============ 发布 ============
async function publishPost() {
  const title = form.title.trim()
  const content = form.content.trim()
  if (!title || !content) { showFeedback('⚠️ 请填写标题和内容', 'error'); return }
  publishing.value = true
  try {
    const result = await api.submitPost({
      title,
      author: form.author.trim() || '匿名',
      category: form.category || '未分类',
      content,
      tags: tags.value
    })
    if (result.success) {
      showFeedback('✅ 文章已提交审核', 'success')
      form.title = ''; form.author = ''; form.category = ''; form.content = ''
      tags.value = []
    } else {
      showFeedback('⚠️ ' + (result.error || '发布失败'), 'error')
    }
  } catch (e) {
    showFeedback('⚠️ ' + (e.message || '网络错误'), 'error')
  } finally {
    publishing.value = false
  }
}
</script>
