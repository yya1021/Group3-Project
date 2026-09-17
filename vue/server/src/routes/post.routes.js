const express = require('express');
const store = require('../services/store');
const { verifyToken } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 获取所有已发布文章
router.get('/posts', (req, res) => res.json({ posts: store.readPosts() }));

// 获取单篇文章
router.get('/posts/:id', (req, res) => {
  const post = store.readPosts().find(p => p.id === parseInt(req.params.id));
  if (post) res.json({ post });
  else res.status(404).json({ error: '文章未找到' });
});

// 提交新文章（进入待审核队列）
router.post('/posts', (req, res) => {
  const { title, content, author, category, tags } = req.body;
  if (!title || !content) return res.status(400).json({ success: false, error: '标题和内容不能为空' });
  const pending = store.readPendingPosts();
  pending.push({
    id: Date.now(),
    title: title.trim(),
    content: content.trim(),
    author: author || '匿名',
    category: category || '未分类',
    tags: Array.isArray(tags) ? tags : [],
    ip: getClientIp(req),
    status: 'pending',
    submittedAt: new Date().toISOString()
  });
  store.writePendingPosts(pending);
  res.status(201).json({ success: true, message: '文章已提交审核' });
});

// 待审核列表（管理员）
router.get('/pending', verifyToken, (req, res) => res.json({ posts: store.readPendingPosts() }));

// 审核通过
router.post('/approve/:id', verifyToken, (req, res) => {
  const pendingId = parseInt(req.params.id);
  const pending = store.readPendingPosts();
  const idx = pending.findIndex(p => p.id === pendingId);
  if (idx === -1) return res.status(404).json({ success: false, error: '文章不存在' });
  const item = pending[idx];
  const posts = store.readPosts();
  posts.push({
    id: store.getNextId(posts),
    title: item.title,
    content: item.content,
    author: item.author,
    category: item.category,
    tags: item.tags,
    ip: item.ip || '',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  });
  pending.splice(idx, 1);
  store.writePosts(posts);
  store.writePendingPosts(pending);
  res.json({ success: true, message: '审核通过' });
});

// 审核拒绝
router.post('/reject/:id', verifyToken, (req, res) => {
  const pending = store.readPendingPosts();
  const idx = pending.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ success: false, error: '文章不存在' });
  pending.splice(idx, 1);
  store.writePendingPosts(pending);
  res.json({ success: true, message: '已拒绝' });
});

// 更新文章（type 区分 pending / 已发布）
router.put('/update/:id', verifyToken, (req, res) => {
  const id = parseInt(req.params.id);
  const { title, author, category, content, tags, type } = req.body;
  if (type === 'pending') {
    const pending = store.readPendingPosts();
    const idx = pending.findIndex(p => p.id === id);
    if (idx === -1) return res.status(404).json({ success: false, error: '文章不存在' });
    pending[idx] = { ...pending[idx], title, author, category, content, tags };
    store.writePendingPosts(pending);
  } else {
    const posts = store.readPosts();
    const idx = posts.findIndex(p => p.id === id);
    if (idx === -1) return res.status(404).json({ success: false, error: '文章不存在' });
    posts[idx] = { ...posts[idx], title, author, category, content, tags, updatedAt: new Date().toISOString() };
    store.writePosts(posts);
  }
  res.json({ success: true, message: '更新成功' });
});

// 删除文章
router.delete('/posts/:id', verifyToken, (req, res) => {
  const posts = store.readPosts();
  const idx = posts.findIndex(p => p.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ success: false, error: '文章不存在' });
  posts.splice(idx, 1);
  store.writePosts(posts);
  res.json({ success: true, message: '删除成功' });
});

module.exports = router;
