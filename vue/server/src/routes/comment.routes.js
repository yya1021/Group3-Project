const express = require('express');
const store = require('../services/store');
const { verifyToken } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 获取全部评论（管理员，用于审核）
router.get('/comments', verifyToken, (req, res) => {
  const comments = store.readComments()
    .map(c => ({ ...c, status: c.status || 'approved' }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ comments });
});

// 获取某内容的评论（仅公开已审核通过的评论；旧数据无 status 视为已通过）
router.get('/comments/:contentType/:contentId', (req, res) => {
  const { contentType, contentId } = req.params;
  const comments = store.readComments().filter(c =>
    c.contentType === contentType &&
    c.contentId === parseInt(contentId) &&
    c.status !== 'pending'
  );
  res.json({ comments });
});

// 发表评论（进入待审核）
router.post('/comments', (req, res) => {
  const { contentType, contentId, author, content } = req.body;
  if (!contentType || !contentId || !content) return res.status(400).json({ success: false, error: '评论内容不能为空' });
  const comments = store.readComments();
  const newComment = {
    id: store.getNextId(comments),
    contentType,
    contentId: parseInt(contentId),
    author: author || '匿名',
    content: content.trim(),
    ip: getClientIp(req),
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  comments.push(newComment);
  store.writeComments(comments);
  res.status(201).json({ success: true, data: newComment, message: '评论已提交，待审核后展示' });
});

// 审核通过评论（管理员）
router.post('/comments/:id/approve', verifyToken, (req, res) => {
  const comments = store.readComments();
  const comment = comments.find(c => c.id === parseInt(req.params.id));
  if (!comment) return res.status(404).json({ success: false, error: '评论不存在' });
  comment.status = 'approved';
  store.writeComments(comments);
  res.json({ success: true, message: '评论已通过审核' });
});

// 拒绝评论（管理员，删除该评论）
router.post('/comments/:id/reject', verifyToken, (req, res) => {
  const comments = store.readComments();
  const idx = comments.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ success: false, error: '评论不存在' });
  comments.splice(idx, 1);
  store.writeComments(comments);
  res.json({ success: true, message: '评论已拒绝' });
});

// 删除评论（管理员）
router.delete('/comments/:id', verifyToken, (req, res) => {
  const comments = store.readComments();
  const idx = comments.findIndex(c => c.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ success: false, error: '评论不存在' });
  comments.splice(idx, 1);
  store.writeComments(comments);
  res.json({ success: true, message: '评论已删除' });
});

module.exports = router;
