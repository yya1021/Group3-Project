const express = require('express');
const path = require('path');
const fs = require('fs');
const store = require('../services/store');
const config = require('../config');
const { verifyToken } = require('../middleware/auth');
const { getClientIp } = require('../utils/get-client-ip');

const router = express.Router();

// 上传文件（Base64 传输）
router.post('/files', verifyToken, (req, res) => {
  const { title, author, category, description, fileName, fileData, fileType } = req.body;
  if (!title || !fileName || !fileData) return res.status(400).json({ success: false, error: '标题和文件不能为空' });
  let fileBuffer;
  try { fileBuffer = Buffer.from(fileData, 'base64'); } catch (e) { return res.status(400).json({ success: false, error: '文件数据格式错误' }); }
  if (fileBuffer.length > config.MAX_FILE_SIZE) return res.status(400).json({ success: false, error: '文件大小不能超过50MB' });
  const uniqueFileName = Date.now() + '-' + Math.round(Math.random() * 1E9) + '-' + fileName;
  const filePath = path.join(store.getUploadsDir(), uniqueFileName);
  try { fs.writeFileSync(filePath, fileBuffer); } catch (e) { return res.status(500).json({ success: false, error: '保存文件失败' }); }
  const files = store.readFiles();
  const newFile = {
    id: store.getNextId(files),
    title: title.trim(),
    author: author || '匿名',
    category: category || '其他',
    description: description || '',
    fileName: uniqueFileName,
    originalName: fileName,
    fileType: fileType || 'application/octet-stream',
    fileSize: fileBuffer.length,
    uploadedBy: req.admin.username,
    ip: getClientIp(req),
    createdAt: new Date().toISOString()
  };
  files.push(newFile);
  store.writeFiles(files);
  res.status(201).json({ success: true, data: newFile, message: '文件上传成功' });
});

// 文件列表
router.get('/files', (req, res) => res.json({ files: store.readFiles() }));

// 文件详情
router.get('/files/:id', (req, res) => {
  const file = store.readFiles().find(f => f.id === parseInt(req.params.id));
  if (file) res.json({ file });
  else res.status(404).json({ error: '文件未找到' });
});

// 下载文件
router.get('/files/:id/download', (req, res) => {
  const file = store.readFiles().find(f => f.id === parseInt(req.params.id));
  if (!file) return res.status(404).json({ error: '文件未找到' });
  const filePath = path.join(store.getUploadsDir(), file.fileName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: '文件已丢失' });
  res.download(filePath, file.originalName);
});

// 删除文件
router.delete('/files/:id', verifyToken, (req, res) => {
  const files = store.readFiles();
  const idx = files.findIndex(f => f.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ success: false, error: '文件不存在' });
  const filePath = path.join(store.getUploadsDir(), files[idx].fileName);
  try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch (e) {}
  files.splice(idx, 1);
  store.writeFiles(files);
  res.json({ success: true, message: '文件删除成功' });
});

module.exports = router;
