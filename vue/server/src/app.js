const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const config = require('./config');
const store = require('./services/store');

const authRoutes = require('./routes/auth.routes');
const postRoutes = require('./routes/post.routes');
const fileRoutes = require('./routes/file.routes');
const commentRoutes = require('./routes/comment.routes');
const productRoutes = require('./routes/product.routes');
const orderRoutes = require('./routes/order.routes');
const userRoutes = require('./routes/user.routes');
const roleRoutes = require('./routes/role.routes');
const auditRoutes = require('./routes/audit.routes');

function createApp() {
  const app = express();

  // 确保数据与上传目录结构就绪
  store.ensureStructure();

  // 中间件
  app.use(cors());
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // 上传目录静态托管
  app.use('/uploads', express.static(store.UPLOADS_DIR || store.getUploadsDir()));

  // API 路由
  app.use('/api', authRoutes);
  app.use('/api', postRoutes);
  app.use('/api', fileRoutes);
  app.use('/api', commentRoutes);
  app.use('/api', productRoutes);
  app.use('/api', orderRoutes);
  app.use('/api', userRoutes);
  app.use('/api', roleRoutes);
  app.use('/api', auditRoutes);

  // API 专属 404（优先于 SPA 兜底）
  app.use('/api', (req, res) => res.status(404).json({ success: false, error: '接口不存在' }));

  // 生产环境：托管前端构建产物
  if (fs.existsSync(config.CLIENT_DIST)) {
    app.use(express.static(config.CLIENT_DIST));
    app.get('*', (req, res) => res.sendFile(path.join(config.CLIENT_DIST, 'index.html')));
  }

  // 404
  app.use((req, res) => res.status(404).json({ success: false, error: '接口不存在' }));

  return app;
}

module.exports = { createApp };
