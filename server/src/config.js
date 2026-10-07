const path = require('path');

const ROOT = path.join(__dirname, '..');

module.exports = {
  PORT: process.env.PORT || 3000,
  // 数据目录：默认 server/data，可通过环境变量覆盖（测试时指向临时目录）
  DATA_DIR: process.env.DATA_DIR || path.join(ROOT, 'data'),
  UPLOADS_DIR: process.env.UPLOADS_DIR || path.join(ROOT, 'uploads'),
  // 生产环境下可托管前端构建产物
  CLIENT_DIST: process.env.CLIENT_DIST || path.join(ROOT, '..', 'client', 'dist'),
  MAX_FILE_SIZE: 50 * 1024 * 1024, // 50MB
  TOKEN_TTL: 24 * 60 * 60 * 1000 // 24小时
};
