// 数字信封解密中间件
//
// 位置：必须挂在 express.json() 之后、业务路由之前。解析出的 req.body 若为数字信封，
// 则完成「时间窗 + 重放校验 + SM2 解封 + SM4-GCM 解密」，并还原成明文对象放回 req.body。
// 非信封请求原样放行（兼容既有明文测试与 GET 请求）。
const envelope = require('../services/envelope');
const replay = require('../services/replay');

function envelopeMiddleware(req, res, next) {
  // 仅处理带 JSON 信封体的请求
  if (!envelope.isEnvelope(req.body)) return next();

  const { ts, nonce } = req.body;

  // 1) 时间窗 + 重放校验（先检查，避免无效请求污染重放缓存）
  try {
    replay.guard(nonce, ts);
  } catch (e) {
    const status = e.code === 'REPLAY' ? 409 : 400;
    return res.status(status).json({ success: false, error: e.message, code: e.code });
  }

  // 2) 解封 + 解密 + 完整性校验
  let plaintext;
  try {
    plaintext = envelope.openEnvelope(req.body, { method: req.method, path: req.originalUrl });
  } catch (e) {
    return res.status(400).json({ success: false, error: e.message, code: e.code });
  }

  // 3) 解密成功后才记录 nonce，防止并发/失败请求占用缓存
  try {
    replay.remember(nonce);
  } catch (e) {
    return res.status(500).json({ success: false, error: '重放缓存写入失败', code: 'INTERNAL' });
  }

  req.body = plaintext;
  next();
}

module.exports = { envelopeMiddleware };
