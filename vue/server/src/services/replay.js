// 时间窗 + 重放校验（防重放）
//
// 说明：本实现采用单进程内存缓存。单机部署下足够；多实例部署需替换为共享存储
// （如 Redis），否则同一请求命中不同实例时无法识别重放。进程重启后缓存清空，
// 但时间窗内已被消费的 nonce 因时间戳过期而自然失效，风险可控。
const WINDOW_MS = 5 * 60 * 1000; // 时间窗：±5 分钟
const CLEANUP_INTERVAL = 1000; // 每次写入后做一次惰性清理

// nonce -> 过期时间戳
const seen = new Map();

// 校验时间窗与重放，不通过则抛出带 code 的错误（由中间件转成 HTTP 响应）
function guard(nonce, ts) {
  const now = Date.now();

  if (typeof ts !== 'number' || !Number.isFinite(ts)) {
    const err = new Error('缺少或非法时间戳');
    err.code = 'BAD_TIMESTAMP';
    throw err;
  }
  if (Math.abs(now - ts) > WINDOW_MS) {
    const err = new Error('请求时间窗已过期或提前于服务器时间');
    err.code = 'EXPIRED';
    throw err;
  }
  if (typeof nonce !== 'string' || nonce.length < 16) {
    const err = new Error('nonce 非法');
    err.code = 'BAD_NONCE';
    throw err;
  }
  if (seen.has(nonce)) {
    const err = new Error('检测到重放请求');
    err.code = 'REPLAY';
    throw err;
  }
}

// 记录已消费的 nonce（应在解密与校验成功之后调用）
function remember(nonce) {
  seen.set(nonce, Date.now() + WINDOW_MS);
  if (seen.size % CLEANUP_INTERVAL === 0) cleanup();
}

function cleanup() {
  const now = Date.now();
  for (const [nonce, expiresAt] of seen) {
    if (expiresAt < now) seen.delete(nonce);
  }
}

// 便于测试
function reset() {
  seen.clear();
}

module.exports = { WINDOW_MS, guard, remember, reset };
