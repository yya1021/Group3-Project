// 获取客户端真实 IP（兼容 Cloudflare 隧道 / nginx / 直连）
function getClientIp(req) {
  // Cloudflare Tunnel 会注入真实客户端 IP
  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String(cf).split(',')[0].trim();
  // 反向代理（nginx / ngrok）注入的 X-Forwarded-For，最左侧为真实客户端
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  // 直连时回退到 socket 地址（去掉 IPv4 映射前缀）
  const remote = req.socket && req.socket.remoteAddress;
  if (remote) return remote.replace(/^::ffff:/, '');
  return req.ip || '';
}

module.exports = { getClientIp };
