#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  快速公网隧道（Cloudflare Tunnel 临时地址）
#  无需账号、无需域名，立刻得到一个 https://xxxx.trycloudflare.com
#
#  用法: bash deploy/start-tunnel.sh [端口]
#    默认 8080（即 nginx 反向代理）；若未启用 nginx，请传 3000 直连后端：
#      bash deploy/start-tunnel.sh 3000
# ============================================================
set -e
PORT="${1:-8080}"

echo "▶ 安装 cloudflared ..."
pkg install -y cloudflared

echo "▶ 启动隧道，映射本地 ${PORT} 端口 ..."
if [ "$PORT" = "8080" ]; then
  echo "   （默认走 nginx 反向代理；请确保已运行: bash deploy/nginx/setup-nginx.sh）"
fi
echo "   （看到 https://xxxx.trycloudflare.com 即成功，Ctrl+C 可停止）"
cloudflared tunnel --url "http://127.0.0.1:${PORT}"
