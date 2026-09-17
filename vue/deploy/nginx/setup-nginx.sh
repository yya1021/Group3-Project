#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  座椅联合图书馆 - 安装并启动 nginx 反向代理（Termux）
#
#  用法（在 Termux 中）:
#    cd ~/vue
#    bash deploy/nginx/setup-nginx.sh
#
#  作用：安装 nginx，写入反向代理配置（监听 8080 → 127.0.0.1:3000），
#        并启动 nginx。之后 Cloudflare Tunnel 只需指向 8080。
# ============================================================
set -e

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
NGINX_CONF="$PREFIX/etc/nginx/nginx.conf"
SRC_CONF="$(cd "$(dirname "$0")" && pwd)/library.conf"

echo "▶ 1/4 安装 nginx ..."
pkg install -y nginx

echo "▶ 2/4 写入反向代理配置 ..."
mkdir -p "$PREFIX/etc/nginx"
# 首次覆盖前备份一次原配置
if [ -f "$NGINX_CONF" ] && ! grep -q "座椅联合图书馆" "$NGINX_CONF" 2>/dev/null; then
  cp "$NGINX_CONF" "$NGINX_CONF.bak" 2>/dev/null || true
fi
cp "$SRC_CONF" "$NGINX_CONF"

echo "▶ 3/4 创建日志目录 ..."
mkdir -p "$PREFIX/var/log/nginx"

echo "▶ 4/4 启动 nginx（监听 8080）..."
# 停止可能残留的 nginx 进程
pkill nginx 2>/dev/null || true
sleep 1
nginx

echo ""
echo "=============================================="
echo " ✅ nginx 反向代理已启动"
echo "    监听:  http://127.0.0.1:8080"
echo "    转发:  → http://127.0.0.1:3000 (Node)"
echo "    验证:  curl http://127.0.0.1:8080"
echo "=============================================="
echo ""
echo " 下一步：让公网域名（不带端口）访问"
echo "    bash deploy/start-tunnel.sh    # 隧道指向 8080"
echo ""
