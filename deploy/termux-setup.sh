#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  座椅联合图书馆 - Termux 一键部署脚本（生产模式）
#
#  用法：把整个 vue/ 文件夹传到旧手机上，然后在 Termux 中：
#    cd ~/vue
#    bash deploy/termux-setup.sh
#
#  完成后本机访问 http://localhost:3000
#  如需公网域名访问，再运行 bash deploy/start-tunnel.sh
# ============================================================
set -e

# 切到项目根目录（脚本位于 deploy/ 下）
cd "$(dirname "$0")/.."

echo "▶ 1/5 更新 Termux 软件源并安装 Node.js ..."
pkg update -y
pkg install -y nodejs-lts

echo "▶ 2/5 安装项目依赖 ..."
npm install

echo "▶ 3/5 构建前端（Vue → client/dist）..."
npm run build -w client

echo "▶ 4/5 防止手机休眠（保持服务运行）..."
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock || true

echo "▶ 5/5 启动后端（生产模式，端口 ${PORT:-3000}）..."
export PORT="${PORT:-3000}"
# 停掉可能残留的服务进程
pkill -f "node src/server.js" 2>/dev/null || true
nohup npm start > server.log 2>&1 &
sleep 3

echo ""
echo "=============================================="
echo " ✅ 部署完成！"
echo "    本机访问: http://localhost:${PORT}"
echo "    日志文件: server.log  （cat server.log 查看）"
echo "=============================================="
echo ""
echo " 下一步（可选）：启用 nginx 反向代理（监听 8080 → 3000）"
echo "   bash deploy/nginx/setup-nginx.sh"
echo ""
echo " 下一步：让域名/公网无端口访问"
echo "   临时公网地址（免账号）: bash deploy/start-tunnel.sh"
echo "   自己的域名:             见 README 部署章节（Cloudflare Tunnel）"
echo ""
