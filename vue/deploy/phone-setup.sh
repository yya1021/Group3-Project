#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  座椅联合图书馆 - 手机端一键部署（Termux）
#
#  用法（在 Termux 中）:
#    cd ~/vue
#    bash deploy/phone-setup.sh
#
#  依次完成:
#    1. 基础部署（装 Node、装依赖、构建前端、启动后端 3000）
#    2. 启用 nginx 反向代理（8080 → 3000）
#    3. 安装 cloudflared 并创建配置目录
# ============================================================
set -e

# 切到项目根目录（脚本位于 deploy/ 下）
cd "$(dirname "$0")/.."

echo ""
echo "== 1/3 基础部署（后端 3000）=="
bash deploy/termux-setup.sh

echo ""
echo "== 2/3 启用 nginx 反向代理（8080 → 3000）=="
bash deploy/nginx/setup-nginx.sh

echo ""
echo "== 3/3 安装 cloudflared =="
pkg install -y cloudflared
mkdir -p "$HOME/.cloudflared"

echo ""
echo "=============================================="
echo " ✅ 手机端部署完成！"
echo "    后端:  http://127.0.0.1:3000"
echo "    nginx: http://127.0.0.1:8080"
echo "=============================================="
echo ""
echo " 接下来只剩两步："
echo "   1) 把电脑上的 <UUID>.json 凭据文件放到 ~/.cloudflared/"
echo "   2) 运行: bash deploy/run-tunnel.sh"
echo ""
