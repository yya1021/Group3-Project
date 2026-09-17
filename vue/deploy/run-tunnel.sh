#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  座椅联合图书馆 - 启动 Cloudflare 隧道（手机端）
#
#  前提:
#    1. 已运行 bash deploy/phone-setup.sh
#    2. 已把电脑上生成的 <UUID>.json 凭据文件放到 ~/.cloudflared/
#
#  用法:
#    bash deploy/run-tunnel.sh
#
#  本脚本会自动:
#    - 找到 ~/.cloudflared 下的凭据文件（.json）并读出隧道 UUID
#    - 生成 config.yml（两个域名 → nginx 8080）
#    - 启动隧道（前台运行，Ctrl+C 停止）
#
#  如需修改域名，编辑本脚本中的 DOMAINS 列表即可。
# ============================================================
set -e

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
CF_DIR="$HOME/.cloudflared"
CONF="$CF_DIR/config.yml"

# 要绑定的域名列表（可自行增删）
DOMAINS="goodwood-ci.asia www.goodwood-ci.asia"

echo "▶ 检测凭据文件 ..."
CRED=$(ls "$CF_DIR"/*.json 2>/dev/null | head -n 1)
if [ -z "$CRED" ]; then
  echo "✗ 未找到凭据文件。请先把电脑上的 <UUID>.json 放到 $CF_DIR/ 后重试。"
  exit 1
fi

TUNNEL_UUID=$(basename "$CRED" .json)
echo "  发现隧道 UUID: $TUNNEL_UUID"

echo "▶ 生成 config.yml ..."
{
  echo "tunnel: $TUNNEL_UUID"
  echo "credentials-file: $CF_DIR/$TUNNEL_UUID.json"
  echo ""
  echo "ingress:"
  for d in $DOMAINS; do
    echo "  - hostname: $d"
    echo "    service: http://127.0.0.1:8080"
  done
  echo "  - service: http_status:404"
} > "$CONF"

echo "▶ 启动隧道（Ctrl+C 停止）..."
exec cloudflared tunnel run "$TUNNEL_UUID"
