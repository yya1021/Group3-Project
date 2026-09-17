# AutoX.js 一键自动部署

在手机上用 [AutoX.js](https://github.com/kkevsekk1/AutoX) 一键自动完成部署。

## 一次性准备

1. 手机安装：
   - **Termux**（F-Droid 安装，要求 Android 7+）
   - **AutoX.js**（GitHub Releases 或 F-Droid）
2. 把项目文件夹 `vue/` 放到手机 `/sdcard/Download/vue`
   （USB / 微信 / 网盘传输均可）
3. 给 AutoX.js 授予 **悬浮窗、无障碍、存储** 权限
4. 无 root 时：先在 Termux 里手动执行一次
   ```bash
   termux-setup-storage
   ```
   并允许存储访问（只此一次）。

## 运行

1. 用 AutoX.js 打开 `vue/deploy/autox/deploy.js`
2. 点 ▶ 运行

- **已 root 的手机**：全自动完成（装 Node → 复制项目 → 构建 → 启动）
- **无 root 的手机**：自动打开 Termux，逐条输入命令（期间别锁屏）

## 脚本做什么

| 步骤 | 操作 |
|------|------|
| 1 | 把 `/sdcard/Download/vue` 复制到 Termux 主目录 `~/vue` |
| 2 | `pkg install -y nodejs-lts`（装 Node） |
| 3 | `npm install` + `npm run build -w client`（构建前端） |
| 4 | `termux-wake-lock` + 后台启动服务器（端口 3000） |

## 部署完成后

- 本机/局域网：手机浏览器打开 `http://localhost:3000`
- 公网域名（无端口）：
  ```bash
  # 在 Termux 中
  cd ~/vue
  bash deploy/start-tunnel.sh            # 临时公网地址（免账号）
  # 或配置自己的域名（Cloudflare Tunnel），见项目 README「部署章节」
  ```

## 常见问题

- **提示找不到项目**：确认 `vue/` 文件夹确实在 `/sdcard/Download/vue`（里面有 package.json）
- **无 root 输入失败**：手动在 Termux 里执行那几条命令即可（与脚本内容相同）
- **构建慢**：老手机构建前端需要几分钟，属正常现象
- **重启手机后服务停了**：重新运行本脚本，或配置 Termux:Boot 开机自启
