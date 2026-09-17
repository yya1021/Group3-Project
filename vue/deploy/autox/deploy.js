/**
 * ============================================================================
 *  座椅联合图书馆 - 手机端一键自动部署脚本（AutoX.js）
 * ============================================================================
 *  原理：本脚本运行在手机上的 AutoX.js 里，自动完成：
 *     ① 把 /sdcard/Download/vue 项目复制到 Termux 主目录
 *     ② 安装 Node.js（若未安装）
 *     ③ npm install + 构建前端
 *     ④ 后台启动服务器（端口 3000）+ 防休眠
 *
 *  运行前准备（一次性）：
 *     1. 手机安装 AutoX.js 与 Termux（都从 F-Droid / GitHub 安装）
 *     2. 把项目文件夹 vue/ 放到手机  /sdcard/Download/vue
 *     3. 给 AutoX.js 授予：悬浮窗、无障碍、存储 权限
 *     4. （无 root 时）先在 Termux 里手动执行一次 termux-setup-storage 并允许
 *
 *  运行方式：
 *     用 AutoX.js 打开本脚本 → 点 ▶ 运行
 *     - 手机已 root：全自动完成，无需任何操作
 *     - 无 root：自动打开 Termux 并逐条帮你输入命令
 * ============================================================================
 */

var PROJECT_SRC = "/sdcard/Download/vue"; // 项目文件夹在手机上的位置
var TERMUX_HOME = "/data/data/com.termux/files/home"; // Termux 主目录

function log(msg) { console.log(msg); toast(msg); }

// ---------- 检测 root ----------
function hasRoot() {
  try {
    var r = shell("id", true);
    if (r && r.code === 0 && String(r.result || "").indexOf("uid=0") >= 0) return true;
  } catch (e) {}
  return false;
}

// ---------- root 路径：在 Termux 环境下直接执行 ----------
function execAsTermux(cmd) {
  var wrapped = "/data/data/com.termux/files/usr/bin/bash -lc " + JSON.stringify(cmd);
  var r = shell(wrapped, true);
  log("→ " + cmd + "   [code=" + (r ? r.code : "?") + "]");
  return r;
}

function deployWithRoot() {
  log("✅ 检测到 root，开始全自动部署...");
  execAsTermux("rm -rf " + TERMUX_HOME + "/vue && cp -r /sdcard/Download/vue " + TERMUX_HOME + "/vue");
  execAsTermux("cd " + TERMUX_HOME + "/vue && bash deploy/termux-setup.sh");
  log("🎉 部署完成！");
  toast("部署完成！本机 http://localhost:3000 ；公网域名见 README");
}

// ---------- 非 root 路径：打开 Termux 并自动输入命令 ----------
function openTermux() {
  app.startActivity({
    action: "android.intent.action.MAIN",
    packageName: "com.termux",
    className: "com.termux.app.TermuxActivity"
  });
  sleep(4000);
}

function typeIntoTermux(cmd, waitMs) {
  try {
    shell('input text "' + cmd + '"', false);
    sleep(400);
    shell("input keyevent 66", false); // ENTER
    log("已输入: " + cmd);
  } catch (e) {
    log("输入失败（请手动在 Termux 输入）: " + cmd);
  }
  sleep(waitMs || 8000);
}

function deployWithoutRoot() {
  log("⚠️ 未检测到 root，将打开 Termux 自动输入命令（期间请勿锁屏）");
  openTermux();
  typeIntoTermux("termux-setup-storage", 6000);
  typeIntoTermux("cp -r /sdcard/Download/vue ~/vue", 8000);
  typeIntoTermux("cd ~/vue", 2000);
  typeIntoTermux("bash deploy/termux-setup.sh", 6000);
  log("🎉 已自动执行部署命令，请查看 Termux 输出确认结果");
}

// ---------- 主流程 ----------
function main() {
  log("📚 座椅联合图书馆 - 自动部署脚本启动");

  if (!files.exists(PROJECT_SRC + "/package.json")) {
    toast("未找到项目！请先把 vue/ 文件夹放到 " + PROJECT_SRC);
    return;
  }

  if (hasRoot()) {
    deployWithRoot();
  } else {
    deployWithoutRoot();
  }
}

main();
