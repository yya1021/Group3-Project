<#
.SYNOPSIS
    第 7 周安全扫描一键演示脚本（SAST / DAST / 依赖成分扫描）。

.DESCRIPTION
    在仓库根目录运行本脚本即可完成：
      1) 自动确认依赖已安装（缺失则执行 npm install）
      2) 自动探测本机代理（Clash / v2ray 等）并注入给 npm audit，保证依赖扫描可联网
      3) 启动一个使用「临时沙箱数据目录」的后端实例（不污染仓库中的 data/ 与 uploads/）
      4) 依次执行 SAST、依赖扫描、DAST
      5) 输出漏洞汇总表，并生成基线报告与漏洞清单

.EXAMPLE
    .\security\run-scan.ps1
    全量扫描，自动启动沙箱服务。

.EXAMPLE
    .\security\run-scan.ps1 -Only sast,deps
    只跑静态扫描与依赖扫描（不需要启动服务，最快）。

.EXAMPLE
    .\security\run-scan.ps1 -Only dast -BaseUrl http://127.0.0.1:3000
    对已经在运行的服务做动态扫描（此时不会执行写入型探针，避免污染真实数据）。
#>
param(
    [string]$Only = 'all',
    [string]$BaseUrl = '',
    [switch]$NoWriteProbes,
    [switch]$NoInstall,
    [int]$Port = 0
)

$ErrorActionPreference = 'Stop'

# 让中文与符号在控制台正确显示
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch { }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

Write-Host ''
Write-Host '=== 第 7 周安全扫描：环境准备 ===' -ForegroundColor Cyan

# ---------- 1) 依赖检查 ----------
$serverModules = Join-Path $repoRoot 'node_modules\express'
if (-not (Test-Path $serverModules)) {
    if ($NoInstall) {
        Write-Host '未检测到 node_modules，且已指定 -NoInstall，扫描可能失败。' -ForegroundColor Yellow
    } else {
        Write-Host '未检测到依赖，正在执行 npm install ...' -ForegroundColor Yellow
        Push-Location $repoRoot
        try { npm install --no-audit --no-fund } finally { Pop-Location }
    }
} else {
    Write-Host '依赖已就绪（node_modules 存在）。' -ForegroundColor Green
}

# ---------- 2) 代理自动探测（用于 npm audit 与依赖下载） ----------
if (-not $env:HTTP_PROXY -or -not $env:HTTPS_PROXY) {
    $proxy = $null
    try {
        $reg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if ($reg.ProxyEnable -eq 1 -and $reg.ProxyServer) { $proxy = $reg.ProxyServer }
    } catch { }
    if ($proxy -and $proxy -notmatch '^https?://') { $proxy = "http://$proxy" }
    if ($proxy) {
        $env:HTTP_PROXY = $proxy
        $env:HTTPS_PROXY = $proxy
        Write-Host "已自动采用系统代理进行依赖扫描：$proxy" -ForegroundColor Green
    } else {
        Write-Host '未检测到系统代理；若 npm audit 失败，将自动降级为内置离线公告表（会在报告中记录原因）。' -ForegroundColor Yellow
    }
} else {
    Write-Host "沿用已有代理环境变量：$env:HTTPS_PROXY" -ForegroundColor Green
}

# ---------- 3) 组装参数并执行 ----------
$nodeArgs = @((Join-Path $scriptDir 'scan.js'))
if ($Only -ne 'all') { $nodeArgs += "--only=$Only" }
if ($BaseUrl) { $nodeArgs += "--base-url=$BaseUrl" }
if ($Port -gt 0) { $nodeArgs += "--port=$Port" }
if ($NoWriteProbes) { $nodeArgs += '--no-write-probes' }

Write-Host ''
Write-Host '=== 开始扫描 ===' -ForegroundColor Cyan
Push-Location $repoRoot
try {
    & node @nodeArgs
    $code = $LASTEXITCODE
} finally {
    Pop-Location
}

# ---------- 4) 结果指引 ----------
$reports = Join-Path $scriptDir 'reports'
Write-Host ''
Write-Host '=== 结果文件 ===' -ForegroundColor Cyan
foreach ($name in @('baseline-report.md', 'vulnerability-list.md', 'scan-summary.json')) {
    $p = Join-Path $reports $name
    if (Test-Path $p) {
        $size = [math]::Round((Get-Item $p).Length / 1KB, 1)
        Write-Host ("  {0,-24} {1,8} KB" -f $name, $size) -ForegroundColor Gray
    }
}
Write-Host ''
Write-Host '提示：用 VS Code 打开 security/reports/ 目录即可直接预览 Markdown 报告。' -ForegroundColor Gray
Write-Host ''

if ($code -eq 2) {
    Write-Host '扫描完成，但存在执行异常（详见报告「局限性」与原始 JSON）。' -ForegroundColor Yellow
} elseif ($code -ne 0) {
    Write-Host "扫描异常退出，退出码 $code。" -ForegroundColor Red
}
exit $code
