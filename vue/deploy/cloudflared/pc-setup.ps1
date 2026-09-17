# ============================================================
#  Library - Cloudflare Tunnel setup on Windows PC
#
#  Steps:
#    1. install cloudflared
#    2. login Cloudflare (open browser and click Authorize)
#    3. create tunnel "library"
#    4. add DNS routes for two domains
#
#  After this, copy the credential .json file to your phone.
#
#  Usage (PowerShell):
#    powershell -ExecutionPolicy Bypass -File deploy\cloudflared\pc-setup.ps1
# ============================================================
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "== 0/5 check cloudflared ==" -ForegroundColor Cyan
$cf = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cf) {
    Write-Host "cloudflared not found, installing via winget ..."
    winget install --id Cloudflare.cloudflared -e --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    $cf = Get-Command cloudflared -ErrorAction SilentlyContinue
    if (-not $cf) {
        Write-Host "Still not found. Close and reopen PowerShell, then run again." -ForegroundColor Yellow
        Write-Host "Or download manually: https://github.com/cloudflare/cloudflared/releases" -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "cloudflared version: " -NoNewline; cloudflared --version

Write-Host ""
Write-Host "== 1/5 login Cloudflare ==" -ForegroundColor Cyan
Write-Host "A URL will be printed. Open it in browser and click Authorize." -ForegroundColor Yellow
cloudflared tunnel login

Write-Host ""
Write-Host "== 2/5 create tunnel library ==" -ForegroundColor Cyan
cloudflared tunnel create library

Write-Host ""
Write-Host "== 3/5 add DNS routes (2 domains + www) ==" -ForegroundColor Cyan
Write-Host "Make sure both domains are added to Cloudflare and Active first." -ForegroundColor Yellow
cloudflared tunnel route dns library goodwood-ci.asia
cloudflared tunnel route dns library www.goodwood-ci.asia
cloudflared tunnel route dns library gczyws.xyz
cloudflared tunnel route dns library www.gczyws.xyz

Write-Host ""
Write-Host "== 4/5 show tunnel UUID and credential file ==" -ForegroundColor Cyan
Get-ChildItem "$env:USERPROFILE\.cloudflared" | Format-Table Name, Length

Write-Host ""
Write-Host "== 5/5 done ==" -ForegroundColor Green
Write-Host "Copy the credential .json file to your phone (Termux home) at:"
Write-Host "   ~/.cloudflared/"
Write-Host "No manual config needed - deploy/run-tunnel.sh detects it automatically."
