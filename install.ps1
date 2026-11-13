# culprit installer
#
# Usage (PowerShell, no admin needed):
#   irm https://raw.githubusercontent.com/markcastle/culprit/master/install.ps1 | iex
#
# What it does:
#   1. Downloads the latest culprit.exe release (x64)
#   2. Puts it in %LOCALAPPDATA%\Programs\culprit
#   3. Adds that folder to your *user* PATH (no admin, no system changes)
#
# Re-run it any time to upgrade. If background tracking is on, the collector
# is restarted on the new version.

$ErrorActionPreference = 'Stop'

$repo = 'markcastle/culprit'
$dir  = Join-Path $env:LOCALAPPDATA 'Programs\culprit'
$url  = "https://github.com/$repo/releases/latest/download/culprit.exe"
$dest = Join-Path $dir 'culprit.exe'
$old  = Join-Path $dir 'culprit.old.exe'

# Older PowerShell defaults to TLS 1.0, which GitHub rejects.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Host "Downloading culprit.exe from the latest release..."
New-Item -ItemType Directory -Force -Path $dir | Out-Null

# A running exe (the background collector, or an open culprit window) cannot
# be overwritten, but it can be renamed out of the way.
if (Test-Path $old)  { Remove-Item $old -Force -ErrorAction SilentlyContinue }
if (Test-Path $dest) { Rename-Item $dest $old -Force }

try {
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
} catch {
    if ((Test-Path $old) -and -not (Test-Path $dest)) { Rename-Item $old $dest -Force }
    throw
}

# Add to user PATH if it isn't there already.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
    Write-Host "Added $dir to your user PATH."
}
# Make it work in this session too, not just new windows.
if (($env:Path -split ';') -notcontains $dir) { $env:Path += ";$dir" }

# If tracking is on, move the collector onto the new version.
& $dest track restart | Out-Null
Remove-Item $old -Force -ErrorAction SilentlyContinue

$ver = & $dest --version
Write-Host ""
Write-Host "Installed $ver to $dest"
Write-Host "Open a new terminal (or just use this one) and type: culprit"
