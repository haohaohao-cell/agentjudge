# 本地开发入口（Windows PowerShell）
# 用法: pwsh -File scripts/dev.ps1 [-Port 8737]
param([int]$Port = 8737)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$env:PYTHONPATH = "$root\src"
$env:PYTHONIOENCODING = "utf-8"

$python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
& $python -m agentjudge serve --host 127.0.0.1 --port $Port
