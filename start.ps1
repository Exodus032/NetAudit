# NetAudit launcher
# Starts the backend API and the frontend dev server, reports the capture tier
# you're going to get, and opens the dashboard.
#
#   .\start.ps1              normal run
#   .\start.ps1 -Prod        build the frontend and serve it from the backend on :8787
#   .\start.ps1 -SkipInstall skip dependency install

[CmdletBinding()]
param(
    [switch]$Prod,
    [switch]$SkipInstall
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$backend = Join-Path $root 'backend'
$frontend = Join-Path $root 'frontend'

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "    ! $msg" -ForegroundColor Yellow }
function Write-Ok($msg)   { Write-Host "    + $msg" -ForegroundColor Green }

# --- capability check -------------------------------------------------------

Write-Step 'Checking capture capabilities'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$npcap = Test-Path 'C:\Windows\System32\Npcap\wpcap.dll'

if ($isAdmin) { Write-Ok 'Running elevated' } else { Write-Warn 'Not elevated' }
if ($npcap)   { Write-Ok 'Npcap installed' }   else { Write-Warn 'Npcap not found' }

if ($isAdmin -and $npcap) {
    Write-Ok 'Capture tier: npcap (full packet headers)'
} elseif ($isAdmin) {
    Write-Warn 'Capture tier: rawsocket (IPv4 headers only). Install Npcap from https://npcap.com for full capture.'
} else {
    Write-Warn 'Capture tier: polling (flow counters only, no per-packet detail).'
    Write-Warn 'Re-run this script from an Administrator PowerShell for real packet capture.'
}

# --- backend ----------------------------------------------------------------

Write-Step 'Preparing backend'

if (-not (Test-Path $backend)) { throw "backend/ not found at $backend" }

$venv = Join-Path $backend '.venv'
$py = Join-Path $venv 'Scripts\python.exe'

if (-not (Test-Path $py)) {
    Write-Host '    creating virtualenv...'
    python -m venv $venv
}
if (-not $SkipInstall) {
    Write-Host '    installing python dependencies...'
    & $py -m pip install --quiet --upgrade pip
    & $py -m pip install --quiet -r (Join-Path $backend 'requirements.txt')
}
Write-Ok 'Backend ready'

# --- frontend ---------------------------------------------------------------

Write-Step 'Preparing frontend'

if (-not (Test-Path $frontend)) { throw "frontend/ not found at $frontend" }

if (-not $SkipInstall -and -not (Test-Path (Join-Path $frontend 'node_modules'))) {
    Write-Host '    installing node dependencies...'
    Push-Location $frontend
    npm install --silent
    Pop-Location
}

if ($Prod) {
    Write-Host '    building frontend...'
    Push-Location $frontend
    npm run build
    Pop-Location
    Write-Ok 'Frontend built; backend will serve it'
}

# --- launch -----------------------------------------------------------------

Write-Step 'Starting services'

$backendProc = Start-Process -FilePath $py -ArgumentList '-m','netaudit.server' `
    -WorkingDirectory $backend -PassThru
Write-Ok "Backend pid $($backendProc.Id) -> http://127.0.0.1:8787"

$frontendProc = $null
if (-not $Prod) {
    $npm = (Get-Command npm).Source
    $frontendProc = Start-Process -FilePath $npm -ArgumentList 'run','dev' `
        -WorkingDirectory $frontend -PassThru
    Write-Ok "Frontend pid $($frontendProc.Id) -> http://localhost:5173"
}

$url = if ($Prod) { 'http://127.0.0.1:8787' } else { 'http://localhost:5173' }

Write-Host "`n    waiting for the API to come up..."
$ready = $false
foreach ($i in 1..30) {
    try {
        $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/health' -TimeoutSec 2
        $ready = $true
        Write-Ok "API healthy - capture mode: $($r.capture.mode), elevated: $($r.capture.elevated)"
        if ($r.capture.degraded_reason) { Write-Warn $r.capture.degraded_reason }
        break
    } catch {
        Start-Sleep -Milliseconds 700
    }
}
if (-not $ready) { Write-Warn 'API did not respond in 20s - check the backend window for errors' }

Write-Host "`nNetAudit is running at $url" -ForegroundColor Green
Write-Host "Press Ctrl+C in this window to stop both services.`n"

try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    Write-Host "`nStopping..."
    foreach ($p in @($backendProc, $frontendProc)) {
        if ($p -and -not $p.HasExited) {
            try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {}
        }
    }
}
