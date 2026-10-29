$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $root 'backend'
$frontendDir = Join-Path $root 'frontend'
$venvCandidates = @(
    (Join-Path $root '.venv\Scripts\python.exe'),
    (Join-Path (Split-Path -Parent $root) '.venv\Scripts\python.exe')
)
$venvPython = $venvCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not (Test-Path $venvPython)) {
    throw "Python virtual environment was not found at $venvPython. Recreate the environment first."
}

if (-not (Test-Path (Join-Path $frontendDir 'node_modules'))) {
    Write-Host 'Installing frontend dependencies...'
    Push-Location $frontendDir
    & npm install
    Pop-Location
}

Write-Host 'Starting KESHIHBA backend...'
Start-Process powershell -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location '$backendDir'; & '$venvPython' -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
)

Write-Host 'Starting KESHIHBA frontend...'
Start-Process powershell -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location '$frontendDir'; npm run dev -- --host 127.0.0.1"
)

Write-Host ''
Write-Host 'KESHIHBA is starting.'
Write-Host 'Frontend: http://localhost:5173/'
Write-Host 'Backend: http://127.0.0.1:8000/docs'
