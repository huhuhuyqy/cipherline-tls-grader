param(
    [switch]$InstallOnly,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$venvRoot = Join-Path $projectRoot '.venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host 'First-time setup: creating the local Python environment...'
    $pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pythonLauncher) {
        & py -3 -m venv $venvRoot
    } else {
        $systemPython = Get-Command python -ErrorAction Stop
        & $systemPython.Source -m venv $venvRoot
    }
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python environment.' }
}

$previousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
& $venvPython -c 'import cryptography' 2>$null
$dependencyStatus = $LASTEXITCODE
$ErrorActionPreference = $previousErrorAction
if ($dependencyStatus -ne 0) {
    Write-Host 'First-time setup: installing the TLS certificate library...'
    & $venvPython -m pip install -r (Join-Path $projectRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Check the internet connection and retry.' }
}

if ($InstallOnly) {
    Write-Host 'Local environment is ready.'
    exit 0
}

$expectedServer = (Join-Path $projectRoot 'server.py').ToLowerInvariant()
$existingListener = Get-NetTCPConnection -LocalPort 8843 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existingListener) {
    $existingProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $($existingListener.OwningProcess)"
    $existingCommand = [string]$existingProcess.CommandLine
    if ($existingProcess.Name -like 'python*' -and $existingCommand.ToLowerInvariant().Contains($expectedServer)) {
        $existingHealth = $null
        try { $existingHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:8843/api/health' -TimeoutSec 2 } catch {}
        if ($existingHealth -and [int]$existingHealth.active_jobs -gt 0) {
            throw "CIPHERLINE already has $($existingHealth.active_jobs) active scan job(s). Return to the existing browser tab and wait for completion; do not restart during a scan."
        }
        Write-Host "Restarting the previous CIPHERLINE process (PID $($existingProcess.ProcessId))..."
        Stop-Process -Id $existingProcess.ProcessId -Force
        Start-Sleep -Milliseconds 600
    } else {
        throw "Port 8843 is already used by another application (PID $($existingListener.OwningProcess)). Close that application and retry."
    }
}

$serverArguments = @((Join-Path $projectRoot 'server.py'))
if (-not $NoBrowser) { $serverArguments += '--open' }

Write-Host ''
Write-Host 'CIPHERLINE will open at http://127.0.0.1:8843'
Write-Host 'Keep this window open. Press Ctrl+C here when you finish.'
Write-Host ''
& $venvPython @serverArguments
