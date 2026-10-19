# InfoShield - Start Backend Server
# Starts FastAPI server on http://127.0.0.1:8000 with auto-reload

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$ProjectRoot = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectRoot "backend"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting InfoShield FastAPI Backend Server" -ForegroundColor Cyan
Write-Host " Directory: $BackendDir" -ForegroundColor Gray
Write-Host " Endpoint : http://127.0.0.1:8000" -ForegroundColor Green
Write-Host " Docs     : http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    Write-Host " Environment: Using virtual environment ($VenvPython)" -ForegroundColor Yellow
    $PythonCmd = $VenvPython
} else {
    $PythonCmd = "python"
}

Set-Location -Path $BackendDir
& $PythonCmd -m uvicorn api:app --host 127.0.0.1 --port 8000 --reload

