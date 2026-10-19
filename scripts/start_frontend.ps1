param(
    [int]$Port = 5500
)

# InfoShield - Start Frontend Web Server
# Serves static frontend on http://127.0.0.1:$Port

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$ProjectRoot = Split-Path -Parent $ScriptDir
$FrontendDir = Join-Path $ProjectRoot "frontend"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting InfoShield Frontend HTTP Server" -ForegroundColor Cyan
Write-Host " Directory: $FrontendDir" -ForegroundColor Gray
Write-Host " UI URL   : http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $PythonCmd = $VenvPython
} else {
    $PythonCmd = "python"
}

& $PythonCmd -m http.server $Port --directory $FrontendDir

