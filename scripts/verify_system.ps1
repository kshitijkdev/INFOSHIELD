param(
    [int]$FrontendPort = 5500
)

# InfoShield - Automated System Verification Script
# Verifies Backend, Database, Frontend, AI/ML Pipeline, and Protection End-to-End

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " INFOSHIELD FULL SYSTEM END-TO-END VERIFICATION" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$Passed = 0
$Failed = 0

function Report-Check($name, $status, $detail) {
    if ($status) {
        $script:Passed++
        Write-Host " [PASS] $name : $detail" -ForegroundColor Green
    } else {
        $script:Failed++
        Write-Host " [FAIL] $name : $detail" -ForegroundColor Red
    }
}

# 1. Backend Health Check
try {
    $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/health" -Method Get -TimeoutSec 30
    $ok = ($res.status -eq "ok")
    Report-Check "Backend API Health (/api/health)" $ok "Status=$($res.status), Service=$($res.service)"
} catch {
    Report-Check "Backend API Health (/api/health)" $false $_.Exception.Message
}

# 2. Database Health Check
try {
    $res = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/database/health" -Method Get -TimeoutSec 30
    $ok = ($res.success -eq $true -and $res.status -eq "connected")
    Report-Check "Database Health (/api/database/health)" $ok "Status=$($res.status), Database=$($res.database)"
} catch {
    Report-Check "Database Health (/api/database/health)" $false $_.Exception.Message
}

# 3. Frontend HTTP Check
try {
    $res = Invoke-WebRequest -Uri "http://127.0.0.1:$FrontendPort" -Method Get -UseBasicParsing -TimeoutSec 30
    $ok = ($res.StatusCode -eq 200 -and $res.Content -like "*InfoShield*")
    Report-Check "Frontend HTTP Server (port $FrontendPort)" $ok "HTTP $($res.StatusCode) OK, InfoShield UI rendered"
} catch {
    # Fallback check on port 3000
    try {
        $res = Invoke-WebRequest -Uri "http://127.0.0.1:3000" -Method Get -UseBasicParsing -TimeoutSec 10
        $ok = ($res.StatusCode -eq 200 -and $res.Content -like "*InfoShield*")
        Report-Check "Frontend HTTP Server (port 3000)" $ok "HTTP $($res.StatusCode) OK, InfoShield UI rendered"
    } catch {
        Report-Check "Frontend HTTP Server (port $FrontendPort)" $false $_.Exception.Message
    }
}

# 4. Live /api/protect Integration Check
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$ProjectRoot = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectRoot "backend"
$TestImage = Join-Path $BackendDir "test_images\test_document.png"

if (Test-Path $TestImage) {
    try {
        $protectUrl = "http://127.0.0.1:8000/api/protect"
        $purposeText = "I need to submit my Aadhaar to my college for admission and financial aid."

        # Use curl.exe with 30s timeout for reliable multipart/form-data upload on Windows
        $jsonResp = & curl.exe -s -S --max-time 30 -F "file=@$TestImage" -F "purpose=$purposeText" $protectUrl
        $parsed = $jsonResp | ConvertFrom-Json

        $protectOk = ($parsed.success -eq $true -and $parsed.document.protected_filename -ne $null)
        Report-Check "Live /api/protect Pipeline" $protectOk "Protected file: $($parsed.document.protected_filename), Redactions: $($parsed.redactions_applied.Count)"

        # 5. Live Protected Image Download Check
        if ($protectOk) {
            $downloadUrl = "http://127.0.0.1:8000$($parsed.document.protected_url)"
            $dlRes = Invoke-WebRequest -Uri $downloadUrl -Method Get -UseBasicParsing -TimeoutSec 30
            $dlOk = ($dlRes.StatusCode -eq 200 -and $dlRes.Headers["Content-Type"] -eq "image/png" -and $dlRes.RawContentLength -gt 10000)
            Report-Check "Protected Image Download" $dlOk "HTTP $($dlRes.StatusCode) OK, $($dlRes.RawContentLength) bytes"
        }
    } catch {
        Report-Check "Live /api/protect Pipeline" $false $_.Exception.Message
    }
} else {
    Report-Check "Test Document Existence" $false "Missing test document at $TestImage"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Verification Summary: $Passed Passed, $Failed Failed" -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Red" })
Write-Host "==========================================================" -ForegroundColor Cyan

if ($Failed -gt 0) {
    exit 1
} else {
    exit 0
}
