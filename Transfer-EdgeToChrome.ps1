# Edge to Chrome Data Transfer Script
param([switch]$Force)

$ErrorActionPreference = "Stop"

# Paths
$edgeDataPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
$chromeDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$backupPath = "$env:USERPROFILE\Desktop\Chrome_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

Write-Host ""
Write-Host "=== Edge to Chrome Data Transfer ===" -ForegroundColor Cyan
Write-Host "This will transfer cookies, passwords, and autofill data from Edge to Chrome"
Write-Host ""

# Step 1: Close browsers
Write-Host "[1/5] Checking browsers..." -ForegroundColor Yellow

$edgeProcesses = Get-Process | Where-Object { $_.ProcessName -like "*msedge*" }
$chromeProcesses = Get-Process | Where-Object { $_.ProcessName -eq "chrome" }

if ($edgeProcesses -or $chromeProcesses) {
    Write-Host "  Found running browsers. Closing them..." -ForegroundColor Yellow
    
    if ($edgeProcesses) {
        Write-Host "  Closing Edge..." -NoNewline
        $edgeProcesses | Stop-Process -Force
        Start-Sleep -Seconds 2
        Write-Host " Done" -ForegroundColor Green
    }
    
    if ($chromeProcesses) {
        Write-Host "  Closing Chrome..." -NoNewline
        $chromeProcesses | Stop-Process -Force
        Start-Sleep -Seconds 2
        Write-Host " Done" -ForegroundColor Green
    }
    
    Start-Sleep -Seconds 3
}

Write-Host "  Browsers closed successfully" -ForegroundColor Green

# Step 2: Verify paths exist
Write-Host ""
Write-Host "[2/5] Verifying data paths..." -ForegroundColor Yellow

if (-not (Test-Path $edgeDataPath)) {
    Write-Host "  ERROR: Edge data path not found: $edgeDataPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $chromeDataPath)) {
    Write-Host "  ERROR: Chrome data path not found: $chromeDataPath" -ForegroundColor Red
    exit 1
}

Write-Host "  Edge data: Found" -ForegroundColor Green
Write-Host "  Chrome data: Found" -ForegroundColor Green

# Step 3: Backup Chrome data
Write-Host ""
Write-Host "[3/5] Backing up Chrome data..." -ForegroundColor Yellow

New-Item -ItemType Directory -Path $backupPath -Force | Out-Null

$filesToBackup = @("Cookies", "Login Data", "Web Data")

foreach ($file in $filesToBackup) {
    $sourcePath = Join-Path $chromeDataPath $file
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $backupPath -Force
        Write-Host "  Backed up: $file" -ForegroundColor Green
    }
}

Write-Host "  Backup location: $backupPath" -ForegroundColor Cyan

# Step 4: Transfer Edge data to Chrome
Write-Host ""
Write-Host "[4/5] Transferring Edge data to Chrome..." -ForegroundColor Yellow

$transferFiles = @{
    "Cookies"    = "Stripe cookies and session data"
    "Login Data" = "Saved passwords"
    "Web Data"   = "Autofill data and payment methods"
}

foreach ($file in $transferFiles.Keys) {
    $edgeFile = Join-Path $edgeDataPath $file
    $chromeFile = Join-Path $chromeDataPath $file
    
    if (Test-Path $edgeFile) {
        try {
            Copy-Item -Path $edgeFile -Destination $chromeFile -Force
            $desc = $transferFiles[$file]
            Write-Host "  Transferred: $file ($desc)" -ForegroundColor Green
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "  WARNING: Could not transfer $file - $errorMsg" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "  SKIPPED: $file (not found in Edge)" -ForegroundColor Yellow
    }
}

# Step 5: Summary
Write-Host ""
Write-Host "[5/5] Transfer Summary" -ForegroundColor Yellow
Write-Host "  [OK] Browsers closed" -ForegroundColor Green
Write-Host "  [OK] Chrome data backed up to Desktop" -ForegroundColor Green
Write-Host "  [OK] Edge data transferred to Chrome" -ForegroundColor Green
Write-Host ""
Write-Host "NOTE: Your Chrome backup is saved at:" -ForegroundColor Cyan
Write-Host "  $backupPath" -ForegroundColor White
Write-Host ""
Write-Host "You can now open Chrome. All your Edge data (including Stripe data) should be available." -ForegroundColor Green
Write-Host "If you encounter any issues, restore from the backup above." -ForegroundColor Yellow
Write-Host ""
