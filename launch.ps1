# PassGuard Launcher
# Starts the FastAPI backend and opens the frontend in your default browser

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = $projectRoot
$htmlFile = Join-Path $projectRoot "password-generator.html"
$apiUrl = "http://127.0.0.1:8000"

Write-Host "Starting PassGuard..." -ForegroundColor Cyan

# Kill any existing process on port 8000
Write-Host "Cleaning up any previous instances..." -ForegroundColor Yellow
$existingProcess = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | 
  Where-Object { $_.State -eq "Listen" } | 
  ForEach-Object { Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue }

if ($existingProcess) {
  Write-Host "Stopping previous server..." -ForegroundColor Yellow
  $existingProcess | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

# Start the FastAPI server in the background
Write-Host "Launching backend server..." -ForegroundColor Yellow
Push-Location $backendDir
$process = Start-Process python `
  -ArgumentList "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000" `
  -PassThru `
  -NoNewWindow

# Wait for the server to start
Write-Host "Waiting for server to boot..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Check if server is responding
$serverReady = $false
for ($i = 0; $i -lt 10; $i++) {
  try {
    $response = Invoke-WebRequest -Uri "$apiUrl/vault/status" -UseBasicParsing -ErrorAction Stop
    $serverReady = $true
    break
  } catch {
    Start-Sleep -Seconds 1
  }
}

if ($serverReady) {
  Write-Host "Backend server is running!" -ForegroundColor Green
  Write-Host "Opening the app in your browser..." -ForegroundColor Cyan
  Start-Process $htmlFile
  Write-Host ""
  Write-Host "PassGuard is ready! Use 'CTRL+C' in the PowerShell window to shut down the server." -ForegroundColor Green
} else {
  Write-Host "Could not connect to backend server. Please check your setup." -ForegroundColor Red
  $process | Stop-Process -Force -ErrorAction SilentlyContinue
  Pop-Location
  exit 1
}

Pop-Location

# Keep the script running so the server stays alive
while ($process.HasExited -eq $false) {
  Start-Sleep -Seconds 1
}
