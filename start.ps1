param(
    [string]$HostName = "localhost",
    [int]$Port = 8090,
    [string]$LogLevel = "debug",
    [switch]$NoReload
)

$EnvFile = "$PSScriptRoot\.env"

$ErrorActionPreference = "Stop"

try {
    # Set environment variables
    $Env:HOST = $HostName
    $Env:PORT = $Port.ToString()
    $Env:LOG_LEVEL = $LogLevel.ToUpper()
    $Env:VOLUME = "P:\core"
    $Env:LOG_PATH = "P:\core\logs"
    $Env:CLIENT = "test-client"

    # Ensure directories exist
    @($Env:VOLUME, $Env:LOG_PATH) | ForEach-Object {
        if (-not (Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "Created directory: $_" -ForegroundColor Green
        }
    }

    # Build uvicorn command
    $uvicornArgs = @(
        "core_api.api.fast_api:get_app",
        "--factory",
        "--host", $HostName,
        "--port", $Port,
        "--log-level", $LogLevel,
        "--proxy-headers",
        "--forwarded-allow-ips=*",
        "--access-log"
    )

    if (-not $NoReload) {
        $uvicornArgs += @("--reload", "--reload-dir", ".\core_api")
    }

    # If a .env file exists, pass it to uvicorn
    if (Test-Path $EnvFile) {
        $uvicornArgs += @("--env-file", $EnvFile)
        Write-Host "Using env file: $EnvFile" -ForegroundColor Yellow
    } else {
        Write-Host "No .env file found at: $EnvFile" -ForegroundColor DarkYellow
    }

    Write-Host "Starting FastAPI server..." -ForegroundColor Green
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  Client: $Env:CLIENT" -ForegroundColor Cyan
    Write-Host "  Host: $Env:HOST" -ForegroundColor Cyan
    Write-Host "  Port: $Env:PORT" -ForegroundColor Cyan
    Write-Host "  Log Level: $Env:LOG_LEVEL" -ForegroundColor Cyan
    Write-Host "  Volume: $Env:VOLUME" -ForegroundColor Cyan
    Write-Host "  Log Path: $Env:LOG_PATH" -ForegroundColor Cyan
    Write-Host "  Reload: $(-not $NoReload)" -ForegroundColor Cyan

    # Start the server
    & uvicorn @uvicornArgs

} catch {
    Write-Host "Error starting server: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}