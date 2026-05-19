param(
    [string]$PackagePrefix = "authlimit-bt-linux-amd64",
    [string]$OutputName = "authlimit",
    [string]$DistDir = "dist",
    [switch]$SkipZip
)

$ErrorActionPreference = "Stop"

$root = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($root)) {
    $root = (Get-Location).Path
}

$requiredFiles = @(
    "config.yaml",
    ".env",
    "certs\jwt_private.pem",
    "certs\jwt_public.pem"
)

foreach ($file in $requiredFiles) {
    $path = Join-Path $root $file
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file not found: $file"
    }
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$distRoot = Join-Path $root $DistDir
$packageDir = Join-Path $distRoot "$PackagePrefix-$stamp"
$certsDir = Join-Path $packageDir "certs"
$binaryPath = Join-Path $packageDir $OutputName
$zipPath = "$packageDir.zip"
$goCache = Join-Path $root ".gocache"

New-Item -ItemType Directory -Force -Path $certsDir | Out-Null
New-Item -ItemType Directory -Force -Path $goCache | Out-Null

$oldEnv = @{
    GOOS        = $env:GOOS
    GOARCH      = $env:GOARCH
    GOAMD64     = $env:GOAMD64
    CGO_ENABLED = $env:CGO_ENABLED
    GOCACHE     = $env:GOCACHE
}

try {
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:GOAMD64 = "v1"
    $env:CGO_ENABLED = "0"
    $env:GOCACHE = $goCache

    Push-Location $root
    try {
        go build `
            -tags=nomsgpack `
            -p=1 `
            -trimpath `
            -buildvcs=false `
            -ldflags="-s -w -buildid=" `
            -o $binaryPath `
            ./cmd/server
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:GOOS = $oldEnv.GOOS
    $env:GOARCH = $oldEnv.GOARCH
    $env:GOAMD64 = $oldEnv.GOAMD64
    $env:CGO_ENABLED = $oldEnv.CGO_ENABLED
    $env:GOCACHE = $oldEnv.GOCACHE
}

Copy-Item -LiteralPath (Join-Path $root "config.yaml") -Destination (Join-Path $packageDir "config.yaml")
Copy-Item -LiteralPath (Join-Path $root ".env") -Destination (Join-Path $packageDir ".env")
Copy-Item -LiteralPath (Join-Path $root "certs\jwt_private.pem") -Destination (Join-Path $certsDir "jwt_private.pem")
Copy-Item -LiteralPath (Join-Path $root "certs\jwt_public.pem") -Destination (Join-Path $certsDir "jwt_public.pem")

if (-not $SkipZip) {
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Compress-Archive -Path (Join-Path $packageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal
}

$binary = Get-Item -LiteralPath $binaryPath
Write-Host "Build complete."
Write-Host "Package directory: $packageDir"
Write-Host ("Binary size: {0:N0} bytes" -f $binary.Length)

if (-not $SkipZip) {
    $zip = Get-Item -LiteralPath $zipPath
    Write-Host "Zip package: $zipPath"
    Write-Host ("Zip size: {0:N0} bytes" -f $zip.Length)
}

Write-Host ""
Write-Host "Upload these files/directories to the same server runtime directory:"
Get-ChildItem -LiteralPath $packageDir -Force | ForEach-Object {
    Write-Host ("- " + $_.Name)
}
