# NVD Vulnerability Scanner for wp-guard (Windows)
# Scans Go dependencies against known CVEs using govulncheck

$ErrorActionPreference = "Stop"

Write-Host "=== wp-guard NVD Vulnerability Scanner ===" -ForegroundColor Cyan
Write-Host ""

# Check if govulncheck is installed
$govulncheck = Get-Command govulncheck -ErrorAction SilentlyContinue
if (-not $govulncheck) {
    Write-Host "Installing govulncheck..." -ForegroundColor Yellow
    go install golang.org/x/vuln/cmd/govulncheck@latest
}

Write-Host "=== Scanning Go code for vulnerabilities ===" -ForegroundColor Cyan
govulncheck ./...

Write-Host ""
Write-Host "=== Checking module dependencies ===" -ForegroundColor Cyan
go list -m all

Write-Host ""
Write-Host "=== NVD Scan Complete ===" -ForegroundColor Green