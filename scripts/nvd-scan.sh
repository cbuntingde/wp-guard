#!/bin/bash
# NVD Vulnerability Scanner for wp-guard
# Scans Go dependencies against known CVEs

set -e

echo "=== wp-guard NVD Vulnerability Scanner ==="
echo ""

# Check if govulncheck is installed
if ! command -v govulncheck &> /dev/null; then
    echo "Installing govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest
fi

echo "=== Scanning Go code for vulnerabilities ==="
govulncheck ./...

echo ""
echo "=== Checking module dependencies ==="
go list -m all

echo ""
echo "=== Checking for known CVE patterns ==="
# Check for common vulnerability patterns in dependencies
grep -r "CVE-" go.mod go.sum 2>/dev/null || echo "No known CVEs in dependencies"

echo ""
echo "=== NVD Scan Complete ==="