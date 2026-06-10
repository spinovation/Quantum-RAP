# QuarkShield Active Directory Certificate Services (ADCS) Sync Script
# Run this script on your Windows CA server to synchronize active certificates.

[CmdletBinding()]
param (
    [string]$ServerUrl = "http://localhost:5000",
    [string]$TempPath = "$env:TEMP\adcs_certs_export.csv"
)

Write-Host "--------------------------------------------------" -ForegroundColor Cyan
Write-Host " QuarkShield ADCS Sync Agent starting..." -ForegroundColor Cyan
Write-Host " Target Portal: $ServerUrl" -ForegroundColor Cyan
Write-Host "--------------------------------------------------" -ForegroundColor Cyan

# 1. Export active certificates from CA database in CSV format using certutil
Write-Host "Querying Active Directory Certificate database..."
certutil -view -restrict "NotAfter>=now,Disposition=20" -out "SerialNumber,CommonName,NotAfter,PublicKeyAlgorithm,KeyLength" csv > $TempPath

if (-not (Test-Path $TempPath)) {
    Write-Error "Failed to export certificate registry from ADCS."
    Exit 1
}

# 2. Parse the CSV file manually to avoid system locale bugs
Write-Host "Parsing certificate rows..."
$csvContent = Import-Csv -Path $TempPath -Delimiter ','

$certRows = @()
foreach ($row in $csvContent) {
    # Clean up column names and values
    $serial = $row."Serial Number" -or $row."SerialNumber"
    $cn = $row."Common Name" -or $row."CommonName"
    $expiry = $row."Certificate Expiration Date" -or $row."NotAfter"
    $algo = $row."Public Key Algorithm" -or $row."PublicKeyAlgorithm"
    $length = $row."Key Length" -or $row."KeyLength"

    if ([string]::IsNullOrEmpty($serial) -or [string]::IsNullOrEmpty($cn)) {
        continue
    }

    # Normalize values for QuarkShield ingestion
    $certObj = [PSCustomObject]@{
        serialNumber       = $serial.Trim()
        commonName         = $cn.Trim()
        notAfter           = $expiry
        publicKeyAlgorithm = $algo.Trim()
        keyLength          = [int]$length
    }
    $certRows += $certObj
}

# Clean up temp file
Remove-Item -Path $TempPath -Force

if ($certRows.Count -eq 0) {
    Write-Host "No active certificates found to sync." -ForegroundColor Yellow
    Exit 0
}

Write-Host "Found $($certRows.Count) active certificates to synchronize." -ForegroundColor Green

# 3. Serialize to JSON and POST to QuarkShield central controller
$jsonPayload = ConvertTo-Json -InputObject $certRows -Depth 5
$headers = @{
    "Content-Type" = "application/json"
}

Write-Host "Posting certificate metadata to QuarkShield Ingestion Gateway..."
try {
    $response = Invoke-RestMethod -Uri "$ServerUrl/api/ca/adcs/sync" -Method Post -Body $jsonPayload -Headers $headers
    Write-Host "--------------------------------------------------"
    Write-Host "✓ Success! Sync Complete." -ForegroundColor Green
    Write-Host "Message: $($response.message)" -ForegroundColor Green
    Write-Host "--------------------------------------------------"
}
catch {
    Write-Error "Failed to push certificate logs: $_"
    Exit 1
}
