# =============================================================================
# sign_driver.ps1 - test-sign EniDrv.sys with a self-signed cert
# =============================================================================
#
# Run this ONCE as Administrator after building EniDrv.sys. Steps:
#
#   1. Create a self-signed code-signing cert in the user's Personal
#      cert store (CurrentUser\My). Won't be trusted by the kernel
#      until we copy it into the right local-machine stores.
#
#   2. Export the cert to a .pfx (private key + cert) and a .cer (cert
#      only, what we install into trust roots).
#
#   3. Install the .cer into LocalMachine\Root (Trusted Root CAs) so
#      the cert chain validates, and LocalMachine\TrustedPublisher so
#      the kernel doesn't ask the user to confirm publisher on load.
#
#   4. signtool.exe sign /v /f cert.pfx /p "" /fd SHA256 ... EniDrv.sys
#
#   5. Remind operator to enable test-signing:
#        bcdedit /set testsigning on
#        (reboot)
#
# Idempotent enough for repeated runs - if the cert exists we reuse it.
# =============================================================================

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$bin         = Join-Path $projectRoot 'bin'
$sysFile     = Join-Path $bin 'EniDrv.sys'
$certDir     = Join-Path $PSScriptRoot 'certs'
$pfxPath     = Join-Path $certDir 'EniDrv.pfx'
$cerPath     = Join-Path $certDir 'EniDrv.cer'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Must run elevated. Open an admin PowerShell."
    exit 1
}

if (-not (Test-Path $sysFile)) {
    Write-Host "[!] $sysFile not found. Build the driver first:"
    Write-Host "    cmake --build build --target EniDrv --config Release"
    exit 1
}

New-Item -ItemType Directory -Force -Path $certDir | Out-Null

# -----------------------------------------------------------------------------
# 1. Find or create the cert
# -----------------------------------------------------------------------------
$subject = "CN=ENI Driver Test Signing, O=ENI, C=US"
$cert = Get-ChildItem 'Cert:\CurrentUser\My' |
    Where-Object { $_.Subject -eq $subject -and $_.HasPrivateKey } |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "[*] Creating self-signed cert..."
    $cert = New-SelfSignedCertificate `
        -Subject $subject `
        -Type CodeSigningCert `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(5) `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3")  # extKeyUsage = code signing
    Write-Host "[+] Created cert: $($cert.Thumbprint)"
} else {
    Write-Host "[+] Reusing existing cert: $($cert.Thumbprint)"
}

# -----------------------------------------------------------------------------
# 2. Export
# -----------------------------------------------------------------------------
# Newer PowerShell rejects empty PFX passwords. The PFX never leaves
# this machine - it only exists so signtool can read the private key
# - so the password is just to satisfy the API. Hardcoded local-only
# string; .gitignore excludes the certs/ directory.
$pfxPasswordPlain = 'eni-test-signing'
$pwd = ConvertTo-SecureString -String $pfxPasswordPlain -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd | Out-Null
Export-Certificate    -Cert $cert -FilePath $cerPath | Out-Null
Write-Host "[+] Exported to $pfxPath / $cerPath"

# -----------------------------------------------------------------------------
# 3. Install into kernel-trusted stores
# -----------------------------------------------------------------------------
# LocalMachine\Root: makes the kernel cert chain validate
# LocalMachine\TrustedPublisher: silences publisher confirmation prompts
foreach ($store in @('Root', 'TrustedPublisher')) {
    $machineStore = Get-Item "Cert:\LocalMachine\$store"
    $machineStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $existing = $machineStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
    if (-not $existing) {
        $machineStore.Add($cert)
        Write-Host "[+] Installed cert in LocalMachine\$store"
    } else {
        Write-Host "[+] Cert already in LocalMachine\$store"
    }
    $machineStore.Close()
}

# -----------------------------------------------------------------------------
# 4. Sign the driver
# -----------------------------------------------------------------------------
$signtool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
if (-not (Test-Path $signtool)) {
    Write-Host "[!] signtool.exe not found at $signtool"
    exit 1
}

Write-Host "[*] Signing $sysFile ..."
& $signtool sign /v /f $pfxPath /p $pfxPasswordPlain /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 $sysFile
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] signtool failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "[+] Driver signed."
Write-Host ""
Write-Host "==============================================================="
Write-Host " NEXT STEPS - YOU MUST DO THESE BEFORE THE KERNEL ACCEPTS IT:"
Write-Host "==============================================================="
Write-Host ""
Write-Host " 1. Enable test-signing mode (requires reboot):"
Write-Host "      bcdedit /set testsigning on"
Write-Host ""
Write-Host " 2. Reboot."
Write-Host ""
Write-Host " 3. After reboot, you'll see 'Test Mode' watermark in the corner."
Write-Host "    That's normal. The driver will now load via SCM."
Write-Host ""
Write-Host " 4. To revert when done:"
Write-Host "      bcdedit /set testsigning off"
Write-Host "      (then reboot)"
Write-Host ""
Write-Host "==============================================================="
