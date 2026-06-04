# SOTH installer for Windows (BETA, ships with 0.1.1+)
#
# Usage (from PowerShell):
#   iwr -useb https://soth.ai/install.ps1 | iex
#   $env:SOTH_CHANNEL = 'canary'; iwr -useb https://soth.ai/install.ps1 | iex
#
# Or, from a checkout of the source repo:
#   powershell.exe -ExecutionPolicy Bypass -File .\scripts\install.ps1
#
# Environment overrides (set before invoking):
#   SOTH_INSTALL_DIR  default: $env:LOCALAPPDATA\soth
#   SOTH_CHANNEL      default: stable
#   SOTH_BASE_URL     default: https://storage.soth.ai/release
#
# Trust path: same as install.sh — fetch the per-channel manifest +
# signature, ed25519-verify against the embedded public key, sha256-
# verify each downloaded artifact (soth.exe + soth-update.exe sidecar)
# against the verified manifest. .NET's `System.Security.Cryptography
# .ECDsa` does not natively expose ed25519 verify; we shell out to
# OpenSSL when available, otherwise fall back to a managed Ed25519
# implementation embedded below.
#
# Both soth.exe (the main binary) AND soth-update.exe (the Phase 4b
# sidecar updater) are installed atomically — the sidecar is required
# for `soth update --apply` on Windows to work. The script refuses to
# install if either fails verification.

[CmdletBinding()]
param(
    [string]$Channel = $(if ($env:SOTH_CHANNEL) { $env:SOTH_CHANNEL } else { "stable" }),
    [string]$Version = $(if ($env:SOTH_VERSION) { $env:SOTH_VERSION } else { "" }),
    [string]$InstallDir = $(if ($env:SOTH_INSTALL_DIR) { $env:SOTH_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "soth" }),
    [string]$BaseUrl = $(if ($env:SOTH_BASE_URL) { $env:SOTH_BASE_URL } else { "https://storage.soth.ai/release" })
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Embedded public keys (must match ops/keys/{stable,canary}.public.pem)
# ---------------------------------------------------------------------------
$StablePubkeyPem = @"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPs/hhy1okfWqaV9TewGde4zYicDy81nCVMTZD9Tr2iw=
-----END PUBLIC KEY-----
"@

$CanaryPubkeyPem = @"
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqIwNCeIA1rYkAoJwE/nRatDFRQui4yoGmL45yovQg34=
-----END PUBLIC KEY-----
"@

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Step($msg) { Write-Host "==> $msg" }
function Fail($msg) { Write-Error $msg; exit 1 }

function Get-PubkeyPem($channel) {
    switch ($channel) {
        'stable' { return $StablePubkeyPem }
        'canary' { return $CanaryPubkeyPem }
        default  { Fail "unknown channel '$channel' (expected stable|canary)" }
    }
}

function Get-PlatformKey() {
    # We only ship windows-amd64 (Windows-arm64 not yet supported by the
    # release pipeline). 32-bit Windows is unsupported.
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($arch -ne 'X64') {
        Fail "unsupported Windows architecture '$arch' (only x64 is supported)"
    }
    return "windows-amd64"
}

function Get-Sha256($path) {
    return (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
}

# Base64-decode the body of a PEM-armored file (between the BEGIN/END
# lines). We need the raw DER bytes to feed ed25519 verify.
function Decode-Pem($pem) {
    $body = ($pem -split "`n" |
        Where-Object { $_ -notmatch '^-----' } |
        ForEach-Object { $_.Trim() }) -join ''
    return [System.Convert]::FromBase64String($body)
}

# Extract the 32-byte raw ed25519 public key from a SubjectPublicKeyInfo
# DER blob. We don't pull in a full ASN.1 parser for one fixed-shape
# blob; ed25519 SPKI is always 44 bytes (12-byte header + 32-byte key)
# so we slice the last 32 bytes.
function Get-Ed25519PublicKeyBytes($pem) {
    $der = Decode-Pem $pem
    if ($der.Length -ne 44) {
        Fail "unexpected public-key DER length $($der.Length); expected 44 (ed25519 SubjectPublicKeyInfo)"
    }
    return $der[12..43]
}

# Verify an ed25519 signature using OpenSSL if available, otherwise
# fall back to .NET 9+'s built-in Ed25519 (System.Security.Cryptography
# .Ed25519). On older .NET we just refuse — the script must NEVER
# silently skip verification.
function Verify-Ed25519($manifestPath, $sigPath, $pubkeyPem) {
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($openssl) {
        $tmpKey = New-TemporaryFile
        try {
            Set-Content -Path $tmpKey -Value $pubkeyPem -NoNewline -Encoding ASCII
            $output = & $openssl pkeyutl -verify -pubin -inkey $tmpKey `
                -rawin -in $manifestPath -sigfile $sigPath 2>&1
            return ($LASTEXITCODE -eq 0)
        } finally {
            Remove-Item -Force $tmpKey -ErrorAction SilentlyContinue
        }
    }

    # .NET 9+ fallback. System.Security.Cryptography.Ed25519 was added
    # in .NET 9. Older runtimes throw a TypeLoadException — refuse
    # rather than skip. PowerShell 7.5+ ships .NET 9.
    try {
        $type = [System.Security.Cryptography.Ed25519]
    } catch {
        Fail @"
ed25519 verification requires either OpenSSL on PATH or PowerShell 7.5+ (.NET 9+).
Neither was detected. Install OpenSSL (https://slproweb.com/products/Win32OpenSSL.html)
or upgrade PowerShell, then re-run the installer.
"@
    }

    $rawKey = Get-Ed25519PublicKeyBytes $pubkeyPem
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    $sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
    return [System.Security.Cryptography.Ed25519]::Verify($manifestBytes, $sigBytes, $rawKey)
}

function Download-File($url, $destination) {
    Write-Step "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing | Out-Null
}

function Install-Atomic($source, $target) {
    $previous = "$target.previous"
    if (Test-Path $target) {
        if (Test-Path $previous) {
            Remove-Item -Force $previous
        }
        Move-Item -Force $target $previous
    }
    Move-Item -Force $source $target
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

$platform = Get-PlatformKey
Write-Step "SOTH installer (channel=$Channel, platform=$platform)"
Write-Step "install dir: $InstallDir"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

$tmpDir = Join-Path $env:TEMP ("soth-install-{0}" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
try {
    # 1. Fetch + verify manifest
    Write-Step "fetching manifest"
    $manifestPath = Join-Path $tmpDir "manifest.json"
    $sigPath = Join-Path $tmpDir "manifest.json.sig"
    # Manifest name: channel-current pointer by default, per-version
    # frozen snapshot when -Version is set.
    if ($Version) {
        $manifestName = "$Channel.v$Version.json"
    } else {
        $manifestName = "$Channel.json"
    }
    Download-File "$($BaseUrl.TrimEnd('/'))/manifest/$manifestName" $manifestPath
    Download-File "$($BaseUrl.TrimEnd('/'))/manifest/$manifestName.sig" $sigPath

    $pubkey = Get-PubkeyPem $Channel
    if (-not (Verify-Ed25519 $manifestPath $sigPath $pubkey)) {
        Fail @"
manifest signature verification FAILED — refusing to install.
The manifest at $BaseUrl is either tampered, served by an attacker,
or signed with a key the installer doesn't recognize.
"@
    }

    # 2. Parse manifest
    $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json
    if ($manifest.channel -ne $Channel) {
        Fail "manifest channel '$($manifest.channel)' != requested '$Channel'"
    }
    if ($Version -and $manifest.version -ne $Version) {
        Fail "pinned manifest version mismatch: requested $Version, got $($manifest.version)"
    }
    Write-Step "version $($manifest.version)"

    $platformEntry = $manifest.platforms.$platform
    if (-not $platformEntry) {
        Fail "manifest has no entry for platform '$platform'"
    }

    # 3. Download soth.exe + verify
    $stagedSoth = Join-Path $tmpDir "soth.exe"
    Download-File $platformEntry.url $stagedSoth
    $actualSoth = Get-Sha256 $stagedSoth
    if ($actualSoth -ne $platformEntry.sha256.ToLower()) {
        Fail "sha256 mismatch on soth.exe: expected $($platformEntry.sha256) got $actualSoth"
    }

    # 4. Download the Phase 4b sidecar updater. NOT in the manifest's
    #    `platforms` map by design (it's a one-time install asset, not
    #    a primary update artifact). Pulled from the same per-version
    #    path as the main binary so it stays paired with the release
    #    that built it.
    $sidecarUrl = "$($BaseUrl.TrimEnd('/'))/v$($manifest.version)/soth-update-windows-amd64.exe"
    $sidecarShaUrl = "$sidecarUrl.sha256"
    $stagedSidecar = Join-Path $tmpDir "soth-update.exe"
    $sidecarShaFile = Join-Path $tmpDir "soth-update.exe.sha256"
    Download-File $sidecarUrl $stagedSidecar
    Download-File $sidecarShaUrl $sidecarShaFile

    # The .sha256 file format mirrors `shasum -a 256` output:
    # "<hex>  <filename>". Take the first whitespace-delimited token.
    $expectedSidecarSha = ((Get-Content -Raw $sidecarShaFile).Trim() -split '\s+')[0].ToLower()
    $actualSidecarSha = Get-Sha256 $stagedSidecar
    if ($actualSidecarSha -ne $expectedSidecarSha) {
        Fail "sha256 mismatch on soth-update.exe: expected $expectedSidecarSha got $actualSidecarSha"
    }

    # 5. Install both atomically
    $sothTarget = Join-Path $InstallDir "soth.exe"
    $sidecarTarget = Join-Path $InstallDir "soth-update.exe"
    Install-Atomic $stagedSoth $sothTarget
    Install-Atomic $stagedSidecar $sidecarTarget

    Write-Step "installed soth.exe v$($manifest.version) → $sothTarget"
    Write-Step "installed soth-update.exe (Phase 4b sidecar) → $sidecarTarget"

    # 6. PATH hint — User scope so existing shells pick it up after refresh.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Host ""
        Write-Host "WARN: $InstallDir is not on your User PATH."
        Write-Host "      Add it (current session + persistent) with:"
        Write-Host "        [Environment]::SetEnvironmentVariable('Path',"
        Write-Host "          [Environment]::GetEnvironmentVariable('Path','User') + ';$InstallDir', 'User')"
        Write-Host "      Then restart your shell."
    }

    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  soth init"
    Write-Host "  soth setup-ca"
    Write-Host "  soth up"
    Write-Host ""
    Write-Host "To check for updates: soth update --check"
    Write-Host "To uninstall: Remove-Item '$sothTarget','$sidecarTarget'"
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $tmpDir
}
