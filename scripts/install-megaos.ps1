# ============================================================================
# install-megaos.ps1 — install / restore the patched boot_a image on
#                     H3C MegaBook 14 (MegaOS / Android 14)
#
# Writes directly to the GPT partition from Windows (no fastboot required),
# then reads it back and verifies SHA256.
#
# Install:
#   .\install-megaos.ps1 -Image .\boot_a_megaos-6.12.30-r1.img `
#       -ExpectedSha256 <sha256> -Backup -SetOneShotBoot
#
# Restore stock:
#   .\install-megaos.ps1 -Restore .\boot_a-backup-YYYYmmdd-HHMMSS.img
#
# Options:
#   -Image <path>          patched boot image to install
#   -Restore <path>        stock image to restore (same as -Image, no hash check)
#   -Partition <name>      default: boot_a
#   -Disk <n>              default: 0
#   -ExpectedSha256 <hex>  abort if the image hash does not match
#   -Backup                save the current partition before writing
#   -SetOneShotBoot        set UEFI one-shot boot to MegaOS after writing
#   -Yes                   skip the confirmation prompt
#   -DryRun                print the plan and exit without writing
#
# The script self-elevates (UAC) because raw disk access needs Administrator.
# ============================================================================

[CmdletBinding()]
param(
    [string]$Image,
    [string]$Restore,
    [string]$Partition = 'boot_a',
    [int]$Disk = 0,
    [string]$ExpectedSha256 = '',
    [switch]$Backup,
    [switch]$SetOneShotBoot,
    [switch]$Yes,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Info($msg) { Write-Host $msg }
function Ok($msg)   { Write-Host $msg -ForegroundColor Green }
function Warn($msg) { Write-Host "WARN: $msg" -ForegroundColor Yellow }

# ---------------------------------------------------------------------------
# Administrator check + self elevation
# ---------------------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Warn 'Administrator privileges required. Relaunching with UAC...'
    $argv = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $argv += "-$k" }
        } else {
            $argv += @("-$k", ('"' + [string]$v + '"'))
        }
    }
    Start-Process powershell -Verb RunAs -Wait -ArgumentList $argv
    exit 0
}

# ---------------------------------------------------------------------------
# Mode: install or restore
# ---------------------------------------------------------------------------
if ($Restore) {
    if ($Image) { Fail 'Use either -Image (install) or -Restore (rollback), not both.' }
    $srcImage = $Restore
    $modeName = 'restore'
    $ExpectedSha256 = ''
    $Backup = $false
} elseif ($Image) {
    $srcImage = $Image
    $modeName = 'install'
} else {
    Fail 'Specify -Image <patched.img> to install, or -Restore <stock.img> to roll back.'
}

if (-not (Test-Path -LiteralPath $srcImage)) { Fail "Image not found: $srcImage" }
$srcItem = Get-Item -LiteralPath $srcImage
$srcSize = [int64]$srcItem.Length
$srcSha  = (Get-FileHash -Algorithm SHA256 -LiteralPath $srcImage).Hash.ToLower()

if ($ExpectedSha256) {
    $expected = $ExpectedSha256.Trim().ToLower()
    if ($srcSha -ne $expected) {
        Fail ("SHA256 mismatch:`n  expected: {0}`n  actual  : {1}" -f $expected, $srcSha)
    }
    Ok 'Image SHA256 matches -ExpectedSha256.'
}

# ---------------------------------------------------------------------------
# Open physical disk and parse GPT
# ---------------------------------------------------------------------------
$diskInfo = Get-Disk -Number $Disk
$sector = [int]$diskInfo.LogicalSectorSize
if (-not $sector) { $sector = 512 }

$diskPath = "\\.\PhysicalDrive$Disk"
$access = if ($DryRun) { [System.IO.FileAccess]::Read } else { [System.IO.FileAccess]::ReadWrite }

try {
    $fs = New-Object System.IO.FileStream(
        $diskPath,
        [System.IO.FileMode]::Open,
        $access,
        [System.IO.FileShare]::ReadWrite)
} catch {
    Fail "Cannot open ${diskPath}: $($_.Exception.Message)"
}

function ReadAt($stream, [int64]$offset, [int]$length) {
    $stream.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $buf = New-Object byte[] $length
    $read = 0
    while ($read -lt $length) {
        $n = $stream.Read($buf, $read, $length - $read)
        if ($n -le 0) { throw "Read failed at offset $offset" }
        $read += $n
    }
    return $buf
}

try {
    $hdr = ReadAt $fs ([int64]$sector) 92
    if ([System.Text.Encoding]::ASCII.GetString($hdr, 0, 8) -ne 'EFI PART') {
        Fail 'GPT header not found (is this a UEFI/GPT disk?).'
    }

    $entryLBA   = [System.BitConverter]::ToUInt64($hdr, 72)
    $numEntries = [System.BitConverter]::ToUInt32($hdr, 80)
    $entrySize  = [System.BitConverter]::ToUInt32($hdr, 84)
    $allEntries = ReadAt $fs ([int64]($entryLBA * $sector)) ([int]($numEntries * $entrySize))

    $parts = @{}
    $zero = New-Object byte[] 16
    for ($i = 0; $i -lt $numEntries; $i++) {
        $off = $i * $entrySize
        $type = New-Object byte[] 16
        [Array]::Copy($allEntries, $off, $type, 0, 16)
        $isZero = $true
        foreach ($b in $type) { if ($b -ne 0) { $isZero = $false; break } }
        if ($isZero) { continue }

        $first = [System.BitConverter]::ToUInt64($allEntries, $off + 32)
        $last  = [System.BitConverter]::ToUInt64($allEntries, $off + 40)
        $nameBytes = New-Object byte[] 72
        [Array]::Copy($allEntries, $off + 56, $nameBytes, 0, 72)
        $name = ([System.Text.Encoding]::Unicode.GetString($nameBytes)).Trim([char]0).Trim()

        $parts[$name] = @{
            Index = $i + 1
            Start = $first
            Size  = [int64](($last - $first + 1) * $sector)
        }
    }

    if (-not $parts.ContainsKey($Partition)) {
        Fail "Partition '$Partition' not found on disk $Disk."
    }

    $p        = $parts[$Partition]
    $offset   = [int64]($p.Start * $sector)
    $partSize = [int64]$p.Size

    Info ''
    Info '=== install plan ==='
    Info ("  image      : {0}" -f $srcItem.FullName)
    Info ("  image size : {0:N0} B" -f $srcSize)
    Info ("  image sha  : {0}" -f $srcSha)
    Info ("  target     : {0}  (GPT #{1}, disk {2}, offset {3:N0}, size {4:N0} B)" -f `
        $Partition, $p.Index, $Disk, $offset, $partSize)
    Info ("  mode       : {0}" -f $modeName)
    Info '===================='

    if ($srcSize -gt $partSize) {
        Fail ("Image is larger than the partition ({0:N0} > {1:N0})." -f $srcSize, $partSize)
    }
    if ($srcSize -lt $partSize) {
        Warn ("Image is {0:N0} B smaller than the partition; the tail will be zero-padded." -f ($partSize - $srcSize))
    }

    if ($DryRun) {
        Ok 'Dry run only. No data was written.'
        exit 0
    }

    # -----------------------------------------------------------------------
    # Optional backup of the current partition
    # -----------------------------------------------------------------------
    if ($Backup) {
        $backupPath = Join-Path (Get-Location) ("{0}-backup-{1}.img" -f $Partition, (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Info "Backing up $Partition to $backupPath ..."
        $fs.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $out = [System.IO.File]::Create($backupPath)
        try {
            $remaining = $partSize
            $buf = New-Object byte[] (4MB)
            while ($remaining -gt 0) {
                $n = [Math]::Min([int64]$buf.Length, $remaining)
                $k = $fs.Read($buf, 0, [int]$n)
                if ($k -le 0) { throw 'Backup read failed' }
                $out.Write($buf, 0, $k)
                $remaining -= $k
            }
        } finally {
            $out.Close()
        }
        $backupSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $backupPath).Hash.ToLower()
        Ok ("Backup written: {0}  sha256={1}" -f $backupPath, $backupSha)
    }

    # -----------------------------------------------------------------------
    # Confirmation
    # -----------------------------------------------------------------------
    if (-not $Yes) {
        $ans = Read-Host "Type 'yes' to write $Partition (this overwrites the current boot image)"
        if ($ans -ne 'yes') {
            Warn 'Cancelled.'
            exit 1
        }
    }

    # -----------------------------------------------------------------------
    # Write + flush
    # -----------------------------------------------------------------------
    Info 'Writing...'
    $src = [System.IO.File]::OpenRead($srcItem.FullName)
    $fs.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
    try {
        $buf = New-Object byte[] (4MB)
        while (($n = $src.Read($buf, 0, $buf.Length)) -gt 0) {
            $fs.Write($buf, 0, $n)
        }
        $pad = $partSize - $srcSize
        if ($pad -gt 0) {
            $zeroBuf = New-Object byte[] (4MB)
            while ($pad -gt 0) {
                $n = [Math]::Min([int64]$zeroBuf.Length, $pad)
                $fs.Write($zeroBuf, 0, [int]$n)
                $pad -= $n
            }
        }
        $fs.Flush($true)
    } finally {
        $src.Close()
    }

    # -----------------------------------------------------------------------
    # Read back and verify
    # -----------------------------------------------------------------------
    Start-Sleep -Milliseconds 500
    Info 'Verifying (read back)...'
    $fs.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $remaining = $srcSize
    $tmp = New-Object byte[] (4MB)
    try {
        while ($remaining -gt 0) {
            $n = [Math]::Min([int64]$tmp.Length, $remaining)
            $k = $fs.Read($tmp, 0, [int]$n)
            if ($k -le 0) { break }
            $sha.TransformBlock($tmp, 0, $k, $null, 0) | Out-Null
            $remaining -= $k
        }
        $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0) | Out-Null
        $readSha = (($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }

    Info ("  written : {0}" -f $srcSha)
    Info ("  readback: {0}" -f $readSha)
    if ($readSha -ne $srcSha) {
        Fail "Verification failed for $Partition. Re-flash the stock image immediately."
    }
    Ok "$Partition written and verified."

    # -----------------------------------------------------------------------
    # Optional one-shot boot to MegaOS
    # -----------------------------------------------------------------------
    if ($SetOneShotBoot) {
        $guid = '{bfb30910-c791-11f1-bfbb-806e6f6e6963}'
        Info "Setting one-shot UEFI boot to $guid ..."
        & bcdedit /set '{fwbootmgr}' bootsequence $guid | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Warn 'bcdedit failed; set the one-shot boot entry manually.'
        } else {
            Ok 'One-shot boot set. Reboot to enter MegaOS.'
        }
    }

    Ok "Done ($modeName)."
}
finally {
    if ($fs) { $fs.Close() }
}
