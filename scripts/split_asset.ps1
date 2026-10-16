<#
.SYNOPSIS
  Splits a file into <2GB parts + a manifest.json, to work around the
  Windows installer size ceilings both NSIS (32-bit mmap) and MSI (2GB CAB
  limit) enforce on single bundled files. See
  docs/superpowers/specs/2026-07-14-first-run-asset-reassembly-design.md.

.PARAMETER Path        The file to split. Deleted after a successful split.
.PARAMETER PartSizeMB  Size of each part in MB (default 1800, safely under
                       the 2048MB/2^31-byte ceiling).
.PARAMETER Compress    gzip the file first and split THAT. The manifest then carries
                       "compression": "gzip" (plus "stored_size"), while total_size and sha256
                       still describe the original file; the launcher
                       (client/src-tauri/src/asset_reassembly.rs) decompresses while
                       reassembling. Used for the Community installer's ~3 GB vulnerability DB:
                       NSIS cannot package more than ~1.9 GB of data in total, and the DB
                       compresses ~8x.
#>
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [int]$PartSizeMB = 1800,
  [switch]$Compress
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Path)) {
  throw "split_asset.ps1: input file not found: $Path"
}

$fullPath = (Resolve-Path $Path).Path
$dir = Split-Path $fullPath -Parent
$name = Split-Path $fullPath -Leaf
$partSizeBytes = [int64]$PartSizeMB * 1MB

Write-Host "Computing sha256 of $name ..."
$sha256 = (Get-FileHash -Path $fullPath -Algorithm SHA256).Hash.ToLowerInvariant()
$totalSize = (Get-Item $fullPath).Length

# The file the parts are cut from: the original, or its gzip when -Compress.
$sourcePath = $fullPath
$packedPath = $null
if ($Compress) {
  $packedPath = "$fullPath.gz.tmp"
  Write-Host "Compressing $name with gzip ($totalSize bytes) ..."
  $in = [System.IO.File]::OpenRead($fullPath)
  try {
    $out = [System.IO.File]::Create($packedPath)
    try {
      $gz = New-Object System.IO.Compression.GZipStream($out, [System.IO.Compression.CompressionLevel]::Optimal)
      try { $in.CopyTo($gz, 4MB) } finally { $gz.Close() }
    } finally { $out.Close() }
  } finally { $in.Close() }
  $sourcePath = $packedPath
  $packedSize = (Get-Item $packedPath).Length
  Write-Host ("Compressed to {0} bytes ({1:N1}x smaller)" -f $packedSize, ($totalSize / [double]$packedSize))
}

$sourceSize = (Get-Item $sourcePath).Length
Write-Host "Splitting $(Split-Path $sourcePath -Leaf) ($sourceSize bytes) into ~$PartSizeMB MB parts..."
$buffer = New-Object byte[] (16MB)
$reader = [System.IO.File]::OpenRead($sourcePath)
$partIndex = 0
try {
  while ($true) {
    $partPath = Join-Path $dir ("{0}.part{1:D3}" -f $name, $partIndex)
    $writer = [System.IO.File]::Create($partPath)
    $wroteAny = $false
    try {
      $remaining = $partSizeBytes
      while ($remaining -gt 0) {
        $toRead = [Math]::Min($buffer.Length, $remaining)
        $read = $reader.Read($buffer, 0, $toRead)
        if ($read -le 0) { break }
        $writer.Write($buffer, 0, $read)
        $remaining -= $read
        $wroteAny = $true
      }
    } finally {
      $writer.Close()
    }
    if (-not $wroteAny) {
      Remove-Item $partPath -Force
      break
    }
    $partIndex++
  }
} finally {
  $reader.Close()
}

$partCount = $partIndex
$manifest = [ordered]@{
  file       = $name
  total_size = $totalSize
  sha256     = $sha256
  part_count = $partCount
}
if ($Compress) {
  $manifest["compression"] = "gzip"
  $manifest["stored_size"] = $sourceSize
}
$manifestPath = Join-Path $dir "$name.manifest.json"
$manifestJson = $manifest | ConvertTo-Json
# Use .NET directly instead of Set-Content -Encoding utf8NoBOM: that encoding
# name is only valid on PowerShell 7+. Windows PowerShell 5.1 (the shell used
# to build this installer) would throw a ParameterBindingException on it.
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestPath, $manifestJson, $utf8NoBom)

Remove-Item $fullPath -Force
if ($packedPath) { Remove-Item $packedPath -Force }

Write-Host "Split $name into $partCount part(s); manifest written to $manifestPath; original deleted."
