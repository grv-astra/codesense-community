#requires -Version 5.1
<#
.SYNOPSIS
  One-command Windows build for the Code Sense offline desktop app.

.DESCRIPTION
  COMMUNITY INSTALLER (-Edition community, the default): ships NO bundled AI model and no
  llama-server, so -ModelGguf / -LlamaServer are not needed (and ignored). The user's own LLM
  (Settings > AI verification) is the AI path. It also switches off the client-delivery
  settings main.rs defaults to (2-scan trial, activation password) and uses the overlay
  client\src-tauri\tauri.community.conf.json (own product name / identifier, no model resource,
  WebView2 bootstrapper instead of the fixed runtime). BUILD IT FROM THE COMMUNITY EXPORT
  (scripts\editions\export_community.py), never from the private source tree: the PyInstaller
  freeze bundles whatever is in server\, and the source tree contains the Pro-only verifier
  and enrichment code.

  Automates BUILD.md end-to-end on a Windows host:
    1. Freezes the Django backend into codesense-server.exe (PyInstaller).
    2. Downloads the SBOM toolchain (Syft/Grype/Grant/Cosign) - latest releases.
    3. Snapshots the Grype vulnerability DB for offline use.
    4. Stages every artifact into the Tauri bundle layout.
    5. Builds the NSIS installer.

  The two heavy AI inputs cannot be produced by this script (they need a built
  llama.cpp + the model), so pass them in:
    -ModelGguf    the quantized GGUF  (e.g. astra-q8_0.gguf)
    -LlamaServer  llama-server.exe    (a llama.cpp Windows release)

.PARAMETER ModelGguf   Path to the GGUF model file (copied into the bundle as astra.gguf).
.PARAMETER ModelTier   Device tier the bundled model targets: low|mid|high (default mid = the
                       Apache Qwen2.5-Coder-7B-Instruct). Recorded/logged; the actual source file
                       is -ModelGguf (explicit wins). Mirrors server\scanner\rag\model_tiers.py.
.PARAMETER Edition     Product edition to build: community|pro|enterprise (default community). Picks
                       the model tier (community->low, pro->mid, enterprise->high) unless -ModelTier
                       is passed explicitly, and for paid editions bakes the entitlements public key.
.PARAMETER EntitlementsPublicKeyPath  Path to vendor_entitlements_public.pem (the Ed25519 PUBLIC
                       key). Required for -Edition pro|enterprise so the running app can verify a
                       vendor-signed entitlements.json. Defaults to $env:ENTITLEMENTS_PUBLIC_KEY_PATH.
.PARAMETER LlamaServer Path to llama-server.exe. Its sibling runtime DLLs (ggml*/llama*/mtmd/libomp)
                       are auto-staged into resources\llama-runtime so the bundled launcher can load.
.PARAMETER WebView2    Path to a fixed-version WebView2 runtime folder. Staged into BOTH the NSIS
                       installer's embed path (src-tauri\webview2) AND resources\webview2, so a raw
                       `tauri build --no-bundle` zip (this project's actual delivery mode, since the
                       full NSIS build is currently blocked by its 32-bit mmap limit on the model
                       file) is also self-contained -- main.rs points WEBVIEW2_BROWSER_EXECUTABLE_FOLDER
                       at resources\webview2 automatically, no target-machine install required.
.PARAMETER LicenseDays Days the build's offline licence lasts. Only baked in when given, or for
                       -Edition community (default 90); otherwise main.rs keeps its own default (the
                       client delivery's 30). Baked at COMPILE time, so changing it needs a new build.
.PARAMETER IconLogo    Square PNG used to generate app icons; defaults to client\public\CSlogo.png.
.PARAMETER SkipTools   Skip downloading the SBOM tools (use what's already staged).
.PARAMETER SigningCert Path to an Authenticode code-signing cert (.pfx). When set (and the SDK's
                       signtool is on PATH) the produced installer is signed; the .pfx password is
                       read from $env:WINDOWS_CERT_PASSWORD. Omit for an unsigned local build.

.EXAMPLE
  .\scripts\build_windows.ps1 `
     -ModelGguf .\ai-artifacts\astra-q8_0.gguf `
     -LlamaServer .\ai-artifacts\llama-server.exe `
     -IconLogo .\client\public\CSlogo.png
#>
[CmdletBinding()]
param(
  [string]$ModelGguf,
  [ValidateSet("low", "mid", "high")]
  [string]$ModelTier = "mid",
  [ValidateSet("community", "pro", "enterprise")]
  [string]$Edition = "community",
  [string]$EntitlementsPublicKeyPath = $env:ENTITLEMENTS_PUBLIC_KEY_PATH,
  [string]$LlamaServer,
  [string]$WebView2,
  [string]$LicenseDays,
  [string]$IconLogo,
  [switch]$SkipTools,
  [string]$SigningCert
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --------------------------------------------------------------------------- #
# Edition -> model tier + entitlements public key
# --------------------------------------------------------------------------- #
# The running edition is resolved by the backend from a build-embedded Ed25519
# public key (ENTITLEMENTS_PUBLIC_KEY) + DATA_DIR\entitlements.json; absent both
# it falls back to Community. This param wires the build side of that:
#   community  -> model tier low  (1.5B GGUF)
#   pro        -> model tier mid  (7B)
#   enterprise -> model tier high (14B)
# unless the caller pinned -ModelTier explicitly. Mirrors
# server\scanner\rag\model_tiers.py. $ModelTier is recorded/logged the same way
# it already was (the real model file is still whatever -ModelGguf points at).
if (-not $PSBoundParameters.ContainsKey('ModelTier')) {
  $ModelTier = @{ community = "low"; pro = "mid"; enterprise = "high" }[$Edition]
}
Write-Host "Edition: $Edition  (model tier: $ModelTier)"

# Paid editions need the entitlements public key baked in so the running app can
# verify a vendor-signed entitlements.json. Community expects no signed file.
if ($Edition -ne "community") {
  if (-not $EntitlementsPublicKeyPath -or -not (Test-Path $EntitlementsPublicKeyPath)) {
    throw "Edition '$Edition' requires -EntitlementsPublicKeyPath pointing at vendor_entitlements_public.pem (or set `$env:ENTITLEMENTS_PUBLIC_KEY_PATH)."
  }
  $env:ENTITLEMENTS_PUBLIC_KEY = Get-Content -Raw $EntitlementsPublicKeyPath
  Write-Host "Baked ENTITLEMENTS_PUBLIC_KEY from $EntitlementsPublicKeyPath"
}
# Consumed by the backend (settings.py: os.getenv("CODESENSE_EDITION")). These
# three vars (CODESENSE_EDITION, MODEL_TIER, ENTITLEMENTS_PUBLIC_KEY) are read at
# COMPILE time by client\src-tauri\src\main.rs (`option_env!`) and forwarded to
# the backend sidecar by spawn_backend via .env(), so `tauri build` below must run
# in this same process environment. They are baked per build: switching edition
# means re-running this script (cargo rebuilds the launcher when they change).
$env:CODESENSE_EDITION = $Edition
$env:MODEL_TIER = $ModelTier

# --------------------------------------------------------------------------- #
# Community installer: no model, no client-delivery trial/activation
# --------------------------------------------------------------------------- #
# These CS_* variables are read at COMPILE time by main.rs (option_env!) -- same mechanism as
# CODESENSE_EDITION above -- so they must be set in THIS process before `tauri build`. Unset =
# main.rs keeps its client-delivery defaults, so Pro / Enterprise builds are unchanged.
#   CS_NO_MODEL=1        no model reassembly, no llama-server, no "AI engine" tray item
#   CS_TRIAL_MODE=false  the 2-scan capped trial is a client-delivery setting, not for Community
#   CS_ACTIVATION_HASH=none  no activation-password gate on a public download
#   CS_LICENSE_DAYS      offline licence length (Community default 90)
#   CS_LICENSE_SCOPE=Community  the licence clock lives in HKCU\Software\CodeSense\Community, not the
#                        registry value every Code Sense build for this Windows user shares (where the
#                        earliest first_seen of ANY earlier build wins)
#   VITE_BUNDLES_MODEL=0 first-run screen stops talking about an AI model (read by `npm run build`)
$IsCommunity = ($Edition -eq "community")
if ($IsCommunity) {
  $env:CS_NO_MODEL = "1"
  $env:CS_TRIAL_MODE = "false"
  $env:CS_ACTIVATION_HASH = "none"
  $env:CS_LICENSE_SCOPE = "Community"
  $env:VITE_BUNDLES_MODEL = "0"
  if (-not $LicenseDays) { $LicenseDays = "90" }
  if ($ModelGguf -or $LlamaServer) {
    Write-Warning "Community ships no bundled model: -ModelGguf / -LlamaServer are ignored."
  }
} else {
  # A Community build earlier in this same PowerShell session must not leak into a paid build.
  foreach ($v in "CS_NO_MODEL", "CS_TRIAL_MODE", "CS_ACTIVATION_HASH", "CS_LICENSE_SCOPE", "VITE_BUNDLES_MODEL") {
    Remove-Item "Env:\$v" -ErrorAction SilentlyContinue
  }
  if (-not $LicenseDays) { Remove-Item Env:\CS_LICENSE_DAYS -ErrorAction SilentlyContinue }
}
if ($LicenseDays) {
  if ($LicenseDays -notmatch '^\d+$' -or [int]$LicenseDays -lt 1) { throw "-LicenseDays must be a positive whole number of days (got '$LicenseDays')." }
  $env:CS_LICENSE_DAYS = $LicenseDays
  Write-Host "Licence length baked into this build: $LicenseDays days"
}

# --------------------------------------------------------------------------- #
# Paths + helpers
# --------------------------------------------------------------------------- #
$RepoRoot   = Split-Path -Parent $PSScriptRoot
$Server     = Join-Path $RepoRoot "server"
$Client     = Join-Path $RepoRoot "client"
$Tauri      = Join-Path $Client "src-tauri"
$BinDir     = Join-Path $Tauri "binaries"
$ResTools   = Join-Path $Tauri "resources\tools"
$ResModel   = Join-Path $Tauri "resources\model"
$ResLlamaRt = Join-Path $Tauri "resources\llama-runtime"
$ResGrypeDb = Join-Path $Tauri "resources\grype-db"
$ResWebview2 = Join-Path $Tauri "resources\webview2"
# Keep in sync with GRYPE_DB_SCHEMA_VERSION in client\src-tauri\src\main.rs --
# see the grype-db snapshot step below for why this drifted once already.
$ExpectedGrypeSchema = "6"
# Pinned, not "latest": the bundler checks the cached NSIS toolset (%LOCALAPPDATA%\tauri\NSIS) against a
# hash baked into each CLI release and, on a mismatch, deletes and re-downloads it. CLI 2.12.3 did that to a
# toolset made by an older CLI and then died with "os error 4395" (a reparse point) while deleting it, so the
# build could not produce an installer at all. 2.11.4 accepts the existing toolset and produced the installer.
# Bump deliberately (and re-run a full build) rather than by whatever npx resolves that day.
$TauriCli = "@tauri-apps/cli@2.11.4"
$Wv2Dir     = Join-Path $Tauri "webview2"

function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Die($m)  { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

function Assert-Cmd($name, $hint) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Die "Required tool '$name' not found on PATH. $hint"
  }
}

function Ensure-Dir($p) { if (-not (Test-Path $p)) { New-Item -ItemType Directory -Force -Path $p | Out-Null } }

# Run a native command and stop the build if it returns a non-zero exit code
# ($ErrorActionPreference='Stop' does NOT catch native exit codes).
function Invoke-Native([scriptblock]$Cmd, [string]$What) {
  & $Cmd
  if ($LASTEXITCODE -ne 0) { Die "$What failed (exit code $LASTEXITCODE)." }
}

# --------------------------------------------------------------------------- #
# 0. Prerequisites
# --------------------------------------------------------------------------- #
Info "Checking prerequisites"
Assert-Cmd python "Install Python 3.11+ from python.org (add to PATH)."
Assert-Cmd npm    "Install Node.js LTS from nodejs.org."
Assert-Cmd cargo  "Install Rust from rustup.rs."
Assert-Cmd rustc  "Install Rust from rustup.rs."
$hostLine = (& rustc -Vv | Select-String '^host:' | Select-Object -First 1)
if (-not $hostLine) { Die "Could not determine the Rust host triple from 'rustc -Vv'." }
$Triple = $hostLine.ToString().Split(' ')[-1].Trim()
Ok "Rust target triple: $Triple"
Ensure-Dir $BinDir; Ensure-Dir $ResTools; Ensure-Dir $ResModel; Ensure-Dir $ResLlamaRt; Ensure-Dir $ResGrypeDb

# --------------------------------------------------------------------------- #
# 1. Backend -> codesense-server.exe (PyInstaller)
# --------------------------------------------------------------------------- #
Info "Building backend executable (PyInstaller)"
Push-Location $Server
try {
  if (-not (Test-Path ".venv")) { Invoke-Native { python -m venv .venv } "venv creation" }
  Invoke-Native { & .\.venv\Scripts\python.exe -m pip install --upgrade pip --quiet } "pip upgrade"
  Invoke-Native { & .\.venv\Scripts\pip.exe install -r requirements.txt pyinstaller --quiet } "pip install"
  # Goes through the interpreter (`python -m PyInstaller`) rather than the
  # standalone pyinstaller.exe entry-point stub. That stub is a tiny
  # pip-generated native launcher (same category as llama-server.exe's thin
  # launcher) and was found silently crashing on this host with zero
  # output/no error message, just a bad exit code -- `python -m PyInstaller`
  # runs the identical underlying code without depending on that fragile
  # stub, and reliably works.
  Invoke-Native { & .\.venv\Scripts\python.exe -m PyInstaller codesense.spec --noconfirm --clean } "PyInstaller"
  $built = Join-Path $Server "dist\codesense-server.exe"
  if (-not (Test-Path $built)) { Die "PyInstaller did not produce dist\codesense-server.exe" }
  Copy-Item $built (Join-Path $BinDir "codesense-server-$Triple.exe") -Force
  Ok "codesense-server-$Triple.exe staged"
} finally { Pop-Location }

# --------------------------------------------------------------------------- #
# 2. llama-server (provided)
# --------------------------------------------------------------------------- #
if ($IsCommunity) {
  # Community has no local AI engine. Clear anything an earlier non-Community build left in the
  # staging folders so it can never be bundled by accident (the overlay config also drops it).
  Info "Community build: no llama-server (clearing any stale AI-engine staging)"
  Get-ChildItem $ResLlamaRt -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
  Get-ChildItem $BinDir -Filter "llama-server*" -Force -ErrorAction SilentlyContinue | Remove-Item -Force
} else {
Info "Staging llama-server"
if (-not $LlamaServer -or -not (Test-Path $LlamaServer)) {
  Die "Pass -LlamaServer <path to llama-server.exe> (download from a llama.cpp release)."
}
Copy-Item $LlamaServer (Join-Path $BinDir "llama-server-$Triple.exe") -Force
Ok "llama-server-$Triple.exe staged"

# A shared-library llama.cpp build ships llama-server.exe as a thin launcher that
# dynamically links its runtime DLLs (llama-server-impl.dll, llama.dll,
# llama-common.dll, ggml*.dll, mtmd.dll, libomp*). Stage every *.dll sitting beside
# llama-server.exe into resources\llama-runtime as a BUILD-TIME staging location;
# tauri.conf.json's `bundle.resources` then maps resources/llama-runtime/*.dll to
# target "" (empty = $RESOURCES root), and on Windows $RESOURCES IS the directory
# Tauri installs the sidecar exe into — so at install time the DLLs land beside
# llama-server.exe, which is what its default DLL search order actually checks.
# (An earlier attempt kept the DLLs nested under resources\llama-runtime\ at
# install time and tried to compensate with a child-process PATH prepend in
# main.rs::spawn_llama; that was proven insufficient — the loader never found
# them. The tauri.conf.json remap is the real fix; this staging step is unchanged.)
# A single-file static build has no sibling DLLs and this simply stages nothing.
$LlamaSrcDir = Split-Path -Parent (Resolve-Path $LlamaServer)
$llamaDlls = @(Get-ChildItem -Path $LlamaSrcDir -Filter *.dll -File -ErrorAction SilentlyContinue)
if ($llamaDlls.Count -gt 0) {
  foreach ($dll in $llamaDlls) { Copy-Item $dll.FullName (Join-Path $ResLlamaRt $dll.Name) -Force }
  Ok "$($llamaDlls.Count) llama runtime DLL(s) staged into resources\llama-runtime"
} else {
  Info "No sibling DLLs next to llama-server.exe (assuming a static build)."
}
}   # end: not Community

# llama-server.exe (and codesense.exe / codesense-server.exe, which end up in
# the same install/extraction directory) are MSVC-linked and depend on the
# Visual C++ redistributable (vcruntime140.dll etc.) at the OS level -- NOT
# part of the llama.cpp release download above, so the loop just above never
# stages it. This build host has the redistributable installed (that's why a
# local run of the app never surfaces this), but a clean target machine may
# not: on 2026-08-11 a client's Azure VM failed to launch llama-server.exe
# with "VCRUNTIME140.dll was not found" -- silent-looking crash, no error
# surfaced anywhere. Copy the actual DLLs from this host's System32 into the
# same resources\llama-runtime staging dir (same install-time destination as
# the llama DLLs above, next to every bundled .exe) so the package is
# self-contained regardless of what's on the target machine.
Info "Staging VC++ runtime DLLs (target machines may not have the redistributable installed)"
$vcDlls = @("vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll")
$vcStaged = 0
foreach ($name in $vcDlls) {
  $src = Join-Path "$env:WINDIR\System32" $name
  if (Test-Path $src) {
    Copy-Item $src (Join-Path $ResLlamaRt $name) -Force
    $vcStaged++
  } else {
    Write-Warning "VC++ runtime DLL not found on this build host: $src -- packaged app may fail on a machine without the redistributable."
  }
}
if ($vcStaged -gt 0) { Ok "$vcStaged VC++ runtime DLL(s) staged into resources\llama-runtime" }

# --------------------------------------------------------------------------- #
# 3. Model GGUF (provided)
# --------------------------------------------------------------------------- #
if ($IsCommunity) {
  Info "Community build: no bundled model (clearing any stale model staging)"
  Get-ChildItem $ResModel -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
} else {
Info "Staging model GGUF (tier: $ModelTier)"
if (-not $ModelGguf -or -not (Test-Path $ModelGguf)) {
  Die "Pass -ModelGguf <path to the .gguf model> (see scripts/offline_ai/). Target tier '$ModelTier' (mid = Apache 7B-Instruct)."
}
Copy-Item $ModelGguf (Join-Path $ResModel "astra.gguf") -Force
$gb = [math]::Round((Get-Item $ModelGguf).Length / 1GB, 2)
Ok "model ($ModelTier tier, $gb GB) staged as resources\model\astra.gguf"

Info "Splitting model into <2GB parts (NSIS/MSI installer size workaround)"
& (Join-Path $PSScriptRoot "split_asset.ps1") -Path (Join-Path $ResModel "astra.gguf")
Ok "model split into parts + manifest.json in resources\model"
}   # end: not Community

# --------------------------------------------------------------------------- #
# 4. SBOM tools (Syft / Grype / Grant / Cosign) - latest releases via GitHub API
# --------------------------------------------------------------------------- #
if (-not $SkipTools) {
  Info "Downloading SBOM tools (latest windows_amd64 releases)"
  $tmp = Join-Path $env:TEMP ("cs-tools-" + [guid]::NewGuid())
  Ensure-Dir $tmp

  function Get-GhAsset($repo, $pattern, $outFile) {
    # Resolve the latest release and download the asset whose name matches $pattern.
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" `
                             -Headers @{ "User-Agent" = "codesense-build" } -UseBasicParsing
    $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $asset) { Die "No asset matching '$pattern' in latest $repo release ($($rel.tag_name))." }
    Ok "$repo $($rel.tag_name) -> $($asset.name)"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $outFile -UseBasicParsing
  }

  foreach ($tool in @("syft", "grype")) {
    $zip = Join-Path $tmp "$tool.zip"
    Get-GhAsset "anchore/$tool" "_windows_amd64\.zip$" $zip
    Expand-Archive -Path $zip -DestinationPath (Join-Path $tmp $tool) -Force
    Copy-Item (Join-Path (Join-Path $tmp $tool) "$tool.exe") (Join-Path $ResTools "$tool.exe") -Force
  }
  Get-GhAsset "sigstore/cosign" "cosign-windows-amd64\.exe$" (Join-Path $ResTools "cosign.exe")

  # anchore/grant publishes no Windows release asset at all (confirmed against
  # the live v0.6.8 release -- only darwin/linux/deb/rpm), so it can't be
  # fetched like syft/grype/cosign above; a real run of the old all-in-one
  # loop would Die here. Build it from source instead.
  #
  # Pinned to v0.5.7, not "latest": v0.6.8's go.mod needs go >=1.26.3 (forces
  # a toolchain auto-download) and vendors syft as a library (~150+
  # transitive deps incl. AWS/GCP SDKs); v0.5.7 only needs go 1.24.6 and has
  # a far smaller graph. CGO_ENABLED=0: grant's sqlite driver is the pure-Go
  # modernc.org/sqlite, so it doesn't actually need cgo -- important on hosts
  # where the cgo/gcc toolchain itself is broken (even a trivial hello-world
  # cgo build fails on some of these). Only bump the version pin after
  # confirming `CGO_ENABLED=0 go build ./cmd/grant` succeeds on the actual
  # build host first.
  Assert-Cmd git "Install Git for Windows."
  Assert-Cmd go  "Install Go from go.dev (needed to build grant from source -- anchore/grant ships no Windows binary)."
  $GrantVersion = "v0.5.7"
  $grantSrc = Join-Path $tmp "grant-src"
  Invoke-Native { git clone --depth 1 --branch $GrantVersion https://github.com/anchore/grant.git $grantSrc } "grant clone"
  Push-Location $grantSrc
  try {
    $env:CGO_ENABLED = "0"
    Invoke-Native { go build -o (Join-Path $ResTools "grant.exe") ./cmd/grant } "grant build"
  } finally {
    Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
  }
  Ok "grant $GrantVersion built from source -> resources\tools\grant.exe"

  # OpenGrep (OSS Semgrep fork) — a single-file native binary, staged as
  # semgrep.exe (the launcher sets SEMGREP_BIN to <tools>\semgrep). Pinned to
  # match the macOS build (scripts/offline_sbom/fetch_offline_tools.sh) so both
  # platforms ship the same detector. The real Windows asset is
  # opengrep_windows_x86.exe (NOT _x86_64); a failed fetch is FATAL because an
  # app with no SAST engine detects nothing.
  $OpengrepVersion = "1.22.0"
  $ogUrl = "https://github.com/opengrep/opengrep/releases/download/v$OpengrepVersion/opengrep_windows_x86.exe"
  $ogOut = Join-Path $ResTools "semgrep.exe"
  Invoke-WebRequest -Uri $ogUrl -OutFile $ogOut -UseBasicParsing
  $ogSize = (Get-Item $ogOut).Length
  if ($ogSize -lt 1000000) {
    throw "Staged OpenGrep is only $ogSize bytes (<1MB) — fetch failed or wrong asset ($ogUrl). Verify at https://github.com/opengrep/opengrep/releases"
  }
  Ok "opengrep $OpengrepVersion staged as resources\tools\semgrep.exe ($ogSize bytes)"

  Remove-Item $tmp -Recurse -Force
  Ok "syft/grype/grant/cosign/semgrep staged in resources\tools"
} else { Info "Skipping SBOM tool download (-SkipTools)" }

# --------------------------------------------------------------------------- #
# 5. Grype DB snapshot (offline)
# --------------------------------------------------------------------------- #
Info "Snapshotting Grype vulnerability DB"
$grypeExe = Join-Path $ResTools "grype.exe"
if (Test-Path $grypeExe) {
  # Wipe any stale snapshot from a previous build FIRST. grype's DB cache is
  # schema-versioned (resources\grype-db\<N>\vulnerability.db, N = whatever
  # `grype version` reports as "Supported DB Schema" -- this has been 5, is
  # now 6, and will presumably keep moving). A stale directory left over from
  # an older grype binary doesn't get overwritten by a newer `db update`; it
  # just sits there unused while the old split parts below it keep getting
  # silently re-bundled build after build. Confirmed on 2026-08-11: a
  # leftover schema-5 snapshot from ~March caused every SBOM scan to report
  # 0 vulnerabilities with no error anywhere, while `db update` had actually
  # (correctly) fetched a fresh schema-6 DB alongside it that nothing ever
  # looked at.
  Remove-Item $ResGrypeDb -Recurse -Force -ErrorAction SilentlyContinue
  Ensure-Dir $ResGrypeDb
  $env:GRYPE_DB_CACHE_DIR = $ResGrypeDb
  & $grypeExe db update
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "grype db update returned $LASTEXITCODE; the bundled CVE DB may be empty/stale."
  } else {
    # grype writes into its OWN schema-numbered subdirectory: resources\grype-db\<schema>\.
    # That nesting is right for GRYPE_DB_CACHE_DIR at RUNTIME, but the bundle/reassembly
    # layout (asset_reassembly.rs::copy_companion_files) expects everything FLAT directly
    # under resources\grype-db\ -- it only copies top-level files, doesn't recurse into
    # subdirectories, and reassembles vulnerability.db back to <data_dir>\grype-db\<schema>\
    # itself (main.rs's GRYPE_DB_SCHEMA_VERSION supplies that nesting at the destination).
    # So: pull everything up out of the schema subdirectory before splitting.
    #
    # Don't hardcode the schema number -- it has already changed once (5 -> 6, 2026-08).
    $schemaDir = Get-ChildItem $ResGrypeDb -Directory -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match '^\d+$' } | Sort-Object { [int]$_.Name } -Descending |
                 Select-Object -First 1
    if ($schemaDir) {
      if ($schemaDir.Name -ne $ExpectedGrypeSchema) {
        Write-Warning "Fetched Grype DB schema $($schemaDir.Name), but main.rs's GRYPE_DB_SCHEMA_VERSION is hardcoded '$ExpectedGrypeSchema' -- update that constant (and `$ExpectedGrypeSchema` above) to match, or reassembly will write to the wrong directory at runtime."
      }
      Get-ChildItem $schemaDir.FullName -File | ForEach-Object {
        Move-Item $_.FullName (Join-Path $ResGrypeDb $_.Name) -Force
      }
      Remove-Item $schemaDir.FullName -Recurse -Force
    }
    $vulnDb = Join-Path $ResGrypeDb "vulnerability.db"
    if (Test-Path $vulnDb) {
      Ok "Grype DB snapshot (schema $($schemaDir.Name)) staged flat in resources\grype-db (frozen; AUTO_UPDATE off at runtime)"
      Info "Splitting vulnerability.db into <2GB parts (NSIS/MSI installer size workaround)"
      # Community ships through NSIS, which cannot package more than ~1.9 GB of data in total (32-bit
      # mmap: "error mmapping file ... out of range"). The DB is ~3 GB but gzips ~8x, so compress it
      # and let the launcher expand it on first launch. Other editions keep today's plain parts.
      $splitArgs = @{ Path = $vulnDb }
      if ($IsCommunity) { $splitArgs.Compress = $true }
      & (Join-Path $PSScriptRoot "split_asset.ps1") @splitArgs
      Ok "vulnerability.db split into parts + manifest.json in resources\grype-db$(if ($IsCommunity) { ' (gzip-compressed)' })"
    } else {
      Write-Warning "vulnerability.db not found at $vulnDb after db update; skipping split."
    }
  }
} else {
  Write-Warning "grype.exe not staged; skipping DB snapshot. Re-run without -SkipTools."
}

# --------------------------------------------------------------------------- #
# 5b. Semgrep rule packs (offline)
# --------------------------------------------------------------------------- #
# The launcher points SEMGREP_RULES_DIR (= `semgrep --config`) at this dir's
# ROOT. Semgrep aborts the whole scan with rc=7 ("invalid configuration file
# found") if --config loads any YAML lacking a top-level `rules:` key, and the
# upstream repo ships many (.pre-commit-config.yaml, CI workflows, nested
# *.test.yaml fixtures). The staging helper clones semgrep-rules and keeps only
# loadable rule files, leaving a valid --config target. Non-fatal on failure
# (the scan then finds nothing until rules are staged), matching the Grype DB
# step; needs git + network on the build host. Guarded by
# scripts\offline_sbom\tests\test_stage_semgrep_rules.py.
Info "Bundling Semgrep rule packs"
$RulesDir   = Join-Path $Tauri "resources\semgrep-rules"
$StageRules = Join-Path $PSScriptRoot "offline_sbom\stage_semgrep_rules.py"
& python $StageRules $RulesDir
if ($LASTEXITCODE -ne 0) {
  Write-Warning "semgrep-rules staging failed (needs git + network on the build host); the packaged scan will find nothing until rules are staged."
}

# --------------------------------------------------------------------------- #
# 6. WebView2 fixed runtime + icons
# --------------------------------------------------------------------------- #
if ($IsCommunity) {
  # Community uses the small embedded WebView2 bootstrapper (tauri.community.conf.json); make sure a
  # fixed runtime left by an earlier Pro / client build cannot be bundled and bloat the installer.
  if ($WebView2) { Write-Warning "Community uses the WebView2 bootstrapper: -WebView2 is ignored." }
  Remove-Item $Wv2Dir, $ResWebview2 -Recurse -Force -ErrorAction SilentlyContinue
} elseif ($WebView2 -and (Test-Path $WebView2)) {
  Info "Staging fixed-version WebView2 runtime"
  Ensure-Dir $Wv2Dir
  Copy-Item (Join-Path $WebView2 "*") $Wv2Dir -Recurse -Force
  Ok "WebView2 runtime staged (NSIS installer path: src-tauri\webview2)"

  # ALSO stage a copy into resources\webview2 -- tauri.conf.json's
  # "resources": ["resources/**/*"] glob picks this up automatically, so it
  # travels with a raw `tauri build --no-bundle` extraction too, not just an
  # NSIS installer. This matters because the NSIS installer currently can't
  # even be produced for a full build (its 32-bit makensis can't mmap the
  # ~4.68GB model file, see W11 handoff notes) -- every real client delivery
  # so far has therefore been the raw --no-bundle zip, which previously had
  # NO WebView2 runtime bundled at all and silently depended on the target
  # machine already having one (most Windows Server images don't). main.rs
  # points WEBVIEW2_BROWSER_EXECUTABLE_FOLDER at this exact resources\webview2
  # directory at startup, so this is fully self-contained either way.
  Ensure-Dir $ResWebview2
  Copy-Item (Join-Path $WebView2 "*") $ResWebview2 -Recurse -Force
  Ok "WebView2 runtime also staged into resources\webview2 (self-contained raw-zip path)"
}

# Default the icon source to a bundled logo so the Tauri build isn't blocked.
if (-not $IconLogo) {
  foreach ($cand in @("client\public\CSlogo.png", "client\public\logoCS.png")) {
    $p = Join-Path $RepoRoot $cand
    if (Test-Path $p) { $IconLogo = $p; break }
  }
}
if ($IconLogo -and (Test-Path $IconLogo)) {
  Info "Generating app icons from $IconLogo"
  Push-Location $Client
  try { Invoke-Native { npx --yes $TauriCli icon $IconLogo } "Tauri icon generation" }
  finally { Pop-Location }
  Ok "Icons generated into src-tauri\icons"
} else {
  Write-Warning "No icon source found; the Tauri build needs src-tauri\icons. Pass -IconLogo <square PNG>."
}

# --------------------------------------------------------------------------- #
# 7. Fail fast if WebView2 fixed runtime is required but missing
# --------------------------------------------------------------------------- #
$wv2HasFiles = (Test-Path $Wv2Dir) -and (@(Get-ChildItem $Wv2Dir -Force -ErrorAction SilentlyContinue).Count -gt 0)
$confJson = Join-Path $Tauri "tauri.conf.json"
if (-not $IsCommunity -and -not $wv2HasFiles -and (Test-Path $confJson) -and (Select-String -Path $confJson -Pattern 'fixedRuntime' -Quiet)) {
  Write-Host "ERROR: tauri.conf.json requests a FIXED WebView2 runtime but src-tauri\webview2\ is empty." -ForegroundColor Red
  Write-Host "  Offline installer: re-run with -WebView2 <fixed-version-runtime-folder>" -ForegroundColor Yellow
  Write-Host "  Online installer : set webviewInstallMode.type to 'downloadBootstrapper' in" -ForegroundColor Yellow
  Write-Host "                     client\src-tauri\tauri.conf.json (and remove the 'path' line)." -ForegroundColor Yellow
  exit 1
}

# --------------------------------------------------------------------------- #
# 8. Frontend + Tauri installer
# --------------------------------------------------------------------------- #
Info "Building the Tauri installer (this compiles Rust + bundles - can take several minutes)"
Push-Location $Client
try {
  Invoke-Native { npm install } "npm install"
  # Community: merge the overlay (own name/identifier, no model resource, WebView2 bootstrapper).
  $tauriArgs = @()
  if ($IsCommunity) { $tauriArgs += @("--config", "src-tauri/tauri.community.conf.json") }
  # The CLI is fetched by npx (not pinned in package.json): record exactly which one built this.
  Info ("Tauri CLI: " + ((& npx --yes $TauriCli --version) -join " "))
  Invoke-Native { npx --yes $TauriCli build @tauriArgs } "Tauri build"
} finally { Pop-Location }

$bundle = Join-Path $Tauri "target\release\bundle\nsis"
$installers = @()
if (Test-Path $bundle) {
  $installers = @(Get-ChildItem $bundle -Filter *.exe -File)
}

# --------------------------------------------------------------------------- #
# 9. Authenticode sign the installer (only when a cert is supplied)
# --------------------------------------------------------------------------- #
# Mirrors the macOS APPLE_SIGNING_IDENTITY gate: with no cert this is a no-op +
# warning, so an unsigned local/CI build still completes. signtool ships with the
# Windows SDK; it is usually not on PATH, so fall back to the newest copy under
# Program Files. Password comes from $env:WINDOWS_CERT_PASSWORD (never a param, so
# it stays out of the process table / history).
function Find-SignTool {
  $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $roots = @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin")
  foreach ($root in $roots) {
    if (Test-Path $root) {
      $found = Get-ChildItem $root -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match '\\x64\\' } |
               Sort-Object FullName -Descending | Select-Object -First 1
      if ($found) { return $found.FullName }
    }
  }
  return $null
}

if ($SigningCert) {
  Info "Signing the installer (Authenticode)"
  if (-not (Test-Path $SigningCert)) { Die "Signing cert not found: $SigningCert" }
  if ($installers.Count -eq 0) { Die "No installer to sign (NSIS bundle missing)." }
  $signtool = Find-SignTool
  if (-not $signtool) { Die "signtool.exe not found. Install the Windows 10/11 SDK (Signing Tools)." }
  if (-not $env:WINDOWS_CERT_PASSWORD) {
    Write-Warning "WINDOWS_CERT_PASSWORD not set; signtool will prompt or fail for a password-protected .pfx."
  }
  foreach ($inst in $installers) {
    $signArgs = @("sign", "/fd", "SHA256", "/tr", "http://timestamp.digicert.com", "/td", "SHA256",
                  "/f", $SigningCert)
    if ($env:WINDOWS_CERT_PASSWORD) { $signArgs += @("/p", $env:WINDOWS_CERT_PASSWORD) }
    $signArgs += $inst.FullName
    Invoke-Native { & $signtool @signArgs } "signtool sign $($inst.Name)"
    Invoke-Native { & $signtool verify /pa $inst.FullName } "signtool verify $($inst.Name)"
    Ok "Signed + verified: $($inst.Name)"
  }
} else {
  Write-Warning "No -SigningCert supplied: installer is UNSIGNED. SmartScreen will warn users on first run."
}

# --------------------------------------------------------------------------- #
# 10. Report
# --------------------------------------------------------------------------- #
Info "Build complete"
if ($installers.Count -gt 0) {
  foreach ($inst in $installers) {
    $sizeMb = [math]::Round($inst.Length / 1MB, 1)
    Ok "Installer: $($inst.FullName) ($sizeMb MB)"
  }
  # SHA-256 of what was built (after signing, if any), written beside the installer so it can be
  # published next to the download and users can verify what they got.
  $sumLines = foreach ($inst in $installers) {
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 -LiteralPath $inst.FullName).Hash.ToLower(), $inst.Name
  }
  $sumFile = Join-Path $bundle "SHA256SUMS.txt"
  [System.IO.File]::WriteAllText($sumFile, (($sumLines -join "`n") + "`n"))
  Ok "SHA-256 written to $sumFile"
  $sumLines | ForEach-Object { Write-Host "    $_" }
} else {
  Write-Warning "NSIS bundle dir not found at $bundle - check the Tauri build output above."
}
