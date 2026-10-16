// Code Sense desktop shell (Tauri v2).
//
// Owns two sidecars and the app lifecycle:
//   * codesense-server  — the Django backend (PyInstaller-frozen, served by waitress) on 127.0.0.1:8585
//   * llama-server      — llama.cpp serving the quantized GGUF on 127.0.0.1:8001
// Tray menu: Open / Pause AI engine (frees the model's RAM) / Quit. Closing the
// window hides to tray so background scans keep running; Quit tears down both
// sidecars cleanly so no orphan processes or held ports remain.
//
// Both sidecars depend on two large bundled assets (the GGUF model and the
// grype vulnerability DB) that ship as build-time-split `.partNNN` shards
// (see scripts/split_asset.ps1) because both NSIS and MSI reject single
// files over ~2GB. `asset_reassembly` streams them back together into a
// writable per-user directory before either sidecar spawns — see
// docs/superpowers/specs/2026-07-14-first-run-asset-reassembly-design.md.
//
// SCAFFOLD: this is NOT compiled in the CI sandbox (no Rust/Tauri/WebView2).
// Validate with `cargo tauri build` on a Windows host once binaries/, resources/,
// webview2/, and icons/ are populated (see README.md). Minor Tauri 2.x API
// details may need adjusting against the exact crate versions resolved.
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

mod asset_reassembly;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    path::BaseDirectory,
    tray::TrayIconBuilder,
    Emitter, Manager, RunEvent, WindowEvent,
};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

use asset_reassembly::{ensure_ready, ReassemblyError, GRYPE_DB_ASSET, MODEL_ASSET};

const BACKEND_PORT: &str = "8585";
const LLAMA_PORT: &str = "8001";
// Baked into this build rather than left to the backend's own 90-day default
// (settings.py::LICENSE_DURATION_DAYS) so a given client delivery has a fixed,
// self-contained license period with no separate setup step required on their
// machine. Note: this value is NOT part of the HMAC-signed license record
// (only first_seen/last_seen are) -- it only stops casual clock/env editing,
// per offline_license.py's documented threat model, not a determined user.
// This is the DEFAULT (the client delivery); a build overrides it with the
// build-time env CS_LICENSE_DAYS (see `baked` / `license_duration_days` below).
const DEFAULT_LICENSE_DURATION_DAYS: &str = "30";
// Where the licence clock's OS-level copy lives (offline_license.py::_scope): the registry
// value / plist is outside the data dir, so it survives uninstalls and is shared by every
// build run by the same OS user. Empty (the DEFAULT) keeps that shared legacy location, so
// client deliveries and Pro are unchanged. The Community installer sets build-time env
// CS_LICENSE_SCOPE=Community so a public download never inherits the date an earlier
// build left behind (earliest first_seen wins), nor leaves one for the next.
const DEFAULT_LICENSE_SCOPE: &str = "";
// Cosign encrypts the SBOM-signing private key with this passphrase at
// generation time and needs the identical value again to decrypt it for every
// later sign-blob call, so it must be a fixed baked-in constant, not left
// unset -- cosign otherwise blocks on an interactive password prompt with no
// stdin attached to answer it. Same offline-signing threat model as
// LICENSE_DURATION_DAYS above: this only needs to be consistent across runs
// of THIS build, not secret.
const COSIGN_PASSWORD: &str = "codesense-offline-sbom-signing";
// Grype's own DB cache layout is `<GRYPE_DB_CACHE_DIR>/<schemaVersion>/vulnerability.db`
// (it appends this subdirectory itself when reading -- confirmed via `grype.exe`'s own
// error message, "database metadata not found: <dir>/5", when it's missing).
// Reassembling straight into GRYPE_DB_CACHE_DIR (flat, no subdirectory) -- which every
// prior build did -- means grype can never find a valid DB there: it fails to load and
// every SBOM scan silently reports zero vulnerabilities (license findings still work,
// since those come from syft, not grype) with no error surfaced anywhere in the app.
//
// This version number is NOT stable across grype releases -- it moved 5 -> 6 sometime
// before 2026-08 (grype 0.117.0 "Supported DB Schema: 6"). A stale schema-5 snapshot
// left over from an older build_windows.ps1 run silently kept getting rebundled build
// after build (never overwritten by a newer `db update`, which fetches into its OWN
// schema-numbered subdirectory alongside the old one) -- same silent-zero-findings
// failure mode as the flat-vs-nested bug above, just one layer further out. Keep this
// in sync with build_windows.ps1's $ExpectedGrypeSchema; that script now warns if the
// grype binary it just fetched reports a different schema than this constant expects.
const GRYPE_DB_SCHEMA_VERSION: &str = "6";
// Trial mode (licenses/services/trial.py) is off by default -- normal builds
// are unlimited. This particular client delivery is a capped trial: 2
// successful scans total (code + SBOM share one counter), then a 403 on any
// further scan attempt until they contact us to upgrade. Same per-delivery
// pattern as LICENSE_DURATION_DAYS above -- edit these two constants for a
// different trial size, or set TRIAL_MODE to "false" for an unlimited build.
// These are the DEFAULTS (the client delivery); a build overrides them with the
// build-time env CS_TRIAL_MODE / CS_TRIAL_SCAN_LIMIT (the Community installer
// turns the trial off and relies on the edition's own limits instead).
const DEFAULT_TRIAL_MODE: &str = "true";
const DEFAULT_TRIAL_SCAN_LIMIT: &str = "2";
// One-time activation gate (licenses/services/activation.py). A bcrypt hash
// of the activation password -- the plaintext is never baked in and never
// given to the client; only whoever deploys this build types it once, on
// the client's own machine, during setup. Until that happens every API
// route is blocked. Leave empty ("") to ship a build with no activation gate
// at all (e.g. for internal/ISec review builds).
// This is the DEFAULT (the client delivery); a build overrides it with the
// build-time env CS_ACTIVATION_HASH ("none" = no activation gate, which is how
// the Community installer ships so a public download is not locked behind a
// password nobody has).
const DEFAULT_ACTIVATION_PASSWORD_HASH: &str = "$2b$12$eMkfluHrQQnkUJt7y2DBOeokxmBovGdFIjVZ2B20mJVUeLuncfnPm";
// Edition wiring (docs/EDITIONS.md, licenses/services/entitlements.py). Same
// build-injected pattern as the constants above: scripts/build_windows.ps1
// (-Edition / -EntitlementsPublicKeyPath) and scripts/build_macos.sh export
// these into the build environment and `option_env!` bakes them into the
// binary, so the sidecar sees them without any setup on the client's machine.
// Unset at build time => the launcher still forwards CODESENSE_EDITION=community
// explicitly (see `edition_env`), so a stray CODESENSE_EDITION in the client's
// own shell environment cannot upgrade a Community build.
const BUILD_EDITION: Option<&str> = option_env!("CODESENSE_EDITION");
const BUILD_ENTITLEMENTS_PUBLIC_KEY: Option<&str> = option_env!("ENTITLEMENTS_PUBLIC_KEY");
const BUILD_MODEL_TIER: Option<&str> = option_env!("MODEL_TIER");

/// Resolves a per-delivery setting from its build-time override. Pure so it is unit-tested.
/// * unset            -> `default` (so existing client-delivery builds are unchanged);
/// * "none" (any case) -> "" (the only way to express "empty": PowerShell drops an env var
///   set to an empty string, see scripts/run_dev.ps1);
/// * anything else    -> that value, trimmed.
fn baked(build_env: Option<&'static str>, default: &'static str) -> &'static str {
    match build_env {
        None => default,
        Some(v) if v.trim().eq_ignore_ascii_case("none") => "",
        Some(v) => v.trim(),
    }
}

fn license_duration_days() -> &'static str {
    baked(option_env!("CS_LICENSE_DAYS"), DEFAULT_LICENSE_DURATION_DAYS)
}
fn license_scope() -> &'static str {
    baked(option_env!("CS_LICENSE_SCOPE"), DEFAULT_LICENSE_SCOPE)
}
fn trial_mode() -> &'static str {
    baked(option_env!("CS_TRIAL_MODE"), DEFAULT_TRIAL_MODE)
}
fn trial_scan_limit() -> &'static str {
    baked(option_env!("CS_TRIAL_SCAN_LIMIT"), DEFAULT_TRIAL_SCAN_LIMIT)
}
fn activation_password_hash() -> &'static str {
    baked(option_env!("CS_ACTIVATION_HASH"), DEFAULT_ACTIVATION_PASSWORD_HASH)
}

/// Whether this build bundles the local AI model + llama-server (Pro / Enterprise and the
/// client delivery). The Community installer sets CS_NO_MODEL=1: no model is unpacked on
/// first launch, no llama-server is started, and the "AI engine" tray item is absent. The
/// user's own LLM (Settings > AI verification) is the Community AI path. Pure so it is tested.
fn bundles_model_for(no_model_flag: Option<&str>) -> bool {
    !matches!(no_model_flag.map(str::trim), Some("1"))
}
fn bundles_model() -> bool {
    bundles_model_for(option_env!("CS_NO_MODEL"))
}

/// Env vars that tell the backend which edition it is. Pure so it is unit-tested.
///
/// * `CODESENSE_EDITION` is ALWAYS emitted. An unknown / empty value is coerced
///   to `community` (the backend would resolve it there anyway) so the sidecar
///   never inherits the user's ambient `CODESENSE_EDITION` -- the sidecar
///   process inherits the launcher's environment by default.
/// * `ENTITLEMENTS_PUBLIC_KEY` (PEM, multi-line) is emitted only when baked in;
///   its presence is what switches the backend to signature-verified
///   `entitlements.json` (source = "signed", per-customer overrides apply).
/// * `MODEL_TIER` is emitted only when it is one of low|mid|high; the backend
///   takes min(edition tier, MODEL_TIER).
fn edition_env(
    edition: Option<&str>,
    public_key: Option<&str>,
    model_tier: Option<&str>,
) -> Vec<(&'static str, String)> {
    let edition = edition.map(|e| e.trim().to_ascii_lowercase());
    let edition = match edition.as_deref() {
        Some(e @ ("community" | "pro" | "enterprise")) => e,
        _ => "community",
    };
    let mut vars = vec![("CODESENSE_EDITION", edition.to_string())];
    if let Some(pem) = public_key.map(str::trim).filter(|p| !p.is_empty()) {
        vars.push(("ENTITLEMENTS_PUBLIC_KEY", pem.to_string()));
    }
    if let Some(tier) = model_tier.map(|t| t.trim().to_ascii_lowercase()) {
        if matches!(tier.as_str(), "low" | "mid" | "high") {
            vars.push(("MODEL_TIER", tier));
        }
    }
    vars
}

/// Windows Job Object wired with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: every
/// process assigned to it is force-killed by the OS the instant the job's
/// last handle closes. Windows closes all of a process's handles
/// unconditionally on exit -- crash, Task Manager "End Task", a debugger
/// stopping it, a logoff, anything -- so this is what guarantees the
/// codesense-server/llama-server sidecars can never outlive this process as
/// orphans, unlike `shutdown()` below which only runs on a *clean* exit path
/// (tray Quit / ExitRequested) and does nothing if the parent dies abruptly.
#[cfg(target_os = "windows")]
mod win_job {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

    pub struct JobGuard(HANDLE);

    // The handle is only ever read (assign/close), never mutated concurrently
    // in a way that needs synchronization beyond what the OS itself provides.
    unsafe impl Send for JobGuard {}
    unsafe impl Sync for JobGuard {}

    impl JobGuard {
        pub fn new() -> Option<Self> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if handle.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    CloseHandle(handle);
                    return None;
                }
                Some(JobGuard(handle))
            }
        }

        /// Assigns an already-spawned process (by PID) to this job so it dies
        /// alongside the parent regardless of how the parent's process ends.
        pub fn assign_pid(&self, pid: u32) -> bool {
            unsafe {
                let proc_handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
                if proc_handle.is_null() {
                    return false;
                }
                let ok = AssignProcessToJobObject(self.0, proc_handle);
                CloseHandle(proc_handle);
                ok != 0
            }
        }
    }

    impl Drop for JobGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Default)]
struct AppState {
    backend: Mutex<Option<CommandChild>>,
    llama: Mutex<Option<CommandChild>>,
    ai_paused: Mutex<bool>,
    model_path: Mutex<Option<PathBuf>>,
    grype_db_dir: Mutex<Option<PathBuf>>,
    /// Guards against two concurrent `ensure_assets_then_spawn` runs (startup
    /// racing a `retry_asset_setup` call) both writing the same `.tmp` file.
    setup_in_progress: AtomicBool,
    /// Set at the start of `shutdown()` so an in-flight reassembly that
    /// finishes afterwards knows not to spawn sidecars nobody will kill.
    quitting: AtomicBool,
    /// Mirrors the last `asset-setup-*` event so a webview that finishes
    /// loading and registers its listeners *after* reassembly already
    /// completed (the common case once `.done` markers exist — reassembly
    /// then takes well under a second, easily beating the webview's JS
    /// bootstrap) can still learn the outcome via `get_asset_setup_status`
    /// instead of waiting forever for an event that already fired.
    setup_status: Mutex<SetupStatus>,
    /// See `win_job` above. `None` on non-Windows or if job-object creation
    /// failed (logged, not fatal -- sidecars still spawn, just without the
    /// orphan guarantee).
    #[cfg(target_os = "windows")]
    job: Mutex<Option<win_job::JobGuard>>,
}

/// Assigns a freshly spawned sidecar's PID to the app's kill-on-close job
/// object, if one exists. No-op on non-Windows.
fn tie_to_job_lifetime(#[allow(unused_variables)] app: &tauri::AppHandle, #[allow(unused_variables)] child: &CommandChild) {
    #[cfg(target_os = "windows")]
    {
        let state = app.state::<AppState>();
        let guard = state.job.lock().unwrap();
        if let Some(job) = guard.as_ref() {
            if !job.assign_pid(child.pid()) {
                eprintln!("[main] failed to assign sidecar pid {} to job object -- it may survive an ungraceful exit", child.pid());
            }
        }
    }
}

#[derive(Clone, Default)]
enum SetupStatus {
    #[default]
    Pending,
    Ready,
    Failed {
        asset: String,
        reason: String,
    },
}

impl SetupStatus {
    fn to_json(&self) -> serde_json::Value {
        match self {
            SetupStatus::Pending => serde_json::json!({ "status": "pending" }),
            SetupStatus::Ready => serde_json::json!({ "status": "ready" }),
            SetupStatus::Failed { asset, reason } => {
                serde_json::json!({ "status": "failed", "asset": asset, "reason": reason })
            }
        }
    }
}

/// RAII guard that resets `AppState::setup_in_progress` back to `false` on
/// every exit path (normal return, early return, or panic) out of
/// `ensure_assets_then_spawn`'s thread body. Owns a cloned `AppHandle`
/// (cheap — it's a handle, not the state itself) so it isn't tied to the
/// lifetime of any single `state.setup_in_progress` borrow.
struct SetupInProgressGuard {
    app: tauri::AppHandle,
}

impl Drop for SetupInProgressGuard {
    fn drop(&mut self) {
        self.app
            .state::<AppState>()
            .setup_in_progress
            .store(false, Ordering::SeqCst);
    }
}

fn spawn_backend(app: &tauri::AppHandle, grype_db_dir: &std::path::Path) -> Option<CommandChild> {
    let data_dir = app.path().app_local_data_dir().ok()?;
    let _ = std::fs::create_dir_all(&data_dir);
    let keys_dir = data_dir.join("keys");
    let tools_dir = app
        .path()
        .resolve("resources/tools", BaseDirectory::Resource)
        .unwrap_or_default();

    let mut cmd = app
        .shell()
        .sidecar("codesense-server")
        .ok()?
        .env("CODESENSE_DATA_DIR", data_dir.to_string_lossy().to_string())
        .env("SCANNER_TOOLS_DIR", tools_dir.to_string_lossy().to_string())
        .env("GRYPE_DB_CACHE_DIR", grype_db_dir.to_string_lossy().to_string())
        // Windows Semgrep/OpenGrep is `semgrep.exe`; the backend's SEMGREP_BIN
        // override is used verbatim (it does NOT append an extension — only the
        // SCANNER_TOOLS_DIR fallback does), so the ext must be correct here or the
        // packaged Windows app can't launch the engine and scans find nothing.
        .env(
            "SEMGREP_BIN",
            tools_dir
                .join(if cfg!(target_os = "windows") { "semgrep.exe" } else { "semgrep" })
                .to_string_lossy()
                .to_string(),
        )
        .env(
            "SEMGREP_RULES_DIR",
            app.path()
                .resolve("resources/semgrep-rules", BaseDirectory::Resource)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        )
        .env("COSIGN_KEY_DIR", keys_dir.to_string_lossy().to_string())
        .env("COSIGN_PASSWORD", COSIGN_PASSWORD)
        .env("LICENSE_DURATION_DAYS", license_duration_days())
        // Always set (empty = legacy shared store) so an ambient LICENSE_SCOPE in the user's
        // shell cannot move this build's clock.
        .env("LICENSE_SCOPE", license_scope())
        .env("TRIAL_MODE", trial_mode())
        .env("TRIAL_SCAN_LIMIT", trial_scan_limit())
        .args(["127.0.0.1", BACKEND_PORT]);

    // No activation gate when the build says so (Community): leave the variable unset rather
    // than set to "" so there is no doubt the backend sees "no gate".
    let activation_hash = activation_password_hash();
    if !activation_hash.is_empty() {
        cmd = cmd.env("ACTIVATION_PASSWORD_HASH", activation_hash);
    }

    // Local AI engine settings only matter when the model is bundled. Without it (Community)
    // the backend must not be pointed at a llama-server that is never started.
    if bundles_model() {
        cmd = cmd
            .env("VLLM_BASE_URL", format!("http://127.0.0.1:{LLAMA_PORT}/v1"))
            .env("VLLM_MODEL", "astra-code-reviewer")
            .env("VLLM_API_KEY", "EMPTY")
            // Ship the instruction-tuned (Apache-2.0 Qwen2.5-Coder-Instruct) path, not
            // the legacy FIM one: the bundled GGUF is the instruct model and the
            // verifier/enricher emit/parse JSON only under instruct mode. Without this
            // the backend defaults to LLM_MODEL_MODE=fim (see llm.py::model_mode).
            .env("LLM_MODEL_MODE", "instruct");
    }

    for (key, value) in edition_env(BUILD_EDITION, BUILD_ENTITLEMENTS_PUBLIC_KEY, BUILD_MODEL_TIER) {
        cmd = cmd.env(key, value);
    }

    match cmd.spawn() {
        Ok((mut rx, child)) => {
            tie_to_job_lifetime(app, &child);
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                            eprintln!("[backend] {}", String::from_utf8_lossy(&line));
                        }
                        _ => {}
                    }
                }
            });
            Some(child)
        }
        Err(e) => {
            eprintln!("failed to start backend: {e}");
            None
        }
    }
}

fn spawn_llama(app: &tauri::AppHandle, model_path: &std::path::Path) -> Option<CommandChild> {
    let cmd = app
        .shell()
        .sidecar("llama-server")
        .ok()?
        .args([
            "--model",
            &model_path.to_string_lossy(),
            "--host",
            "127.0.0.1",
            "--port",
            LLAMA_PORT,
            "--ctx-size",
            "8192",
            "--alias",
            "astra-code-reviewer",
            "--api-key",
            "EMPTY",
            "--jinja",
        ]);

    // The Windows llama-server.exe is a thin (~9KB) launcher that dynamically
    // links its runtime DLLs (llama-server-impl.dll, llama.dll, ggml*.dll,
    // mtmd.dll, libomp*). A PATH-prepend workaround here was proven insufficient
    // (the loader still failed to resolve them). The real fix lives in
    // tauri.conf.json: `bundle.resources` maps resources/llama-runtime/*.dll to
    // target "" (= $RESOURCES root), which on Windows IS the same directory
    // Tauri installs the sidecar exe into — so the DLLs are simply beside it on
    // disk and the default Windows DLL search order finds them with no code
    // needed here. No-op on macOS (single Metal binary; the dir is absent there).
    match cmd.spawn() {
        Ok((mut rx, child)) => {
            tie_to_job_lifetime(app, &child);
            let app = app.clone();
            let spawned_at = std::time::Instant::now();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                            eprintln!("[llama] {}", String::from_utf8_lossy(&line));
                        }
                        CommandEvent::Terminated(payload) => {
                            // A deliberate "Pause AI" toggle or app quit also kills this
                            // process and produces a Terminated event, so only treat a
                            // termination in the first few seconds as a startup failure
                            // (the crash-on-launch symptom this check targets).
                            if spawned_at.elapsed() < std::time::Duration::from_secs(5) {
                                eprintln!(
                                    "[llama] AI engine failed to start (exit code {:?}) — scans will run deterministic-only, no AI verify/enrich.",
                                    payload.code
                                );
                                if let Some(tray) = app.tray_by_id("main") {
                                    let _ = tray.set_tooltip(Some(
                                        "Code Sense — AI engine failed to start (deterministic-only scans)",
                                    ));
                                }
                            } else {
                                eprintln!("[llama] AI engine stopped (exit code {:?})", payload.code);
                            }
                        }
                        CommandEvent::Error(err) => {
                            eprintln!("[llama] AI engine spawn error: {err}");
                        }
                        _ => {}
                    }
                }
            });
            Some(child)
        }
        Err(e) => {
            eprintln!("failed to start llama-server: {e}");
            None
        }
    }
}

/// Runs `ensure_ready` for one asset with the auto-retry-once policy: on
/// failure, discard any partial output and try exactly once more before
/// giving up. Emits `asset-setup-progress` events for the frontend's
/// first-run setup screen as it streams.
fn reassemble_with_retry(
    app: &tauri::AppHandle,
    asset_name: &str,
    resource_dir: &std::path::Path,
    target_dir: &std::path::Path,
    spec: &asset_reassembly::AssetSpec,
) -> Result<PathBuf, ReassemblyError> {
    let mut last_err = None;
    for _attempt in 0..2 {
        let app_for_progress = app.clone();
        let name_for_progress = asset_name.to_string();
        let result = ensure_ready(resource_dir, target_dir, spec, |written, total| {
            let _ = app_for_progress.emit(
                "asset-setup-progress",
                serde_json::json!({ "asset": name_for_progress, "bytes": written, "total": total }),
            );
        });
        match result {
            Ok(path) => return Ok(path),
            // ManifestMissing/ManifestCorrupt indicate a packaging defect, not
            // a transient condition — retrying can never succeed, so bail out
            // on the first attempt instead of burning a second identical try.
            Err(e @ (ReassemblyError::ManifestMissing | ReassemblyError::ManifestCorrupt(_))) => {
                return Err(e);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("loop runs at least once"))
}

/// Records a failure in `AppState::setup_status` (so a webview that wasn't
/// listening yet can pick it up via `get_asset_setup_status`) and emits
/// `asset-setup-failed` for webviews that already are.
fn fail_setup(app: &tauri::AppHandle, asset: &str, reason: String) {
    let state = app.state::<AppState>();
    *state.setup_status.lock().unwrap() = SetupStatus::Failed {
        asset: asset.to_string(),
        reason: reason.clone(),
    };
    let _ = app.emit(
        "asset-setup-failed",
        serde_json::json!({ "asset": asset, "reason": reason }),
    );
}

/// Reassembles both bundled assets (model, grype-db) on a background thread,
/// then spawns both sidecars once they're verified ready. Emits
/// `asset-setup-complete` on success or `asset-setup-failed` (with a
/// specific reason) if either asset fails after its retry — the sidecars are
/// never spawned against unverified assets. Re-entrant: also used as the
/// `retry_asset_setup` command's implementation.
///
/// Also mirrors the outcome into `AppState::setup_status` rather than
/// relying solely on these events: once `.done` markers exist, reassembly
/// completes in well under a second — often faster than the webview can
/// finish loading its JS and registering event listeners, so an event-only
/// signal can fire before anyone is listening and be lost forever. The
/// frontend's `get_asset_setup_status` command call (issued right after it
/// registers its listeners) closes that race by picking up whatever already
/// happened; the listeners remain necessary for the slower first-run case
/// where reassembly is still in progress when the frontend mounts.
fn ensure_assets_then_spawn(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        // Startup and `retry_asset_setup` (exposed to the frontend) can both
        // land here concurrently. A retry request that arrives while one run
        // is already in flight is simply a no-op, not queued or errored — it
        // must NOT proceed, since two runs would race on the same `.tmp` path.
        if app
            .state::<AppState>()
            .setup_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // From here on, every exit path (early return or normal completion)
        // must clear the flag again — the guard does that on drop.
        let _guard = SetupInProgressGuard { app: app.clone() };

        // A build with no bundled model (Community, CS_NO_MODEL=1) skips every model step:
        // there is nothing to reassemble and no llama-server to start.
        let model_resource: Option<PathBuf> = if bundles_model() {
            match app.path().resolve("resources/model", BaseDirectory::Resource) {
                Ok(p) => Some(p),
                Err(_) => {
                    fail_setup(&app, "model", "failed to resolve resources/model directory".to_string());
                    return;
                }
            }
        } else {
            None
        };
        let grype_resource = match app.path().resolve("resources/grype-db", BaseDirectory::Resource) {
            Ok(p) => p,
            Err(_) => {
                fail_setup(&app, "grype-db", "failed to resolve resources/grype-db directory".to_string());
                return;
            }
        };
        let data_dir = match app.path().app_local_data_dir() {
            Ok(p) => p,
            Err(_) => {
                // This failure blocks both assets, not just the model — "setup"
                // isn't a real asset name, signaling a setup-wide failure.
                fail_setup(&app, "setup", "failed to resolve app data directory".to_string());
                return;
            }
        };
        let model_target_dir = data_dir.join("model");
        // `grype_target_dir` is the CACHE ROOT handed to grype as GRYPE_DB_CACHE_DIR (it
        // appends the schema-version subdirectory itself) -- the reassembled file must
        // therefore land one level deeper, at `grype_target_dir/<GRYPE_DB_SCHEMA_VERSION>/`.
        let grype_target_dir = data_dir.join("grype-db");
        let grype_reassembly_dir = grype_target_dir.join(GRYPE_DB_SCHEMA_VERSION);

        // licenses/services/trial.py::_delete_model_if_present() deletes the
        // reassembled model once the CODE-scan trial allowance is exhausted
        // (SBOM scanning never uses it) and drops this marker beside it. The
        // bundled .partNNN shards are still on disk in the install folder --
        // reassemble_with_retry() would happily rebuild the model right back
        // from them, silently undoing the deletion. So: if the marker is
        // present, skip reassembly entirely and treat this as "no model" (not
        // a setup failure) -- spawn_llama below handles a missing model file
        // gracefully (llama-server just fails to start; the backend's own
        // llm_health() check already fails open for verification, and new
        // code scans are blocked by the trial cap regardless).
        let model_exhausted_marker = model_target_dir.join("TRIAL_EXHAUSTED");
        let model_path: Option<PathBuf> = match &model_resource {
            None => None,
            Some(model_resource) => Some(if model_exhausted_marker.exists() {
                model_target_dir.join(MODEL_ASSET.file_name)
            } else {
                match reassemble_with_retry(
                    &app, "model", model_resource, &model_target_dir, &MODEL_ASSET,
                ) {
                    Ok(path) => path,
                    Err(e) => {
                        let reason = if matches!(e, ReassemblyError::ManifestMissing | ReassemblyError::ManifestCorrupt(_)) {
                            format!("reinstall required: {e}")
                        } else {
                            e.to_string()
                        };
                        fail_setup(&app, "model", reason);
                        return;
                    }
                }
            }),
        };

        if let Err(e) = reassemble_with_retry(
            &app, "grype-db", &grype_resource, &grype_reassembly_dir, &GRYPE_DB_ASSET,
        ) {
            let reason = if matches!(e, ReassemblyError::ManifestMissing | ReassemblyError::ManifestCorrupt(_)) {
                format!("reinstall required: {e}")
            } else {
                e.to_string()
            };
            fail_setup(&app, "grype-db", reason);
            return;
        }

        {
            let state = app.state::<AppState>();
            *state.model_path.lock().unwrap() = model_path.clone();
            *state.grype_db_dir.lock().unwrap() = Some(grype_target_dir.clone());
        }

        // If the user quit while reassembly was still running, shutdown()
        // already ran and there is nothing left to kill these sidecars — so
        // don't start them, and don't bother signaling a UI that's going away.
        if app.state::<AppState>().quitting.load(Ordering::SeqCst) {
            return;
        }

        *app.state::<AppState>().setup_status.lock().unwrap() = SetupStatus::Ready;
        let _ = app.emit("asset-setup-complete", ());

        let state = app.state::<AppState>();
        *state.backend.lock().unwrap() = spawn_backend(&app, &grype_target_dir);
        *state.llama.lock().unwrap() = model_path.as_ref().and_then(|p| spawn_llama(&app, p));
    });
}

#[tauri::command]
fn get_asset_setup_status(app: tauri::AppHandle) -> serde_json::Value {
    app.state::<AppState>().setup_status.lock().unwrap().to_json()
}

#[tauri::command]
fn retry_asset_setup(app: tauri::AppHandle) {
    ensure_assets_then_spawn(app);
}

fn kill(slot: &Mutex<Option<CommandChild>>) {
    if let Some(child) = slot.lock().unwrap().take() {
        let _ = child.kill();
    }
}

fn shutdown(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    // Set before killing anything so a reassembly thread that's still running
    // sees it and skips spawning sidecars we'd otherwise never get to kill.
    state.quitting.store(true, Ordering::SeqCst);
    kill(&state.backend);
    kill(&state.llama);
}

/// Points WebView2's own loader at a bundled, portable copy of the runtime
/// (resources\webview2, staged by build_windows.ps1 alongside the other
/// bundled resources) instead of relying on a system-wide install. Must run
/// before anything creates a webview -- WEBVIEW2_BROWSER_EXECUTABLE_FOLDER is
/// read once by WebView2Loader.dll when the CoreWebView2 environment is
/// created internally during `Builder::build()`, so this is the very first
/// statement in `main()`, ahead of the builder entirely.
///
/// Why this exists: this app's NSIS installer currently cannot be produced
/// for a full build (32-bit makensis can't mmap the ~4.68GB model file), so
/// real deliveries are a raw `tauri build --no-bundle` folder, zipped by
/// hand. `windows.webviewInstallMode.fixedRuntime` in tauri.conf.json only
/// gets embedded by the NSIS/WiX bundler -- a --no-bundle build never gets
/// it, and previously silently depended on the target machine already having
/// WebView2 (most Windows Server images don't; a client's Azure VM hit
/// exactly this on 2026-08-11). `<exe_dir>/resources/webview2` is used
/// (rather than Tauri's own path resolver) because this runs before an
/// AppHandle exists to resolve BaseDirectory::Resource with.
#[cfg(target_os = "windows")]
fn set_webview2_env() {
    let Ok(exe) = std::env::current_exe() else { return };
    let Some(dir) = exe.parent() else { return };
    let wv2 = dir.join("resources").join("webview2");
    if wv2.is_dir() {
        std::env::set_var("WEBVIEW2_BROWSER_EXECUTABLE_FOLDER", &wv2);
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    set_webview2_env();

    tauri::Builder::default()
        // Must be registered first: without this, launching the exe again
        // while the app is already running (e.g. double-clicking it without
        // noticing the tray icon — closing the window only hides it, it
        // doesn't quit) starts a second full backend that races the first
        // over the same port and SQLite database. This makes a second
        // launch attempt just focus the existing window instead.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![retry_asset_setup, get_asset_setup_status])
        .setup(|app| {
            // Must happen before any sidecar spawns (ensure_assets_then_spawn
            // below can spawn them as early as this thread yields) so the
            // very first codesense-server/llama-server processes are covered.
            #[cfg(target_os = "windows")]
            {
                let job = win_job::JobGuard::new();
                if job.is_none() {
                    eprintln!("[main] failed to create Windows job object -- sidecars won't be tied to this process's lifetime; an ungraceful exit could leave them running");
                }
                *app.state::<AppState>().job.lock().unwrap() = job;
            }

            let handle = app.handle().clone();
            ensure_assets_then_spawn(handle);

            let open = MenuItem::with_id(app, "open", "Open Code Sense", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let sep = PredefinedMenuItem::separator(app)?;
            // The "AI engine" item only exists when a local model is bundled (not in Community).
            let menu = if bundles_model() {
                let pause = MenuItem::with_id(app, "pause_ai", "Pause / resume AI engine", true, None::<&str>)?;
                Menu::with_items(app, &[&open, &pause, &sep, &quit])?
            } else {
                Menu::with_items(app, &[&open, &sep, &quit])?
            };

            TrayIconBuilder::with_id("main")
                .tooltip("Code Sense")
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .on_menu_event(move |app, event| match event.id().as_ref() {
                    "open" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "pause_ai" => {
                        // Toggle the llama-server sidecar to free / restore its RAM.
                        let state = app.state::<AppState>();
                        let mut paused = state.ai_paused.lock().unwrap();
                        if *paused {
                            let model_path = state.model_path.lock().unwrap().clone();
                            if let Some(model_path) = model_path {
                                let child = spawn_llama(app, &model_path);
                                *state.llama.lock().unwrap() = child;
                                *paused = false;
                            }
                        } else {
                            kill(&state.llama);
                            *paused = true;
                        }
                    }
                    "quit" => {
                        shutdown(app);
                        app.exit(0);
                    }
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Hide to tray instead of exiting so background scans continue.
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Code Sense")
        .run(|app, event| {
            if let RunEvent::ExitRequested { .. } = event {
                shutdown(app);
            }
        });
}

#[cfg(test)]
mod tests {
    use super::{
        baked, bundles_model_for, edition_env, DEFAULT_ACTIVATION_PASSWORD_HASH,
        DEFAULT_LICENSE_DURATION_DAYS, DEFAULT_LICENSE_SCOPE, DEFAULT_TRIAL_MODE,
        DEFAULT_TRIAL_SCAN_LIMIT,
    };

    #[test]
    fn unset_overrides_keep_the_client_delivery_defaults() {
        // A build that sets none of the CS_* variables must behave exactly as before.
        assert_eq!(baked(None, DEFAULT_LICENSE_DURATION_DAYS), "30");
        assert_eq!(baked(None, DEFAULT_TRIAL_MODE), "true");
        assert_eq!(baked(None, DEFAULT_TRIAL_SCAN_LIMIT), "2");
        assert_eq!(baked(None, DEFAULT_ACTIVATION_PASSWORD_HASH), DEFAULT_ACTIVATION_PASSWORD_HASH);
        assert!(DEFAULT_ACTIVATION_PASSWORD_HASH.starts_with("$2b$"));
    }

    #[test]
    fn licence_scope_is_the_shared_legacy_store_unless_a_build_sets_one() {
        assert_eq!(baked(None, DEFAULT_LICENSE_SCOPE), "");
        assert_eq!(baked(Some("Community"), DEFAULT_LICENSE_SCOPE), "Community");
        assert_eq!(baked(Some(" Community "), DEFAULT_LICENSE_SCOPE), "Community");
        assert_eq!(baked(Some("none"), DEFAULT_LICENSE_SCOPE), "");
    }

    #[test]
    fn a_value_overrides_and_is_trimmed() {
        assert_eq!(baked(Some("90"), "30"), "90");
        assert_eq!(baked(Some(" 90 "), "30"), "90");
        assert_eq!(baked(Some("false"), "true"), "false");
    }

    #[test]
    fn none_means_empty_in_any_case() {
        for v in ["none", "NONE", " None "] {
            assert_eq!(baked(Some(v), "$2b$12$somehash"), "", "{v:?}");
        }
    }

    #[test]
    fn the_model_is_bundled_unless_explicitly_disabled() {
        assert!(bundles_model_for(None));
        assert!(bundles_model_for(Some("0")));
        assert!(bundles_model_for(Some("")));
        assert!(bundles_model_for(Some("yes")));
        assert!(!bundles_model_for(Some("1")));
        assert!(!bundles_model_for(Some(" 1 ")));
    }

    fn get<'a>(vars: &'a [(&'static str, String)], key: &str) -> Option<&'a str> {
        vars.iter().find(|(k, _)| *k == key).map(|(_, v)| v.as_str())
    }

    #[test]
    fn unset_build_pins_community_and_forwards_nothing_else() {
        let vars = edition_env(None, None, None);
        assert_eq!(vars, vec![("CODESENSE_EDITION", "community".to_string())]);
    }

    #[test]
    fn unknown_or_blank_edition_fails_safe_to_community() {
        for bad in ["", "  ", "gold", "PRO2"] {
            let vars = edition_env(Some(bad), None, None);
            assert_eq!(get(&vars, "CODESENSE_EDITION"), Some("community"), "{bad:?}");
        }
    }

    #[test]
    fn valid_editions_are_normalised() {
        for (raw, want) in [("pro", "pro"), (" Enterprise ", "enterprise"), ("COMMUNITY", "community")] {
            let vars = edition_env(Some(raw), None, None);
            assert_eq!(get(&vars, "CODESENSE_EDITION"), Some(want));
        }
    }

    #[test]
    fn public_key_is_forwarded_verbatim_multiline_and_blank_is_dropped() {
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";
        let vars = edition_env(Some("pro"), Some(pem), None);
        assert_eq!(get(&vars, "ENTITLEMENTS_PUBLIC_KEY"), Some(pem.trim()));
        assert!(get(&edition_env(Some("pro"), Some("  \n"), None), "ENTITLEMENTS_PUBLIC_KEY").is_none());
    }

    #[test]
    fn model_tier_forwarded_only_when_valid() {
        assert_eq!(get(&edition_env(None, None, Some("MID")), "MODEL_TIER"), Some("mid"));
        assert!(get(&edition_env(None, None, Some("huge")), "MODEL_TIER").is_none());
        assert!(get(&edition_env(None, None, None), "MODEL_TIER").is_none());
    }
}
