"""Run Semgrep over a folder and parse its --json output into SemgrepFinding objects.

The detector is intentionally narrow: it shells out to the Semgrep binary,
captures stdout, and translates the JSON to our dataclass. No filtering, no
heuristics, no LLM — those live in downstream modules.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
from typing import Any

from scanner.rag.lsast_types import SemgrepFinding
from scanner.services.tools import get_privacy_rules_dir, get_semgrep_bin, get_semgrep_rules_dir

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}

# Semgrep redacts the matched-code `lines` field as "requires login" for registry
# rules when run unauthenticated (the cloud uses `--config p/...` registry packs).
# We detect that and recover the snippet from disk instead.
_REDACTED_MARKERS = ("requires login",)


def _read_code_lines(file_path: str, start_line: int, end_line: int) -> str:
    """Best-effort read of the matched source lines from disk; "" on any error.

    Recovers the code snippet when the engine redacts it. The scanned files still
    exist on disk at this point (the temp extraction dir is cleaned up only after
    the scan completes).
    """
    try:
        if not file_path or not start_line or start_line < 1:
            return ""
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        lo = start_line - 1
        hi = max(end_line or start_line, start_line)
        return "".join(lines[lo:hi]).rstrip("\n")[:2000]
    except OSError:
        return ""


_DISPLAY_CONTEXT_LINES = 3


def _read_code_lines_with_context(
    file_path: str, start_line: int, end_line: int, context: int = _DISPLAY_CONTEXT_LINES,
) -> tuple[str, int]:
    """Best-effort read of the matched lines PLUS a few lines of surrounding
    context, clamped to the file's bounds. Display-only: the returned text is
    NEVER fed to the LLM (code_excerpt, read separately, stays the exact match
    the verifier/enricher prompts were tuned against) — this exists purely so
    the finding-detail UI can show more than just the sink line.

    Returns (widened_text, first_line_number of that text); ("", 0) on any
    error so callers can fall back to the exact-match excerpt.
    """
    try:
        if not file_path or not start_line or start_line < 1:
            return "", 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        end = max(end_line or start_line, start_line)
        lo = max(0, start_line - 1 - context)
        hi = min(len(lines), end + context)
        return "".join(lines[lo:hi]).rstrip("\n")[:2000], lo + 1
    except OSError:
        return "", 0


_DEFAULT_REGISTRY_PACKS = ["p/security-audit", "p/owasp-top-ten", "p/secrets"]

# Was a hardcoded 300s with no override -- too tight on slower/smaller-core
# client hardware scanning a real (non-trivial) codebase against the full
# multi-language rule bundle, even though the same scan completes fine on
# faster dev/test hardware. Now configurable via SEMGREP_TIMEOUT_SECONDS so
# a client-side timeout can be tuned without rebuilding the frozen binary;
# default bumped from 300 to 900 for more headroom out of the box.
def _timeout_seconds() -> int:
    try:
        return int(os.getenv("SEMGREP_TIMEOUT_SECONDS", 900))
    except (TypeError, ValueError):
        return 900


_TIMEOUT_SECONDS = _timeout_seconds()


class SemgrepDetectionError(RuntimeError):
    """Semgrep/OpenGrep never produced a result (timed out or the binary is
    missing). Distinct from "ran and found nothing" -- callers must surface
    this as a scan failure, not silently persist zero findings.
    """


def _extract_cwe(metadata: dict[str, Any]) -> str:
    """The explicit CWE from rule metadata (handles str / int / list / 'CWE-89: ...')."""
    cwes = metadata.get("cwe")
    if isinstance(cwes, (str, int)):
        cwes = [cwes]
    for entry in cwes or []:
        if isinstance(entry, int):
            return f"CWE-{entry}"
        if not isinstance(entry, str):
            continue
        m = re.search(r"CWE[-_ ]?(\d+)", entry, re.IGNORECASE)
        if m:
            return f"CWE-{m.group(1)}"
        head = entry.split(":", 1)[0].strip()
        if head.isdigit():
            return f"CWE-{head}"
    return ""


# Rule-name keyword -> CWE, matched as substrings against the (lowercased) Semgrep
# check_id, most-specific first. Keys are deliberately long/unambiguous so they
# don't collide with path noise in a local --config check_id (e.g. NO bare "rce":
# it lurks inside "souRCE"). Guarded by test_rule_id_keyword_does_not_misfire.
_RULE_ID_CWE: tuple[tuple[str, str], ...] = (
    ("sql-injection", "CWE-89"), ("sqli", "CWE-89"), ("tainted-sql", "CWE-89"),
    ("command-injection", "CWE-78"), ("os-command", "CWE-78"),
    ("code-injection", "CWE-94"), ("eval-injection", "CWE-95"),
    ("non-literal-require", "CWE-95"),
    ("path-traversal", "CWE-22"), ("path-join", "CWE-22"),
    ("directory-traversal", "CWE-22"), ("zip-slip", "CWE-22"),
    ("cross-site-scripting", "CWE-79"), ("xss", "CWE-79"),
    ("csrf", "CWE-352"), ("csurf", "CWE-352"),
    ("ssrf", "CWE-918"), ("server-side-request", "CWE-918"),
    ("xxe", "CWE-611"), ("xml-external", "CWE-611"),
    ("open-redirect", "CWE-601"),
    ("deserial", "CWE-502"),
    ("prototype-pollution", "CWE-1321"),
    ("ldap-injection", "CWE-90"),
    ("redos", "CWE-1333"), ("regex-dos", "CWE-1333"),
    ("hardcoded-secret", "CWE-798"), ("jwt-secret", "CWE-798"),
    ("hardcoded", "CWE-798"), ("hard-coded", "CWE-798"),
    ("weak-hash", "CWE-328"), ("insecure-hash", "CWE-328"),
    ("weak-crypto", "CWE-327"), ("insecure-cipher", "CWE-327"),
    ("insecure-random", "CWE-330"), ("math-random", "CWE-330"),
    ("disable-cert", "CWE-295"), ("verify-false", "CWE-295"),
    ("missing-user", "CWE-250"), ("no-new-privileges", "CWE-250"),
    ("privileged", "CWE-250"), ("writable-filesystem", "CWE-732"),
)

# OWASP category keyword -> representative CWE, matched against the (lowercased)
# owasp tag(s). Coarse (one OWASP category spans many CWEs) but far better than
# Unknown. XSS / SSRF / XXE listed before the broad "injection" so they win.
_OWASP_CWE: tuple[tuple[str, str], ...] = (
    ("cross-site scripting", "CWE-79"),
    ("server-side request forgery", "CWE-918"),
    ("xml external entit", "CWE-611"),
    ("injection", "CWE-74"),
    ("sensitive data exposure", "CWE-200"),
    ("cryptographic failure", "CWE-327"),
    ("broken access control", "CWE-284"),
    ("identification and authentication", "CWE-287"),
    ("broken authentication", "CWE-287"),
    ("vulnerable and outdated", "CWE-1104"),
    ("known vulnerabilit", "CWE-1104"),
    ("insecure design", "CWE-657"),
    ("software and data integrity", "CWE-345"),
    ("logging and monitoring", "CWE-778"),
    ("security misconfiguration", "CWE-16"),
    ("misconfiguration", "CWE-16"),
)

# Non-security rule categories -> generic coding-standards CWE, so quality/lint
# rules read as "coding standard" rather than the misleading "unknown vuln".
_NON_SECURITY_CATEGORIES = frozenset(
    {"correctness", "best-practice", "maintainability", "performance", "portability"})


def _cwe_from_rule_id(rule_id: str) -> str:
    rid = (rule_id or "").lower()
    for needle, cwe in _RULE_ID_CWE:
        if needle in rid:
            return cwe
    return ""


def _cwe_from_owasp(metadata: dict[str, Any]) -> str:
    owasp = metadata.get("owasp")
    if isinstance(owasp, (str, int)):
        owasp = [owasp]
    blob = " ".join(str(x) for x in (owasp or [])).lower()
    for needle, cwe in _OWASP_CWE:
        if needle in blob:
            return cwe
    return ""


def _cwe_from_category(metadata: dict[str, Any]) -> str:
    cat = str(metadata.get("category") or "").strip().lower()
    return "CWE-710" if cat in _NON_SECURITY_CATEGORIES else ""   # coding standards


# Rule-name signals for an OS-command-execution sink (shell_exec, system, exec,
# passthru, proc_open, popen, pcntl_exec). Several upstream registry rules
# (php tainted-exec, exec-use, wp-command-execution-audit) tag these CWE-94
# (code injection) when an OS command sink is really CWE-78. Specific enough not
# to match genuine code-injection rules (eval/assert/create_function).
_OS_COMMAND_RULE_SIGNALS: tuple[str, ...] = (
    "tainted-exec", "exec-use", "shell-exec", "shell_exec",
    "command-execution", "command-exec", "os-command", "system-exec",
    "proc-open", "proc_open", "passthru", "popen", "pcntl",
)


def _is_os_command_rule(rule_id: str) -> bool:
    rid = (rule_id or "").lower()
    return any(sig in rid for sig in _OS_COMMAND_RULE_SIGNALS)


def derive_cwe(metadata: dict[str, Any], rule_id: str) -> str:
    """Best-effort CWE: explicit metadata, else rule-name keyword, else OWASP tag,
    else a coding-standards CWE for non-security categories. Returns '' when
    nothing fits (the caller renders that as CWE-Unknown)."""
    cwe = (_extract_cwe(metadata)
           or _cwe_from_rule_id(rule_id)
           or _cwe_from_owasp(metadata)
           or _cwe_from_category(metadata))
    # Correct the upstream mislabel: an OS-command-execution sink flagged CWE-94
    # (code injection) is really CWE-78 (OS command injection).
    if cwe == "CWE-94" and _is_os_command_rule(rule_id):
        return "CWE-78"
    return cwe


def _find_loc_and_code(node: Any) -> tuple[int | None, str]:
    """Best-effort (line, code) from one dataflow-trace node. Never raises.

    Handles BOTH engine shapes:
      * Semgrep:  {"start": {"line": N}, "code"/"content": "..."}
      * OpenGrep: ["CliLoc", [{"start": {"line": N}, ...}, "code"]]  (OCaml tagged
        tuple — item[0] is a string tag, NOT a location dict).
    """
    line: int | None = None
    code = ""
    stack = [node]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            for lk in ("start", "location"):   # Semgrep uses both across node kinds
                loc = x.get(lk)
                if line is None and isinstance(loc, dict) and isinstance(loc.get("line"), int):
                    line = loc["line"]
            for key in ("code", "content"):
                v = x.get(key)
                if not code and isinstance(v, str) and v:
                    code = v
            stack.extend(v for v in x.values() if isinstance(v, (dict, list)))
        elif isinstance(x, list):
            stack.extend(x)
        elif isinstance(x, str) and not code and x != "CliLoc":
            code = x
    return line, code.strip()


def _extract_taint_trace(extra: dict[str, Any]) -> list[tuple[int, str]]:
    """Distil a (line, code) taint path from Semgrep/OpenGrep dataflow_trace.

    Defensive by design: engines disagree on the JSON shape (Semgrep emits a list
    of location dicts; OpenGrep emits a single ['CliLoc', [...]] tagged tuple), and
    a malformed node must never sink the whole scan.
    """
    df = extra.get("dataflow_trace")
    if not isinstance(df, dict):
        return []
    trace: list[tuple[int, str]] = []
    for key in ("taint_source", "intermediate_vars", "taint_sink"):
        raw = df.get(key)
        if not isinstance(raw, list) or not raw:
            continue
        # A leading string tag (OpenGrep "CliLoc") means the whole list is ONE node;
        # otherwise it's Semgrep's list of node dicts.
        nodes = [raw] if isinstance(raw[0], str) else raw
        for n in nodes:
            line, code = _find_loc_and_code(n)
            if isinstance(line, int):
                trace.append((line, code))
    return trace


def parse_semgrep_json(raw: str) -> list[SemgrepFinding]:
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError):
        logger.warning("Could not parse Semgrep JSON output")
        return []
    if not isinstance(doc, dict):
        return []

    findings: list[SemgrepFinding] = []
    for r in doc.get("results", []) or []:   # `or []` guards an explicit "results": null
        if not isinstance(r, dict):
            continue
        extra = r.get("extra")
        if not isinstance(extra, dict):
            extra = {}
        metadata = extra.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        severity_raw = (extra.get("severity") or "").upper()
        check_id = str(r.get("check_id", ""))
        refs = metadata.get("references")
        references = [str(u) for u in refs if isinstance(u, str)] if isinstance(refs, list) else []
        fix_raw = extra.get("fix")
        fix = str(fix_raw) if isinstance(fix_raw, str) else ""
        try:
            findings.append(SemgrepFinding(
                rule_id=check_id,
                cwe=derive_cwe(metadata, check_id),
                severity=_SEVERITY_MAP.get(severity_raw, "medium"),
                message=str(extra.get("message", "")),
                file_path=str(r.get("path", "")),
                start_line=int((r.get("start") or {}).get("line", 0)),
                end_line=int((r.get("end") or {}).get("line", 0)),
                code_excerpt=str(extra.get("lines", "")),
                taint_trace=_extract_taint_trace(extra),
                sanitizers_observed=[],
                references=references,
                fix=fix,
            ))
        except (TypeError, ValueError) as exc:
            logger.warning("Skipping malformed Semgrep result: %s", exc)
            continue
    return findings


# Windows' MAX_PATH is 260. Only paths at or past this length get the \\?\ extended-length prefix
# (comfortably below the limit, because the extraction path is extended further by the code base's
# own nesting).
_LONG_PATH_THRESHOLD = 200


def _long_path_safe(path: str) -> str:
    """The path to hand to the engine as a scan target on Windows.

    Ordinary paths are passed as plain absolute paths. The \\\\?\\ extended-length prefix is added only
    when the path is long enough to need it (see the WinError 206 note in run_semgrep), because the
    prefix is NOT harmless: OpenGrep then cannot make the target relative to its root, matches its
    default ignore patterns (build/, dist/, vendor/, test/, ...) against the WHOLE absolute path
    instead, and silently scans nothing if any folder in the path is named like one of them -- e.g. an
    app-data folder under a user or build directory called "build". It also made every finding's path
    absolute with the prefix, which broke path-relative features (incremental scans).
    """
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    absolute = os.path.abspath(path)
    if len(absolute) < _LONG_PATH_THRESHOLD:
        return absolute
    return "\\\\?\\" + absolute


def run_semgrep(target: str | list[str]) -> list[SemgrepFinding]:
    bin_path = get_semgrep_bin()
    rules_dir = get_semgrep_rules_dir()

    cmd = [bin_path]
    if rules_dir:
        cmd += ["--config", rules_dir]
    else:
        for pack in _DEFAULT_REGISTRY_PACKS:
            cmd += ["--config", pack]
    # Layered on top of whichever rules source above: a small hand-written PII/
    # privacy pack (CWE-359/532) shipped in-repo, kept separate from the
    # upstream-cloned rules_dir so it survives that tree's re-staging.
    privacy_rules_dir = get_privacy_rules_dir()
    if privacy_rules_dir:
        cmd += ["--config", privacy_rules_dir]
    # No "--metrics off": the bundled engine is OpenGrep, which has no telemetry
    # and rejects that flag (rc=2). Upstream Semgrep (dev/eval) telemetry is
    # disabled via SEMGREP_SEND_METRICS in the env below instead.
    cmd += ["--json", "--quiet", "--disable-version-check"]
    # `target` is either a single directory/file path (today's behavior) or an
    # explicit list of file paths (incremental scan) -- OpenGrep's CLI TARGETS
    # argument accepts either interchangeably.
    #
    # A real codebase's own nesting (node_modules, Java/C# package trees, ...)
    # combined with this app's already-fairly-long extraction path routinely
    # pushes the target path itself past Windows' 260-char MAX_PATH. Without
    # the \\?\ extended-length prefix, CreateProcess can fail outright on that
    # single argument with WinError 206 ("filename or extension is too long"),
    # which subprocess.run() surfaces as if the semgrep binary itself couldn't
    # be found -- misleading, since the binary is fine; it's this argument.
    # (`_long_path_safe` is module-level below: the prefix is applied ONLY to paths long enough to
    # need it, see its docstring for why it must not be used on ordinary ones.)
    if isinstance(target, (list, tuple)):
        safe_targets = [_long_path_safe(t) for t in target]
        # An incremental scan can pass hundreds of individual file paths as
        # separate CLI arguments. Each is now long-path-safe (\\?\ + abspath),
        # which makes each one *longer* -- with enough files that can push the
        # *total* command line past Windows' CreateProcess limit (~32K chars),
        # surfacing as the same "binary not found" WinError 206 even though
        # every individual path is fine on its own. If that would happen,
        # fall back to scanning their common parent folder as a single target
        # instead -- a strict superset of what the file list covered (may
        # rescan a few already-unchanged files), trading a little incremental
        # -scan efficiency for never failing outright on a big changeset.
        # Conservative on purpose: Windows' documented CreateProcess limit is
        # ~32K chars, but the exact boundary that actually triggers WinError
        # 206 in practice is uncertain (it may be hit via an intermediate,
        # lower-limited path). A false-positive fallback costs almost nothing
        # (a slightly less-targeted incremental scan); a missed one repeats
        # the exact production failure this exists to prevent -- so bias hard
        # toward falling back early rather than cutting it close.
        _MAX_CMDLINE_CHARS = 8000
        if os.name == "nt" and len(subprocess.list2cmdline(cmd + safe_targets)) > _MAX_CMDLINE_CHARS:
            try:
                common_root = os.path.commonpath([os.path.abspath(t) for t in target])
                logger.warning(
                    "Semgrep target file list too long for the command line "
                    "(%d files) -- falling back to scanning the common folder "
                    "%r instead", len(target), common_root,
                )
                cmd += [_long_path_safe(common_root)]
            except ValueError:
                # No common path exists (e.g. different drives) -- fall back
                # to the original per-file behavior; this is no worse than
                # before this safeguard existed.
                cmd += safe_targets
        else:
            cmd += safe_targets
    else:
        cmd += [_long_path_safe(target)]

    # Force a UTF-8 environment. The frozen OpenGrep/Semgrep reads rule YAMLs
    # using the process locale; a non-UTF-8 host locale makes it fall back to
    # the ASCII codec and crash (UnicodeDecodeError) on rules containing
    # non-ASCII bytes (em-dashes, smart quotes, …). C.UTF-8 is portable across
    # macOS/Linux; PYTHONUTF8 covers Windows.
    env = os.environ.copy()
    # This app is itself a frozen Python build (PyInstaller). If the host
    # machine has ANY stray PYTHONHOME/PYTHONPATH/etc set anywhere in its
    # environment -- another Python install, leftover debugging state, a
    # system-wide var nobody remembers setting -- this process inherits it,
    # and semgrep.exe (a SEPARATELY frozen Python program) would inherit it
    # again here via the blind os.environ.copy() above, pointing its own
    # interpreter at the wrong stdlib entirely. Confirmed root cause of a
    # real production zero-findings incident: rc=0, valid-but-empty JSON,
    # stderr "ModuleNotFoundError: No module named 'warnings'" -- semgrep's
    # own Python startup was silently broken, not the rules or engine.
    for _var in ("PYTHONHOME", "PYTHONPATH", "PYTHONSAFEPATH", "PYTHONNOUSERSITE"):
        env.pop(_var, None)
    env["PYTHONUTF8"] = "1"
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
    env["SEMGREP_SEND_METRICS"] = "off"

    logger.info("Running Semgrep: %s", shlex.join(cmd))
    try:
        # Decode the engine's output as UTF-8 explicitly. Without `encoding`, text=True uses the
        # host locale codec (cp1252 on many Windows machines), and the first byte that codec
        # cannot map (e.g. 0x8d in "Í") kills subprocess's reader thread: stdout comes back
        # empty and the scan silently reports 0 findings. The PYTHONUTF8 set on `env` above only
        # affects the engine, not how this process decodes the pipe. errors="replace" keeps one
        # stray malformed byte from discarding an entire scan's results.
        result = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_TIMEOUT_SECONDS, check=False, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Semgrep timed out after %ds: %s", _TIMEOUT_SECONDS, exc)
        raise SemgrepDetectionError(
            f"Semgrep/OpenGrep did not finish within {_TIMEOUT_SECONDS}s"
        ) from exc
    except FileNotFoundError as exc:
        logger.error("Semgrep binary not found: %s", exc)
        raise SemgrepDetectionError(f"Semgrep/OpenGrep binary not found: {exc}") from exc

    # Confirms the subprocess call itself returned control to Python -- distinct
    # from the outcome messages below, which depend on what it returned. If a
    # scan hangs, whether this line ever appears is the single fact that tells
    # you whether the hang is inside subprocess.run() or somewhere downstream.
    logger.info(
        "Semgrep subprocess returned: rc=%d, stdout=%d bytes, stderr=%d bytes",
        result.returncode, len(result.stdout or ""), len(result.stderr or ""),
    )

    if result.returncode >= 2:
        logger.warning("Semgrep failed (rc=%d): %s", result.returncode, result.stderr[:500])
        return []

    findings = parse_semgrep_json(result.stdout)
    if not findings:
        # parse_semgrep_json() only ever returns the results list -- it silently
        # discards semgrep's own "errors"/"skipped_rules"/"paths.scanned" fields,
        # so a genuine 0-findings run and a run that silently failed on every
        # file (parse errors, unsupported syntax, wrong rule pack, ...) were
        # previously indistinguishable from the log alone. Surface them here,
        # only on the empty-findings path, so this stays silent on the normal
        # (findings-producing) path but never leaves a real problem invisible.
        try:
            doc = json.loads(result.stdout)
            errors = doc.get("errors") or []
            skipped = doc.get("skipped_rules") or []
            scanned = (doc.get("paths") or {}).get("scanned") or []
            logger.info(
                "Semgrep 0-findings detail: scanned=%d files, errors=%d, "
                "skipped_rules=%d%s%s",
                len(scanned), len(errors), len(skipped),
                f"; first error: {errors[0]}" if errors else "",
                f"; stderr: {result.stderr.strip()[:500]}" if result.stderr and result.stderr.strip() else "",
            )
        except (ValueError, TypeError, AttributeError):
            pass
    # Recover the code snippet from disk when the engine redacted it (registry
    # rules emit "requires login" when unauthenticated). This fixes the stored
    # snippet AND the code the LLM verifier/enricher reasons over.
    for f in findings:
        excerpt = (f.code_excerpt or "").strip().lower()
        if not excerpt or any(m in excerpt for m in _REDACTED_MARKERS):
            recovered = _read_code_lines(f.file_path, f.start_line, f.end_line)
            if recovered:
                f.code_excerpt = recovered
        # Display-only widened snippet — best-effort, degrades silently to just
        # code_excerpt (via finding_normalizer) when the source file isn't reachable.
        context_text, context_start = _read_code_lines_with_context(
            f.file_path, f.start_line, f.end_line)
        if context_text:
            f.context_code = context_text
            f.context_start_line = context_start
    return findings
