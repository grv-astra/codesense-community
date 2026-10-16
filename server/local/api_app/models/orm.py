from django.db import models
from common.orm import UUIDModel


def _severity_counts_default():
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}


def _scan_metrics_default():
    return {"total_functions": 0, "total_loc": 0, "languages": []}


class Project(UUIDModel):
    name = models.CharField(max_length=255)
    preset = models.CharField(max_length=255, blank=True, default="")
    description = models.TextField(blank=True, default="")
    created_by = models.CharField(max_length=32, blank=True, default="")
    created_at = models.DateTimeField()
    deleted = models.BooleanField(default=False)

    class Meta:
        app_label = "api_app"
        db_table = "projects"


class Scan(UUIDModel):
    project_id = models.CharField(max_length=32, db_index=True)
    scan_name = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=32, default="queued")
    source = models.CharField(max_length=32, default="zip")
    created_at = models.DateTimeField()
    last_updated = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    triggered_by = models.CharField(max_length=32, blank=True, default="")
    total_files = models.IntegerField(default=0)
    files_scanned = models.IntegerField(default=0)
    findings = models.IntegerField(default=0)
    error = models.TextField(blank=True, default="")
    deleted = models.BooleanField(default=False)
    metrics = models.JSONField(default=_scan_metrics_default)
    source_path = models.CharField(max_length=1024, blank=True, default="")
    cancel_requested = models.BooleanField(default=False)
    file_manifest = models.JSONField(default=dict, blank=True)
    ruleset_version = models.CharField(max_length=64, blank=True, default="")
    incremental_info = models.JSONField(default=dict)

    class Meta:
        app_label = "api_app"
        db_table = "scans"


class Finding(UUIDModel):
    scan_id = models.CharField(max_length=32, db_index=True)
    created_by = models.CharField(max_length=32, blank=True, default="")
    cwe = models.CharField(max_length=255, blank=True, default="")
    cvss_vector = models.CharField(max_length=255, blank=True, default="")
    cvss_score = models.CharField(max_length=32, blank=True, default="")
    code = models.CharField(max_length=64, blank=True, default="")
    title = models.TextField(blank=True, default="")
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=32, blank=True, default="")
    file_path = models.CharField(max_length=512, blank=True, default="")
    code_snip = models.TextField(blank=True, default="")
    security_risk = models.TextField(blank=True, default="")
    mitigation = models.TextField(blank=True, default="")
    status = models.CharField(max_length=32, default="open")
    deleted = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    reference = models.CharField(max_length=512, blank=True, default="")
    created_at = models.DateTimeField()
    # W7 — verifier metadata + the Semgrep rule id (previously dropped on persist).
    # rule_id = the detector check_id; confidence/verifier_reason come from the LLM
    # verifier via fusion. Nullable/blank for back-compat with pre-W7 rows.
    rule_id = models.CharField(max_length=512, blank=True, default="")
    confidence = models.FloatField(null=True, blank=True)
    verifier_reason = models.TextField(blank=True, default="")
    # Flow-diagram widget data: formatted Source/Step/Sink strings from the
    # detector's dataflow trace. Nullable/blank for back-compat with pre-existing rows.
    flow_diagram = models.JSONField(null=True, blank=True)
    # First real source-file line number of code_snip (which may be a context-padded
    # window, not just the exact match) — lets the UI number lines correctly.
    # Nullable for back-compat with pre-existing rows.
    code_snip_start_line = models.IntegerField(null=True, blank=True)
    # Stable identity for the raw detector match this Finding came from
    # (sha256 of file_path+start_line+rule_id) -- lets a resumed scan tell
    # which findings were already verified+persisted in a prior attempt and
    # skip re-running the LLM step for them. Blank for pre-existing rows.
    fingerprint = models.CharField(max_length=64, blank=True, default="", db_index=True)

    # Scan in which this finding was ORIGINALLY detected. On the first scan of
    # a project this equals scan_id. A later task will carry this value
    # forward across consecutive incremental scans so a finding's provenance
    # (first detection) survives even after many re-scans copy it forward.
    first_seen_scan_id = models.CharField(max_length=32, blank=True, default="", db_index=True)

    # "ai" when title/description/security_risk/mitigation were written by an LLM
    # (the bundled model or the user's own); "" when they are the deterministic,
    # rule-derived text. Lets the UI label model-authored advice as such.
    report_source = models.CharField(max_length=16, blank=True, default="")

    class Meta:
        app_label = "api_app"
        db_table = "findings"


class TrialUsage(UUIDModel):
    """Single-row, monotonic counters of successfully-completed scans, used to
    enforce a trial limit -- SEPARATE per scan type (code vs SBOM each get their
    own allowance; using up one doesn't consume the other's). Deliberately
    separate from the (hard-deletable) Scan/SbomScan rows so deleting a scan
    can't free a trial slot. Only ever incremented."""
    code_scans_used = models.IntegerField(default=0)
    sbom_scans_used = models.IntegerField(default=0)
    updated_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "api_app"
        db_table = "trial_usage"


class SbomScan(UUIDModel):
    project_id = models.CharField(max_length=32, db_index=True)
    scan_name = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=32, default="queued")
    created_at = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    triggered_by = models.CharField(max_length=32, blank=True, default="")
    dependencies_scanned = models.IntegerField(default=0)
    vulnerabilities = models.IntegerField(default=0)
    severity_counts = models.JSONField(default=_severity_counts_default)
    ecosystems = models.JSONField(default=list)
    sbom_format = models.CharField(max_length=32, default="syft-json")
    deleted = models.BooleanField(default=False)
    sbom_signing = models.JSONField(default=dict)
    sbom_artifact = models.CharField(max_length=512, blank=True, default="")
    license_policy = models.JSONField(default=dict)
    cancel_requested = models.BooleanField(default=False)

    class Meta:
        app_label = "api_app"
        db_table = "sbom_scans"


class SbomFinding(UUIDModel):
    scan_id = models.CharField(max_length=32, db_index=True)
    package_name = models.CharField(max_length=255, blank=True, default="")
    package_version = models.CharField(max_length=128, blank=True, default="")
    package_type = models.CharField(max_length=64, blank=True, default="")
    cve_id = models.CharField(max_length=64, blank=True, default="")
    severity = models.CharField(max_length=32, blank=True, default="")
    description = models.TextField(blank=True, default="")
    cvss = models.JSONField(default=list)
    fix_versions = models.JSONField(default=list)
    created_at = models.DateTimeField()

    class Meta:
        app_label = "api_app"
        db_table = "sbom_findings"


class SbomLicenseFinding(UUIDModel):
    scan_id = models.CharField(max_length=32, db_index=True)
    package_name = models.CharField(max_length=255, blank=True, default="")
    package_version = models.CharField(max_length=128, blank=True, default="")
    package_type = models.CharField(max_length=64, blank=True, default="")
    license = models.JSONField(default=dict)
    decision = models.CharField(max_length=64, blank=True, default="")
    locations = models.JSONField(default=list)
    created_at = models.DateTimeField()

    class Meta:
        app_label = "api_app"
        db_table = "sbom_licenses_findings"


class APIKey(UUIDModel):
    project_id = models.CharField(max_length=32, db_index=True)
    name = models.CharField(max_length=255)
    # Stores a SHA-256 hash of the API key, never the raw/plaintext key itself.
    key_hash = models.CharField(max_length=64, unique=True)
    key_prefix = models.CharField(max_length=16)
    created_by = models.CharField(max_length=32, blank=True, default="")
    created_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        app_label = "api_app"
        db_table = "api_keys"


class ScanEvent(UUIDModel):
    """Append-only, never-deleted record of one successfully-completed scan.
    Backs the per-rolling-window edition scan quota (licenses.services.limits).
    Deliberately independent of the hard-deletable Scan/SbomScan rows so a client
    cannot free quota by deleting scans -- same rationale as TrialUsage."""
    scan_type = models.CharField(max_length=8, db_index=True)   # "code" | "sbom"
    completed_at = models.DateTimeField(db_index=True)

    class Meta:
        app_label = "api_app"
        db_table = "scan_events"


class LLMConnection(UUIDModel):
    """The install's single bring-your-own-LLM connection (singleton row; use
    scanner.byo_llm.store.load()). The API key is stored ONLY encrypted
    (api_key_enc) and is write-only through the API. Consent is bound to the host
    it was given for (consent_host): changing the host clears it."""
    enabled = models.BooleanField(default=False)
    provider = models.CharField(max_length=32, default="openai_compatible")
    base_url = models.CharField(max_length=500, blank=True, default="")
    model = models.CharField(max_length=200, blank=True, default="")
    api_version = models.CharField(max_length=32, blank=True, default="")   # Azure OpenAI only
    api_key_enc = models.TextField(blank=True, default="")
    timeout_s = models.IntegerField(default=60)
    max_concurrency = models.IntegerField(default=2)
    consent_at = models.DateTimeField(null=True, blank=True)
    consent_by = models.CharField(max_length=32, blank=True, default="")
    consent_host = models.CharField(max_length=255, blank=True, default="")
    # Also have the LLM write the finding's mitigation advice (a second call per
    # finding that sends the rule name + analyzer message too). Active only when
    # consent_reports is set: consent given BEFORE this existed covers verification only.
    enrich_reports = models.BooleanField(default=True)
    consent_reports = models.BooleanField(default=False)
    updated_at = models.DateTimeField(null=True, blank=True)
    updated_by = models.CharField(max_length=32, blank=True, default="")
    last_test_at = models.DateTimeField(null=True, blank=True)
    last_test_ok = models.BooleanField(null=True, blank=True)
    last_test_error = models.TextField(blank=True, default="")

    class Meta:
        app_label = "api_app"
        db_table = "llm_connection"
