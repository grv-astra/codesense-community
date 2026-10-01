# CodeSense Editions — Community / Pro / Enterprise

CodeSense ships in three editions. The edition is resolved **fully offline** at
server start-up (no license server, no phone-home) and decides which features are
on and what scale limits apply. This document is the operator + customer
reference: what each edition includes, how the running edition is decided, and
how to deploy each one.

Authoritative source for every value below: `server/licenses/editions.py`
(static catalog) and `server/licenses/services/entitlements.py` (resolution).

---

## 1. The three editions

### Feature matrix (all 8 feature flags)

| Feature flag         | What it gates                                             | Community | Pro | Enterprise |
|----------------------|----------------------------------------------------------|:---------:|:---:|:----------:|
| `llm_analysis`       | LLM verifier (TP/FP) + report enrichment                 |    off    | on  |     on     |
| `sbom_signing`       | cosign SBOM signing + verification                       |    off    | on  |     on     |
| `license_compliance` | `grant` license-policy findings                          |    off    | on  |     on     |
| `api_access`         | REST / CI-CD access via API keys                         |    off    | on  |     on     |
| `incremental_scan`   | changed-files-only re-scan                               |    off    | on  |     on     |
| `github_scan`        | clone + scan a GitHub repo                               |  **on**   | on  |     on     |
| `sso`                | RESERVED (Enterprise) — not yet enforced                 |    off    | off |     on     |
| `audit_log`          | RESERVED (Enterprise) — not yet enforced                 |    off    | off |     on     |

Community has every feature **off except `github_scan`**. Pro has everything on
**except `sso` and `audit_log`**. Enterprise has everything on.

### Limits table (all 6 scale limits)

| Limit                   | Meaning                                          | Community | Pro   | Enterprise      |
|-------------------------|-------------------------------------------------|:---------:|:-----:|:---------------:|
| `projects`              | max live projects                               |     1     |  10   | unlimited (`null`) |
| `code_scans_per_window` | code scans per rolling window                   |    25     |  500  | unlimited (`null`) |
| `sbom_scans_per_window` | SBOM scans per rolling window                   |    25     |  500  | unlimited (`null`) |
| `window_days`           | rolling-window length (days)                    |    30     |  30   |       30        |
| `max_codebase_mb`       | max size of a single scanned codebase (MB)      |    250    | 2048  | unlimited (`null`) |
| `seats`                 | max non-deleted users                           |     3     |  25   | unlimited (`null`) |

Scan-per-window counts come from an **append-only `ScanEvent` table** (rolling 30
days) — deleting `Scan` rows does not reset a quota. `projects` / `seats` are live
`COUNT(*)`. A limit of `null` (Enterprise) means the predicate always passes.
Note `window_days` stays `30` for Enterprise even though the other limits go
`null`.

### Model tier

| Edition    | `model_tier` |
|------------|:------------:|
| Community  |     low      |
| Pro        |     mid      |
| Enterprise |     high     |

The **effective** tier at runtime is `min(edition tier, staged MODEL_TIER env)`
by capability order (`server/scanner/rag/model_tiers.py::model_tier()`) — a build
that only stages the 1.5B model runs `low` even on Enterprise.

---

## 2. How the running edition is decided (fail-safe)

Resolution order — **any error resolves *down* to Community, never up**:

1. **`DATA_DIR/entitlements.json`** (same directory as `license.json` /
   `app.sqlite3`), if the file exists:
   - unreadable / not JSON / no `payload` object → **Community** (warned)
   - `ENTITLEMENTS_PUBLIC_KEY` present in the build → the payload's Ed25519
     signature is verified against it. Valid → use the payload
     (`source = "signed"`). Invalid / missing signature → **Community**.
   - `ENTITLEMENTS_PUBLIC_KEY` absent (dev build) → payload accepted **unverified**
     (`source = "unsigned-file"`, warned).
   - `payload.edition` not one of `community` / `pro` / `enterprise` → **Community**.
   - `expires_at` in the past → **Community** (warned "expired").
2. else **`CODESENSE_EDITION`** env var, if it is `community` / `pro` /
   `enterprise` → that edition (`source = "env"`).
3. else → **Community** (`source = "default"`).

Per-customer `overrides` in the payload (`limits` / `features` / `model_tier`)
apply **only when `source == "signed"`** — never for `unsigned-file` or `env`.

**Community needs zero setup.** No file, no env var, no key: the server runs as
Community. What makes a deployment fall back to Community is a *missing*,
*tampered*, *expired*, or *unknown-edition* `entitlements.json`. The
`CODESENSE_EDITION` fallback applies **only when the `entitlements.json` file is
entirely absent** — a present-but-invalid file (tampered / expired /
unknown-edition / unreadable) resolves straight to Community regardless of
`CODESENSE_EDITION`.

The resolved result is cached per process, keyed by the file mtime + env + key
presence. Swap the file in place and **restart** (or call `entitlements.reload()`
from a shell) to pick up a change.

---

## 3. Operator workflow

### One-time, on the vendor / build host

```
python manage.py gen_entitlements_keypair --outdir ./keys [--password PW]
```

Writes `vendor_entitlements_private.pem` and `vendor_entitlements_public.pem`.

- Keep `vendor_entitlements_private.pem` on the **signing machine only** — it is
  the root of trust for every signed entitlement. Never ship it.
- `vendor_entitlements_public.pem` is **provided to the build** (see §3.3 / §4) so
  the running server can verify signatures offline.

`gen_entitlements_keypair` and `mint_entitlements` are **vendor / build-host
tools only** — they are not part of a customer deployment.

### Per customer / deployment — mint an entitlement

```
python manage.py mint_entitlements \
  --edition pro \
  --customer "Acme" \
  --expires 2027-09-04 \
  --private-key vendor_entitlements_private.pem \
  [--key-password PW] \
  [--override-limit projects=25 --override-limit code_scans_per_window=1000] \
  [--override-model-tier high] \
  --out entitlements.json
```

- `--expires` is **inclusive, end-of-day UTC** (`2027-09-04` is valid through
  `2027-09-04T23:59:59Z`). Omit for a non-expiring entitlement.
- `--override-limit` / `--override-model-tier` write a signed `overrides` block —
  these take effect **only** because the file is signed.
- Deliver `entitlements.json` to the customer. They drop it in the server's
  `DATA_DIR` (the directory that already holds `license.json` / `app.sqlite3`)
  and **restart** the server.

### How the public key gets into a build

- **Windows:**
  `scripts/build_windows.ps1 -Edition pro -EntitlementsPublicKeyPath vendor_entitlements_public.pem`
- **macOS:**
  `EDITION=pro ENTITLEMENTS_PUBLIC_KEY_PATH=vendor_entitlements_public.pem ./scripts/build_macos.sh`

`-Edition` / `EDITION=` also sets the per-edition `MODEL_TIER` and
`CODESENSE_EDITION` in the **build-process environment**.
`-EntitlementsPublicKeyPath` / `ENTITLEMENTS_PUBLIC_KEY_PATH=` sets the PEM
**contents** as `ENTITLEMENTS_PUBLIC_KEY` in the build-process environment.
For the packaged Tauri app these three vars are compiled into the launcher
(`option_env!` in `client/src-tauri/src/main.rs`) and forwarded to the backend
sidecar — see §4.2; on the on-prem / nginx path the operator sets them directly in
the server environment.

---

## 4. Two deployment paths

### 4.1 nginx / on-prem server — fully wired

This path works end to end today.

1. In `server/.env` (or the systemd / service unit environment) set:
   - `ENTITLEMENTS_PUBLIC_KEY` — the **PEM contents** of
     `vendor_entitlements_public.pem` (multi-line value).
     ⚠️ `python-dotenv` only keeps a multi-line value if it is wrapped in double
     quotes — `ENTITLEMENTS_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"`
     — otherwise it is truncated to the first line and verification silently fails
     → Community. Prefer setting it in the systemd / service unit environment
     instead.
   - optionally `CODESENSE_EDITION=pro` — used only if there is no
     `entitlements.json` file at all. It is **not** a grace fallback: once a
     customer `entitlements.json` is installed, an expired or tampered file drops
     the server to Community and `CODESENSE_EDITION` is ignored.
2. Drop the customer's `entitlements.json` in `DATA_DIR`.
3. Restart the service.

Verify with `GET /api/edition/` or the `X-CodeSense-Edition` response header
(see §6).

### 4.2 Packaged desktop (Tauri) app

`scripts/build_windows.ps1 -Edition …` / `build_macos.sh` export
`CODESENSE_EDITION`, `MODEL_TIER` and `ENTITLEMENTS_PUBLIC_KEY` into the **build**
environment; `client/src-tauri/src/main.rs` bakes them in at compile time and
`spawn_backend()` forwards them to the sidecar (`edition_env()`, unit-tested):

- `CODESENSE_EDITION` is **always** forwarded — an unset / unknown build value is
  pinned to `community`, so a `CODESENSE_EDITION` in the client's own shell can
  never upgrade a packaged build.
- `ENTITLEMENTS_PUBLIC_KEY` is forwarded when baked, so a customer
  `entitlements.json` is signature-verified (`source = "signed"`, `overrides`
  apply).
- `MODEL_TIER` is forwarded when it is `low` / `mid` / `high`.

Consequences to know:

> **Paid build + no `entitlements.json` = the edition it was built as, unsigned**
> (`source = "env"`), because the env fallback in §2 applies whenever the file is
> absent. Only a *present-but-invalid* file drops to Community. Signed-only
> enforcement for paid builds (Community unless a valid signed file exists) is a
> separate, not-yet-done follow-up.
>
> Editions are **baked per build**. Changing edition means rebuilding with the
> script (cargo re-compiles the launcher when the vars change); builds made before
> this change resolve to Community regardless of `-Edition`.

---

## 5. `CODESENSE_EDITION` — dev override (running from source)

When running the server from source (not a packaged build) you can select an
edition without minting a file:

```
CODESENSE_EDITION=enterprise ./manage.py runserver
```

- Accepted values: `community`, `pro`, `enterprise`.
- Source is `"env"` → **unsigned**, so `overrides` do **not** apply (you get the
  plain catalog values for that edition).
- Dev / from-source only. Production deployments should use a signed
  `entitlements.json`.

---

## 6. How to check the active edition

- **API:** `GET /api/edition/` → `{ edition, label, source, customer, issued_at,
  expires_at, features, limits, model_tier, warnings, usage }`. Allow-listed past
  activation and readable under the read-only middleware.
- **Response header:** every response carries `X-CodeSense-Edition: <edition>`
  (stamped by `EditionHeaderMiddleware`; absent only if resolution itself
  throws).
- **UI:** the edition badge in the top bar (above the license banner) —
  `client/src/components/molecule/edition-badge.tsx`, fed by the
  `useEditionStatus` hook.

---

## 7. What Community loses vs Pro / Enterprise

With `llm_analysis` off:
- **No AI verify/enrich.** Every OpenGrep finding is kept as-is and surfaced as a
  low-confidence result — there is no LLM pass to mark findings TP/FP or to write
  enriched descriptions / remediation.

With `sbom_signing` off:
- **No cosign SBOM signing.** SBOMs are produced but not signed or verified.

With `license_compliance` off:
- **No `grant` license findings.** Dependency license-policy violations are not
  reported.

With `api_access` off:
- **No API keys, no CI/CD.** API-key auth is rejected and key creation is blocked,
  so there is no programmatic / pipeline-triggered scanning.

With `incremental_scan` off:
- **No changed-files-only re-scan.** Every scan is a full scan.

Plus the Community limits: **1 project**, **25 code scans / 30 days**, **25 SBOM
scans / 30 days**, **250 MB** max codebase, **3 seats**. `github_scan` (clone +
scan a public GitHub repo) is the one feature Community keeps.

---

## 8. Support & deployment tiers (not enforced in code)

| Edition    | Support                | Deployment                                              |
|------------|------------------------|--------------------------------------------------------|
| Community  | Community / self-serve | Self-install                                            |
| Pro        | Email                  | Self-install, guided                                    |
| Enterprise | White-glove            | On-prem install + SLA + custom rules / models           |

---

## 9. macOS build default-tier note

`scripts/build_macos.sh` run with **neither `EDITION` nor `MODEL_TIER` set** now
defaults the model tier to **`low`** (previously `mid`). To restore the old
behaviour pass `MODEL_TIER=mid`, or set `EDITION=pro` (which implies `mid`) /
`EDITION=enterprise` (`high`).
