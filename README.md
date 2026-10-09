# Code Sense Community

Code Sense is an **offline** static application security testing (SAST) tool. It
scans source code (OpenGrep/Semgrep rules) and dependencies (Syft + Grype SBOM and
vulnerability scanning) entirely on your own machine or server: no cloud service, no
license server, no phone-home. It ships as a Django backend, a React web UI, and an
optional Tauri desktop shell.

This repository is the **Community edition**.

> **This repo is generated.** It is exported from a private source repository by a
> script, and each release replaces the whole tree. Changes committed directly here
> are overwritten by the next export, so please don't open pull requests against it;
> open an issue instead.

## What Community includes

| | Community |
|---|---|
| Code scanning and SBOM / vulnerability scanning | yes |
| Scan a GitHub repository (clone and scan) | yes |
| Projects | 1 |
| Scans per rolling 30 days | 25 code + 25 SBOM |
| Max codebase size | 250 MB |
| Users (seats) | 3 |
| AI verification and report enrichment | no (module not present) |
| SBOM signing, license-compliance findings, API keys / CI-CD, incremental scans | no |

With no configuration the server runs as Community. How editions are resolved, and
the full feature and limit matrix, is in [docs/EDITIONS.md](docs/EDITIONS.md). You
can check the active edition at `GET /api/edition/`.

## Layout

| Path | What |
|---|---|
| `server/` | Django backend (SQLite) and the scanner pipeline |
| `client/` | React + Vite UI; `client/src-tauri/` is the desktop shell |
| `scripts/` | Build scripts and offline tool staging (`scripts/offline_sbom/`) |
| `docker/`, `docker-compose.yml`, `native-deploy/` | Server deployment |
| `docs/` | [Architecture](docs/Code_Sense_Architecture.md), [editions](docs/EDITIONS.md), [release notes](docs/RELEASE-NOTES.md) |

## Getting started

Scanning needs the offline tool bundle (Semgrep, Syft, Grype, Cosign), the Semgrep
rules, and a Grype vulnerability DB. These are **not** in git; build them with the
scripts in `scripts/offline_sbom/` (`fetch_offline_tools.sh`, `stage_semgrep_rules.py`).

- **Desktop installer:** see [WINDOWS_BUILD_START_HERE.md](WINDOWS_BUILD_START_HERE.md),
  [BUILD.md](BUILD.md) (Windows) and [BUILD_MACOS.md](BUILD_MACOS.md). Those guides
  also describe an AI model component that Community does not include; skip it.
- **Run from source (Windows):** create `server/.venv` and install the requirements,
  stage the tools, then run `server\run_dev.ps1` (backend on port 8586). For the
  UI, from `client/` run `npm install`, then
  `VITE_BACKEND_URL=http://localhost:8586 npx vite --port 5173` (the backend only
  accepts browser requests from 5173 by default; for another port set
  `DJANGO_CORS_ALLOWED_ORIGINS`). A fresh data directory opens the first-run setup
  wizard at `/setup`.
- **Server deployment:** `docker-compose.yml` and `docs/ci-cd/`.

## Tests

```
cd server && python manage.py test scanner local.api_app licenses
cd client && npx vitest run
```

Set `SEMGREP_BIN` and `SEMGREP_RULES_DIR` to enable the scanner characterization
tests; without them they skip, as do the tests that need the AI module.

## License

No license has been specified yet. Until one is added, all rights are reserved by
the copyright holder.
