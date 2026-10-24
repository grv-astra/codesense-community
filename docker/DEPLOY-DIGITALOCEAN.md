# Deploy Code Sense Community on a DigitalOcean droplet

One droplet runs four containers: **caddy** (HTTPS), **nginx** (limits and blocks), **backend** and
**frontend**. Data lives in one Docker volume, `codesense_data`.

> Status: tested on 2026-10-24 with Docker Desktop (Linux containers), built from a fresh Community export and run
> over plain HTTP: first-run admin limited to one IP, sign-in rate limit, `/admin/` blocked, 413 above 260 MB, the
> 2-scan cap, a code scan and an SBOM scan, and sessions, accounts and scans surviving a restart and a full
> down/up. **Not tested:** a real domain with Caddy certificates, a droplet, and large repositories.

## 1. Decide first
| Question | Why it matters |
|---|---|
| Domain name and who controls its DNS | Caddy needs an A record pointing at the droplet to get a certificate. |
| Who may reach it | Start with the DigitalOcean Cloud Firewall allowing only your office or VPN addresses. |
| `LICENSE_DURATION_DAYS` | After this many days from first-run setup the instance goes read-only for everyone. |
| Licence terms | Put your terms in front of users before anyone outside the team signs in. |

Community limits apply to a hosted instance too: 3 seats, 1 project, 250 MB per upload, 25 scans per type per 30 days.
These are fixed per edition and cannot be changed from the environment.

**Scan cap for a trial.** `TRIAL_MODE=true` with `TRIAL_SCAN_LIMIT=2` (the values in `community.env.example`) allows
2 successful code scans and 2 successful SBOM scans on the instance, in total and for all users. Only completed scans count;
failed or cancelled ones do not, and deleting a scan does not give the slot back. At the cap the app answers
"Trial limit reached". To lift the cap later, set `TRIAL_MODE=false` (or raise `TRIAL_SCAN_LIMIT`) in `docker/.env` and
run `docker compose -f docker/docker-compose.community.yml up -d`. To give the instance a fresh allowance of the same size:
```bash
docker compose -f docker/docker-compose.community.yml exec backend python -c \
  "import sqlite3; c=sqlite3.connect('/data/app.sqlite3'); c.execute('update trial_usage set code_scans_used=0, sbom_scans_used=0'); c.commit()"
```

## 2. Create the droplet
- Ubuntu 24.04. **4 vCPU / 8 GB RAM / 80 GB disk** is a comfortable start; 2 vCPU / 4 GB works for small repositories.
  The image build and large scans are the heavy parts. Add 2 GB of swap if you build on the droplet.
- Turn on DigitalOcean **Backups** (weekly snapshots) in addition to the data backup in section 7.
- Cloud Firewall: allow 22 from your address only; allow 80 and 443 from the addresses that should reach the app.
- DNS: an **A record** for the domain pointing at the droplet's IPv4 address.

## 3. Install Docker and get the code
```bash
curl -fsSL https://get.docker.com | sh
git clone <your Community repository URL> codesense && cd codesense
```
The repository is private: use a read-only deploy key or token that you create and keep yourself.

## 4. Configure
```bash
cp docker/community.env.example docker/.env
nano docker/.env
```
Fill in `SITE_ADDRESS`, `SITE_HOST`, `SETUP_ALLOW_IP` (your own public IP), and generate `COSIGN_PASSWORD`
and `LICENSE_SECRET` with `openssl rand -hex 32`. Keep `docker/.env` out of version control.

## 5. Build and start
```bash
docker compose -f docker/docker-compose.community.yml up -d --build
docker compose -f docker/docker-compose.community.yml ps
```
The first build takes a while: it freezes the backend, builds the frontend and downloads the vulnerability database.
Wait until `backend` shows `healthy`.

## 6. First-run setup
From the machine whose address is `SETUP_ALLOW_IP`, open `https://<your domain>/setup` and create the admin account.
Anyone else gets a 403 on that step. Do this immediately after the first start. Then, in **Settings**, connect your own
AI model if you want AI verification (the admin's consent applies to everyone using the instance).

Checks: sign in, create a project, scan a small zip, open the findings.

## 7. Operate
- **Logs:** `docker compose -f docker/docker-compose.community.yml logs -f backend` (rotated at 5 x 10 MB per container).
- **Backup** (data volume; stop the backend briefly so the database file is consistent). Run it from cron at a quiet hour:
  ```bash
  cd codesense
  docker compose -f docker/docker-compose.community.yml stop backend
  docker run --rm -v codesense_codesense_data:/data -v "$PWD":/backup busybox \
    tar czf /backup/codesense-data-$(date +%F).tgz -C /data .
  docker compose -f docker/docker-compose.community.yml start backend
  ```
  Copy the archive off the droplet (DigitalOcean Spaces or another host). The volume name starts with the project
  name `codesense` (check with `docker volume ls`).
- **Update:** `git pull && docker compose -f docker/docker-compose.community.yml up -d --build`. Database migrations
  run automatically at start. To roll back, check out the previous commit, rebuild, and restore the backup if needed.
- **Disk:** each scan keeps its extracted source in `/data/media/scans/<id>` so it can be resumed. Delete old scans
  in the app and watch `df -h`; the vulnerability database inside the image is only refreshed when you rebuild with
  `docker compose ... build --no-cache backend`.

## 8. Known limits
- Brute-force limits and the first-run protection are applied by nginx. The application itself has no lockout.
- The backend image is about 5.2 GB; keep at least 15 GB free for the build. A code scan loads the whole rule set,
  so even a tiny project took about 2 minutes in the test; SBOM scans took seconds.
- Single instance, SQLite, no high availability. One scan runs at a time per project.
- GitHub-repository scans write outside the data volume and are not size-limited: prefer zip uploads here.
- The image uses the upstream `semgrep` package, where the Windows desktop app uses OpenGrep; check a sample scan.
- The signing password and licence secret are yours (from `docker/.env`); losing `docker/.env` does not lose data,
  but changing `LICENSE_SECRET` makes the existing licence clock read as tampered.
