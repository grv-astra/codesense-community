#!/usr/bin/env python
"""Production entrypoint for the bundled Code Sense backend.

Applies DB migrations (creating the SQLite DB on first launch) then serves Django
via waitress. The Tauri shell launches this as the `codesense-server` sidecar:

    codesense-server <host> <port>     # e.g. codesense-server 127.0.0.1 8585

Two extra subcommands cover activation (see licenses/services/activation.py)
for deployments with no frontend to host a password field -- e.g. the native
web deploy, where ACTIVATION_PASSWORD_HASH is otherwise unreachable:

    codesense-server activate [--password <pw>]   # prompts (hidden) if omitted
    codesense-server activation-status             # read-only, no password needed

All configuration comes from environment variables set by the launcher
(CODESENSE_DATA_DIR, VLLM_BASE_URL, SCANNER_TOOLS_DIR, GRYPE_DB_CACHE_DIR,
COSIGN_KEY_DIR, ...). DEBUG defaults off (see settings.py).
"""
import getpass
import os
import sys


def _django_setup():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "codesense.settings")
    import django
    django.setup()


def _cli_activate(args):
    _django_setup()
    from licenses.services import activation

    if not activation.is_configured():
        print("This build has no activation gate configured (ACTIVATION_PASSWORD_HASH "
              "unset) -- nothing to activate.", flush=True)
        return 0

    if activation.is_activated():
        print("Already activated on this machine.", flush=True)
        return 0

    password = None
    if args and args[0] == "--password" and len(args) > 1:
        password = args[1]
    if password is None:
        password = getpass.getpass("Activation password: ")

    if activation.activate(password):
        print("Activation successful.", flush=True)
        return 0
    print("Activation failed: incorrect password.", flush=True)
    return 1


def _cli_activation_status():
    _django_setup()
    from licenses.services import activation

    if not activation.is_configured():
        print("configured: false (no activation gate on this build)", flush=True)
        return 0
    print(f"configured: true\nactivated: {activation.is_activated()}", flush=True)
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "activate":
        sys.exit(_cli_activate(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "activation-status":
        sys.exit(_cli_activation_status())

    # argv wins (desktop launcher), else env (cloud hosts inject PORT), else local default.
    host = sys.argv[1] if len(sys.argv) > 1 else os.getenv("HOST", "127.0.0.1")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.getenv("PORT", "8585"))

    _django_setup()

    from django.core.management import call_command
    call_command("migrate", interactive=False, verbosity=0)

    from scanner.rag.resume import reconcile_orphaned_scans
    reconciled = reconcile_orphaned_scans()
    if reconciled:
        print(f"Reconciled {reconciled} orphaned scan(s) from a previous run", flush=True)

    # Gather admin/DRF assets so they render with DEBUG off (no-op if already present).
    call_command("collectstatic", interactive=False, verbosity=0)

    from waitress import serve
    from codesense.wsgi import application

    print(f"Code Sense backend listening on http://{host}:{port}", flush=True)
    serve(application, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
