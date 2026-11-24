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

One more covers a locked-out account (no "forgot password" flow exists). Run it on the PC
that holds the data, with CODESENSE_DATA_DIR pointing at the app's data folder; it refuses
to run if there is no database there rather than creating an empty one:

    codesense-server reset-password --email <email> [--password <pw>]   # prompts (hidden) if omitted

If the build has an activation gate configured (ACTIVATION_PASSWORD_HASH in the
environment) the activation password is required too (--activation-password, or prompted).

All configuration comes from environment variables set by the launcher
(CODESENSE_DATA_DIR, VLLM_BASE_URL, SCANNER_TOOLS_DIR, GRYPE_DB_CACHE_DIR,
COSIGN_KEY_DIR, ...). DEBUG defaults off (see settings.py).
"""
import argparse
import getpass
import os
import sys
from pathlib import Path


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


def _db_path():
    from django.conf import settings
    return Path(settings.DATABASES["default"]["NAME"])


def _cli_reset_password(args):
    parser = argparse.ArgumentParser(
        prog="codesense-server reset-password",
        description="Set a new password for an existing account on this PC.",
    )
    parser.add_argument("--email", required=True, help="email address of the account")
    parser.add_argument("--password", help="new password (prompted, hidden, if omitted)")
    parser.add_argument("--activation-password",
                        help="only needed when the build has an activation gate configured")
    ns = parser.parse_args(args)

    # Check BEFORE importing settings: without it the backend falls back to a data folder
    # next to the code (a temp folder in the frozen exe) and would act on the wrong place.
    if not os.getenv("CODESENSE_DATA_DIR"):
        print("CODESENSE_DATA_DIR is not set. Point it at the app's data folder first, e.g. "
              "set CODESENSE_DATA_DIR=%LOCALAPPDATA%\\com.codesense.desktop", flush=True)
        return 2

    _django_setup()
    db = _db_path()
    if not db.is_file():
        print(f"No database at {db}. Check CODESENSE_DATA_DIR; no account was changed.", flush=True)
        return 2

    from licenses.services import activation
    if activation.is_configured():
        supplied = ns.activation_password
        if supplied is None:
            supplied = getpass.getpass("Activation password: ")
        if not activation.verify_password(supplied):
            print("Reset refused: incorrect activation password.", flush=True)
            return 1

    new_password = ns.password
    if new_password is None:
        new_password = getpass.getpass("New password: ")
        if getpass.getpass("Confirm new password: ") != new_password:
            print("The two passwords do not match; nothing was changed.", flush=True)
            return 1

    from local.auth_app.utils.password_reset import ResetError, reset_password
    try:
        result = reset_password(ns.email, new_password)
    except ResetError as exc:
        print(f"Reset failed: {exc}", flush=True)
        return 1

    print(f"Password updated for {result['email']}.\nDatabase: {db}", flush=True)
    if result["registry_updated"]:
        print(f"Account-integrity registry updated: {result['registry_path']}", flush=True)
    else:
        print(f"Account is not tracked in the integrity registry ({result['registry_path']}); "
              "nothing to update there.\nIf sign-in still says 'protected account details were "
              "modified locally', run this again from the folder the app starts in.", flush=True)
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "activate":
        sys.exit(_cli_activate(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "activation-status":
        sys.exit(_cli_activation_status())
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        sys.exit(_cli_reset_password(sys.argv[2:]))

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
