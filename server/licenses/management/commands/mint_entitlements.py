"""Offline: mint a signed entitlements.json for one customer / deployment.

    python manage.py mint_entitlements --edition pro --customer "Acme Corp" \
        --expires 2027-09-04 --private-key vendor_entitlements_private.pem \
        [--override-limit projects=20] [--override-model-tier mid] --out entitlements.json

This command is a vendor / build-host tool (never invoked by the running app or a customer deployment).
"""
import json
from datetime import datetime, timezone
from django.core.management.base import BaseCommand, CommandError

from licenses.editions import EDITIONS, LIMIT_KEYS
from licenses.services import crypto


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Command(BaseCommand):
    help = "Mint a signed entitlements.json (offline)."

    def add_arguments(self, parser):
        parser.add_argument("--edition", required=True)
        parser.add_argument("--customer", default="")
        parser.add_argument("--expires", default=None, help="YYYY-MM-DD or blank = perpetual")
        parser.add_argument("--private-key", required=True)
        parser.add_argument("--key-password", default=None)
        parser.add_argument("--override-limit", action="append", default=[],
                            help="key=value, repeatable (e.g. projects=20)")
        parser.add_argument("--override-model-tier", default=None, choices=["low", "mid", "high"])
        parser.add_argument("--out", required=True)

    def handle(self, *args, **o):
        if o["edition"] not in EDITIONS:
            raise CommandError(f"Unknown edition {o['edition']!r}; "
                               f"expected one of {sorted(EDITIONS)}")

        expires_at = None
        if o["expires"]:
            try:
                day = datetime.strptime(o["expires"], "%Y-%m-%d")
            except ValueError:
                raise CommandError(
                    f"--expires must be YYYY-MM-DD, got {o['expires']!r}"
                )
            # Inclusive: the license is valid through the END of the named day.
            expires_at = day.replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            ).isoformat()

        limit_overrides = {}
        for item in o["override_limit"]:
            if "=" not in item:
                raise CommandError(
                    f"--override-limit must be key=value, got {item!r}"
                )
            k, _, v = item.partition("=")
            if k not in LIMIT_KEYS:
                raise CommandError(f"Unknown limit key {k!r}; expected {list(LIMIT_KEYS)}")
            try:
                limit_overrides[k] = int(v)
            except ValueError:
                raise CommandError(
                    f"--override-limit {k!r} value must be an integer, got {v!r}"
                )

        overrides = {}
        if limit_overrides:
            overrides["limits"] = limit_overrides
        if o["override_model_tier"]:
            overrides["model_tier"] = o["override_model_tier"]

        payload = {
            "edition": o["edition"],
            "customer": o["customer"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at,
        }
        if overrides:
            payload["overrides"] = overrides

        key_password = o["key_password"]
        if isinstance(key_password, str):
            key_password = key_password.encode()
        priv = crypto.load_private_key(o["private_key"], password=key_password)
        signature = crypto.sign_message(priv, _canonical(payload))

        with open(o["out"], "w", encoding="utf-8") as f:
            json.dump({"payload": payload, "signature": signature}, f, indent=2)
        self.stdout.write(self.style.SUCCESS(
            f"Wrote {o['out']} — edition={o['edition']} customer={o['customer']!r} "
            f"expires={expires_at or 'perpetual'}"
        ))
