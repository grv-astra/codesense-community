"""One-time: generate the vendor Ed25519 keypair used to sign entitlements.json.

The PUBLIC pem is baked into every build as ENTITLEMENTS_PUBLIC_KEY. The PRIVATE
pem never leaves the vendor signing machine. Run offline.
"""
import os
from django.core.management.base import BaseCommand
from licenses.services import crypto


class Command(BaseCommand):
    help = "Generate the vendor Ed25519 keypair for signing entitlements files."

    def add_arguments(self, parser):
        parser.add_argument("--outdir", default=".")
        parser.add_argument("--password", default=None,
                            help="Encrypt the private key with this passphrase.")

    def handle(self, *args, **o):
        priv, pub = crypto.generate_keypair()
        os.makedirs(o["outdir"], exist_ok=True)
        priv_path = os.path.join(o["outdir"], "vendor_entitlements_private.pem")
        pub_path = os.path.join(o["outdir"], "vendor_entitlements_public.pem")
        crypto.save_private_key(priv, priv_path, password=o["password"])
        crypto.save_public_key(pub, pub_path)
        self.stdout.write(self.style.SUCCESS(f"Wrote {priv_path} and {pub_path}"))
        self.stdout.write("Bake the PUBLIC pem into builds as ENTITLEMENTS_PUBLIC_KEY.")
