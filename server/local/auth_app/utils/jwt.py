import jwt
import os
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


def _load_or_create_secret() -> str:
    """JWT_TOKEN_SECRET if set, else a per-install secret persisted in
    DATA_DIR -- mirrors settings.py's own SECRET_KEY handling. No hardcoded
    fallback: a literal shared across every install would let anyone who
    reads the source forge tokens for any role."""
    env_secret = os.getenv("JWT_TOKEN_SECRET")
    if env_secret:
        return env_secret
    from django.conf import settings
    secret_file = Path(settings.DATA_DIR) / "jwt_secret"
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(48)
    secret_file.write_text(secret, encoding="utf-8")
    return secret


JWT_SECRET = _load_or_create_secret()
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60

def generate_token(payload):
    payload["iat"] =  datetime.now(timezone.utc)
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXP_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None