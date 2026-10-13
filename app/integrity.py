import hashlib
import hmac
import os

from dotenv import load_dotenv

load_dotenv()


def _key():
    key = os.environ.get("HMAC_KEY")
    if not key:
        raise RuntimeError("HMAC_KEY is missing in .env")
    return bytes.fromhex(key)


def _to_bytes(value):
    return value if isinstance(value, bytes) else str(value).encode("utf-8")


def compute_hmac(user_id, title, encrypted_content):
    parts = [str(user_id).encode(), title.encode("utf-8"), _to_bytes(encrypted_content)]
    # Length prefix so ("ab", "c") and ("a", "bc") give different messages.
    message = b"".join(len(p).to_bytes(4, "big") + p for p in parts)
    return hmac.new(_key(), message, hashlib.sha256).hexdigest()


def verify_hmac(user_id, title, encrypted_content, expected):
    if not expected:
        return False
    return hmac.compare_digest(compute_hmac(user_id, title, encrypted_content), expected)
