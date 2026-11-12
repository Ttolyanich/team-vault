"""Versioned envelope encryption. No plaintext keys are stored with database records."""
import base64
import json
import secrets
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value)


def master_key():
    key = unb64(settings.VAULT_MASTER_KEY)
    if len(key) != 32:
        raise ValueError("VAULT_MASTER_KEY must encode exactly 32 random bytes")
    return key


def seal(value, context):
    aad = context.encode("utf-8")
    dek, nonce, wrap_nonce = secrets.token_bytes(32), secrets.token_bytes(12), secrets.token_bytes(12)
    return {"v": 1, "nonce": b64(nonce), "wrap_nonce": b64(wrap_nonce),
            "key": b64(AESGCM(master_key()).encrypt(wrap_nonce, dek, b"wrap|" + aad)),
            "data": b64(AESGCM(dek).encrypt(nonce, json.dumps(value, ensure_ascii=False).encode(), aad))}


def unseal(envelope, context):
    if envelope.get("v") != 1:
        raise ValueError("Unsupported encryption envelope")
    aad = context.encode("utf-8")
    dek = AESGCM(master_key()).decrypt(unb64(envelope["wrap_nonce"]), unb64(envelope["key"]), b"wrap|" + aad)
    return json.loads(AESGCM(dek).decrypt(unb64(envelope["nonce"]), unb64(envelope["data"]), aad))
