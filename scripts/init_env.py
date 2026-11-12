"""Run once on the deployment host; never overwrite existing secrets."""
import base64
import os
from pathlib import Path
import secrets

root = Path(__file__).resolve().parent.parent
target = root / ".env"
if target.exists():
    raise SystemExit(".env already exists; refusing to replace passwords or encryption keys")
values = {
    "DJANGO_SECRET_KEY": secrets.token_urlsafe(48),
    "VAULT_MASTER_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    "LOCAL_ADMIN_PASSWORD": secrets.token_urlsafe(24),
    "POSTGRES_PASSWORD": secrets.token_hex(24),
    "POSTGRES_ROOT_PASSWORD": secrets.token_hex(24),
}
text = (root / ".env.example").read_text(encoding="utf-8")
for name, value in values.items():
    text = text.replace(name + "=\n", name + "=" + value + "\n")
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
    stream.write(text)
print("Created .env with fresh passwords and keys. Values were not printed.")
