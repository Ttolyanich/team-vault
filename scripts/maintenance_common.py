"""Host-side maintenance helpers. Never print environment values or decrypted data."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKER = ["docker"] if hasattr(os, "geteuid") and os.geteuid() == 0 else ["sudo", "-n", "--preserve-env=VAULT_MASTER_KEY", "docker"]


def read_env():
    result = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            result[key.strip()] = value
    return result


def execute(args, *, data=None, env=None):
    result = subprocess.run(args, input=data, capture_output=True, env=env)
    if result.returncode:
        folder = ROOT / "backups"; folder.mkdir(mode=0o700, exist_ok=True)
        log = folder / "maintenance-error.log"
        descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(result.stderr + b"\n")
        raise RuntimeError("Maintenance command failed; restricted diagnostic log was saved, command arguments were not printed.")
    return result.stdout


def compose(*args):
    return DOCKER + ["compose", "--project-directory", str(ROOT)] + list(args)


def image_id(service):
    container = execute(compose("ps", "-q", service)).decode().strip()
    if not container:
        raise RuntimeError("The source container must be running to create a snapshot.")
    return execute(DOCKER + ["inspect", "--format", "{{.Image}}", container]).decode().strip()


CRYPTO_CODE = '''import os,sys,json,base64,secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
 key=base64.urlsafe_b64decode(os.environ['VAULT_MASTER_KEY'])
 raw=sys.stdin.buffer.read()
 if sys.argv[1]=='encrypt':
  context=sys.argv[2]; nonce=secrets.token_bytes(12)
  body=AESGCM(key).encrypt(nonce,raw,context.encode())
  print(json.dumps(dict(version=2,context=context,nonce=base64.b64encode(nonce).decode(),data=base64.b64encode(body).decode())))
 else:
  envelope=json.loads(raw)
  if envelope['version']!=2: raise ValueError()
  sys.stdout.buffer.write(AESGCM(key).decrypt(base64.b64decode(envelope['nonce']),base64.b64decode(envelope['data']),envelope['context'].encode()))
except Exception:
 raise SystemExit('Invalid backup or encryption key; no data was printed.')
'''


def crypto_command(image, operation, context=""):
    return DOCKER + ["run", "--rm", "-i", "--network", "none", "-e", "VAULT_MASTER_KEY", "--entrypoint", "python", image, "-c", CRYPTO_CODE, operation, context]


SNAPSHOT_CODE = '''import os,json,hashlib
os.environ.setdefault('DJANGO_SETTINGS_MODULE','config.settings')
import django
django.setup()
from django.apps import apps
def snapshot():
 result={}
 for model in sorted(apps.get_models(include_auto_created=True),key=lambda x:x._meta.label):
  if model._meta.proxy or not model._meta.managed: continue
  digest=hashlib.sha256(); count=0
  for row in model._default_manager.order_by(model._meta.pk.name).values().iterator(chunk_size=1000):
   digest.update(json.dumps(row,sort_keys=True,default=str,separators=(',',':')).encode());digest.update(b'\\n');count+=1
  result[model._meta.label]=dict(rows=count,sha256=digest.hexdigest())
 return result
'''
