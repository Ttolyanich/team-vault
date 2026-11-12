"""Run on the Docker host. Output is an encrypted PostgreSQL backup, never plaintext SQL."""
import base64
import datetime
import json
import os
import subprocess
import uuid
from maintenance_common import ROOT, compose, image_id, read_env, execute, crypto_command, SNAPSHOT_CODE


def backup():
    os.umask(0o077)
    env = read_env()
    app_image, db_image = image_id("app"), image_id("db")
    export = SNAPSHOT_CODE + '''
import sys
from django.db import connection,transaction
with transaction.atomic():
 with connection.cursor() as cursor:
  cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
  cursor.execute('SELECT pg_export_snapshot()');snapshot_id=cursor.fetchone()[0]
 print(json.dumps(dict(id=snapshot_id,tables=snapshot())),flush=True)
 sys.stdin.buffer.read(1)
'''
    process = subprocess.Popen(compose("exec", "-T", "app", "python", "-u", "-c", export), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        manifest = json.loads(process.stdout.readline())
        dump = execute(compose("exec", "-T", "db", "pg_dump", "-Fc", "--snapshot", manifest["id"], "-U", env["POSTGRES_USER"], env["POSTGRES_DB"]))
    finally:
        process.communicate(input=b"x")
    if process.returncode:
        raise RuntimeError("Could not hold a consistent database snapshot.")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    body = json.dumps({"format": "postgres-custom", "app_image": app_image, "db_image": db_image,
        "tables": manifest["tables"], "db_user": env["POSTGRES_USER"], "db_name": env["POSTGRES_DB"], "dump": base64.b64encode(dump).decode()}).encode()
    crypto_env = dict(os.environ, VAULT_MASTER_KEY=env["VAULT_MASTER_KEY"])
    encrypted = execute(crypto_command(app_image, "encrypt", "team-vault-backup:" + stamp), data=body, env=crypto_env)
    folder = ROOT / "backups"; folder.mkdir(mode=0o700, exist_ok=True); folder.chmod(0o700)
    path = folder / ("backup-" + stamp + "-" + uuid.uuid4().hex[:6] + ".json")
    with path.open("xb") as stream:
        stream.write(encrypted)
    path.chmod(0o600)
    return path


if __name__ == "__main__":
    try:
        print(backup())
    except Exception:
        raise SystemExit("Backup failed. No credentials or database contents were printed.") from None
