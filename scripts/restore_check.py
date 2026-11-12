"""Restore an encrypted backup into an isolated Docker project, verify every table, then remove the clone."""
import argparse
import base64
import datetime
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid
from urllib.parse import quote
from maintenance_common import ROOT, DOCKER, read_env, execute, crypto_command, SNAPSHOT_CODE


def restore_check(path):
    os.umask(0o077)
    env = read_env()
    # The decryptor image is local/trusted; the backup cannot choose the decryptor.
    decryptor = execute(DOCKER + ["image", "inspect", "team-vault-app", "--format", "{{.Id}}"]).decode().strip()
    encrypted = Path(path).read_bytes()
    key_env = dict(os.environ, VAULT_MASTER_KEY=env["VAULT_MASTER_KEY"])
    negative = subprocess.run(crypto_command(decryptor, "decrypt"), input=encrypted, capture_output=True,
        env=dict(key_env, VAULT_MASTER_KEY=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()))
    if negative.returncode == 0 or negative.stdout:
        raise RuntimeError("Wrong-key protection failed.")
    body = json.loads(execute(crypto_command(decryptor, "decrypt"), data=encrypted, env=key_env))
    if body["format"] != "postgres-custom":
        raise RuntimeError("Unsupported backup format.")
    project = "team-vault-restore-check-" + uuid.uuid4().hex[:10]
    folder = (ROOT / "backups" / project).resolve()
    if not folder.is_relative_to((ROOT / "backups").resolve()):
        raise RuntimeError("Unsafe test directory.")
    folder.mkdir(mode=0o700)
    config = folder / "compose.json"
    app_password, root_password = secrets.token_hex(24), secrets.token_hex(24)
    database_url = "postgresql://" + quote(body["db_user"], safe="") + ":" + app_password + "@db:5432/" + quote(body["db_name"], safe="")
    configuration = {"services": {
        "db": {"image": body["db_image"], "pull_policy": "never", "environment": {"POSTGRES_USER": "vault_root", "POSTGRES_PASSWORD": root_password,
            "POSTGRES_DB": "postgres", "APP_DB_NAME": body["db_name"], "APP_DB_USER": body["db_user"], "APP_DB_PASSWORD": app_password},
            "volumes": ["database:/var/lib/postgresql", str(ROOT / "docker/init-db.sh") + ":/docker-entrypoint-initdb.d/10-app.sh:ro"], "networks": ["check"]},
        "app": {"image": body["app_image"], "pull_policy": "never", "entrypoint": ["python"], "environment": {
            "DATABASE_URL": database_url, "DJANGO_SECRET_KEY": secrets.token_urlsafe(48), "VAULT_MASTER_KEY": env["VAULT_MASTER_KEY"],
            "ALLOWED_HOSTS": "testserver,localhost", "SECURE_COOKIES": "false"}, "networks": ["check"], "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}},
        "volumes": {"database": {}}, "networks": {"check": {"internal": True}}}
    config.write_text(json.dumps(configuration), encoding="utf-8"); config.chmod(0o600)
    command = DOCKER + ["compose", "-p", project, "-f", str(config)]
    started = False
    try:
        started = True
        execute(command + ["up", "-d", "db"])
        db_container = execute(command + ["ps", "-q", "db"]).decode().strip()
        inspected = json.loads(execute(DOCKER + ["inspect", db_container]))[0]
        mounts = [item.get("Name", "") for item in inspected["Mounts"] if item["Type"] == "volume"]
        if mounts != [project + "_database"] or inspected["HostConfig"].get("PortBindings"):
            raise RuntimeError("The restore target is not isolated.")
        for _ in range(100):
            ready = subprocess.run(command + ["exec", "-T", "db", "pg_isready", "-h", "127.0.0.1", "-U", "vault_root", "-d", body["db_name"]], capture_output=True)
            if ready.returncode == 0:
                break
            time.sleep(.3)
        else:
            raise RuntimeError("The isolated database did not start.")
        execute(command + ["exec", "-T", "db", "pg_restore", "--exit-on-error", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--role", body["db_user"], "-U", "vault_root", "-d", body["db_name"]], data=base64.b64decode(body["dump"]))
        verify = SNAPSHOT_CODE + '''
from vault import crypto
from vault.models import ItemVersion,TotpConfig,RecoveryCode,IssuedCode,MicrosoftConfig,LdapConfig
from vault.services import generate_totp
from django.db import connection
decoded=0;totp=0
for row in ItemVersion.objects.iterator(): crypto.unseal(row.payload,f'item:{row.item_id}:{row.number}');decoded+=1
for row in TotpConfig.objects.iterator():
 value=crypto.unseal(row.payload,f'totp:{row.item_id}:{row.revision}');code,expiry=generate_totp(value)
 assert code.isdigit() and len(code)==value['digits'];decoded+=1;totp+=1
for row in RecoveryCode.objects.iterator(): crypto.unseal(row.payload,f'recovery:{row.item_id}:{row.pk}');decoded+=1
for row in IssuedCode.objects.iterator(): crypto.unseal(row.payload,f'issued:{row.item_id}:{row.actor_id}:{row.request_id}');decoded+=1
for row in MicrosoftConfig.objects.iterator():
 if row.secret_payload: crypto.unseal(row.secret_payload,'integration:microsoft:secret');decoded+=1
for row in LdapConfig.objects.iterator():
 if row.bind_secret_payload: crypto.unseal(row.bind_secret_payload,'integration:ldap:bind-password');decoded+=1
with connection.cursor() as cursor:
 cursor.execute('SELECT rolsuper,rolcreatedb FROM pg_roles WHERE rolname=current_user');superuser,createdb=cursor.fetchone()
assert not superuser and not createdb
print(json.dumps(dict(tables=snapshot(),decoded=decoded,totp=totp,runtime_superuser=superuser)))
'''
        result = json.loads(execute(command + ["run", "--rm", "-T", "--no-deps", "app", "-c", verify]))
        if result["tables"] != body["tables"]:
            raise RuntimeError("Restored table checksums do not match the snapshot.")
        report = {"status": "passed", "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "backup": Path(path).name, "tables": len(result["tables"]), "rows": sum(item["rows"] for item in result["tables"].values()),
            "decrypted_values": result["decoded"], "totp_configurations": result["totp"], "wrong_key_rejected": True,
            "runtime_superuser": result["runtime_superuser"], "isolated_project": project}
    finally:
        if started:
            # Only this freshly generated project's volume may ever be removed.
            container = execute(command + ["ps", "-q", "db"]).decode().strip()
            if container:
                inspected = json.loads(execute(DOCKER + ["inspect", container]))[0]
                volumes = [item.get("Name", "") for item in inspected["Mounts"] if item["Type"] == "volume"]
                if volumes != [project + "_database"] or not project.startswith("team-vault-restore-check-"):
                    raise RuntimeError("Refusing cleanup: unexpected restore volume.")
            execute(command + ["down", "-v"])
        config.unlink(missing_ok=True)
    report["clone_removed"] = True
    report_path = folder / "result.json"; report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return report_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("backup", type=Path); args = parser.parse_args()
    try:
        restore_check(args.backup)
    except Exception:
        raise SystemExit("Restore check failed. No database contents or credentials were printed; the production project was not a restore target.") from None
