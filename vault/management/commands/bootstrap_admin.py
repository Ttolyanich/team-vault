from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from vault.crypto import master_key
import hashlib
from vault.models import User, Vault, AuditEvent, SystemState


class Command(BaseCommand):
    help = "Create/synchronize the reserved local administrator from environment variables."

    @transaction.atomic
    def handle(self, *args, **kwargs):
        fingerprint = hashlib.sha256(master_key()).hexdigest()
        marker, _ = SystemState.objects.get_or_create(key="master_key_fingerprint", defaults={"value": fingerprint})
        if marker.value != fingerprint:
            raise CommandError("VAULT_MASTER_KEY does not match this database; refusing startup. Restore the original key.")
        password = settings.LOCAL_ADMIN_PASSWORD
        if len(password) < 16:
            raise CommandError("LOCAL_ADMIN_PASSWORD must contain at least 16 characters")
        user, created = User.objects.get_or_create(username=settings.LOCAL_ADMIN_USERNAME)
        if not created and not user.is_local_admin:
            raise CommandError("Reserved admin username belongs to another account")
        changed = created or not user.check_password(password)
        user.is_local_admin = user.is_superuser = user.is_staff = user.is_active = True
        user.display_name = "Локальный администратор"
        if changed:
            user.set_password(password)
        user.save()
        Vault.objects.get_or_create(personal_owner=user, defaults={"name": "Мои рабочие секреты"})
        if changed:
            AuditEvent.objects.create(actor=user, actor_name=str(user), action="admin.bootstrap", details={"created": created})
        self.stdout.write("Local administrator is ready. Password was not printed.")
