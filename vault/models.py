import uuid
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import Q


class User(AbstractUser):
    display_name = models.CharField(max_length=200, blank=True)
    entra_tenant = models.CharField(max_length=64, blank=True)
    entra_oid = models.CharField(max_length=64, blank=True)
    ad_object_guid = models.UUIDField(null=True, blank=True, unique=True)
    is_local_admin = models.BooleanField(default=False)
    is_manager = models.BooleanField(default=False)
    manager = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="employees")
    department = models.ForeignKey("Department", null=True, blank=True, on_delete=models.PROTECT, related_name="employees")
    team_revision = models.PositiveIntegerField(default=0)
    auth_revision = models.PositiveIntegerField(default=0)

    def _get_session_auth_hash(self, secret=None):
        base = super()._get_session_auth_hash(secret=secret)
        if not self.auth_revision:
            return base
        from django.utils.crypto import salted_hmac
        return salted_hmac("vault.User.session_revision", f"{base}:{self.auth_revision}", secret=secret, algorithm="sha256").hexdigest()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["entra_tenant", "entra_oid"], condition=~Q(entra_oid=""), name="unique_entra_identity")]

    def __str__(self):
        return self.display_name or self.get_full_name() or self.username


class Department(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160, unique=True)
    head = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="headed_departments")
    revision = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.name


class Vault(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160)
    description = models.CharField(max_length=500, blank=True)
    personal_owner = models.OneToOneField(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.PROTECT, related_name="personal_vault")
    department = models.ForeignKey(Department, null=True, blank=True, on_delete=models.PROTECT, related_name="vaults")
    access_mode = models.CharField(max_length=12, choices=[("selected", "Выбранные сотрудники"), ("department", "Все сотрудники подразделения")], default="selected")
    department_role = models.CharField(max_length=10, choices=[("reader", "Просмотр"), ("editor", "Редактирование")], default="reader")
    department_totp = models.BooleanField(default=False)
    access_revision = models.PositiveIntegerField(default=0)
    deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="deleted_vaults")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class Membership(models.Model):
    vault = models.ForeignKey(Vault, on_delete=models.CASCADE, related_name="memberships")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=[("reader", "Читатель"), ("editor", "Редактор"), ("owner", "Владелец")])
    can_totp = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vault", "user"], name="unique_membership")]


class Item(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vault = models.ForeignKey(Vault, on_delete=models.PROTECT, related_name="items")
    title = models.CharField(max_length=200)
    kind = models.CharField(max_length=10, choices=[("account", "Учётная запись"), ("token", "API-токен"), ("note", "Защищённая заметка")], default="account")
    tags = models.CharField(max_length=250, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="owned_items")
    version = models.PositiveIntegerField(default=1)
    deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="deleted_items")
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)


class ItemVersion(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="versions")
    number = models.PositiveIntegerField()
    payload = models.JSONField()
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["item", "number"], name="unique_item_version")]


class TotpConfig(models.Model):
    item = models.OneToOneField(Item, primary_key=True, on_delete=models.CASCADE, related_name="totp_config")
    payload = models.JSONField()
    revision = models.PositiveIntegerField(default=1)


class RecoveryCode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name="recovery_codes")
    payload = models.JSONField()
    used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    actor_name = models.CharField(max_length=200)
    action = models.CharField(max_length=80)
    target = models.CharField(max_length=100, blank=True)
    vault = models.ForeignKey(Vault, null=True, on_delete=models.PROTECT)
    ip = models.GenericIPAddressField(null=True)
    details = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)


class IssuedCode(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    item = models.ForeignKey(Item, on_delete=models.CASCADE)
    request_id = models.UUIDField()
    payload = models.JSONField()
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["actor", "item", "request_id"], name="unique_totp_request")]


class LoginAttempt(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    started_at = models.DateTimeField()


class SystemState(models.Model):
    key = models.CharField(max_length=80, primary_key=True)
    value = models.CharField(max_length=200)


class MicrosoftConfig(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    enabled = models.BooleanField(default=False)
    tenant_id = models.CharField(max_length=64, blank=True)
    client_id = models.CharField(max_length=64, blank=True)
    secret_payload = models.JSONField(null=True, blank=True)
    revision = models.PositiveIntegerField(default=1)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    updated_at = models.DateTimeField(auto_now=True)


class LdapConfig(models.Model):
    TRANSPORTS = [("ldaps", "LDAPS — шифрование, обычно порт 636"),
        ("starttls", "LDAP + StartTLS — шифрование, обычно порт 389"),
        ("plain", "LDAP без шифрования — обычно порт 389")]
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    enabled = models.BooleanField(default=False)
    host = models.CharField(max_length=253, blank=True)
    port = models.PositiveIntegerField(default=636)
    transport = models.CharField(max_length=12, choices=TRANSPORTS, default="ldaps")
    base_dn = models.CharField(max_length=1024, blank=True)
    bind_dn = models.CharField(max_length=1024, blank=True)
    bind_secret_payload = models.JSONField(null=True, blank=True)
    allowed_group_dn = models.CharField(max_length=1024, blank=True)
    ca_certificate = models.TextField(blank=True)
    allow_plain = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=0)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def ready(self):
        return bool(self.enabled and self.host and self.base_dn and self.bind_dn and self.bind_secret_payload
            and (self.transport != "plain" or self.allow_plain))
