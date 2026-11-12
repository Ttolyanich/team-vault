from dataclasses import dataclass, field
from django.conf import settings
from . import crypto
from .models import MicrosoftConfig


@dataclass(frozen=True)
class MicrosoftSettings:
    enabled: bool
    tenant_id: str
    client_id: str
    secret_set: bool
    source: str
    revision: int = 0
    client_secret: str = field(default="", repr=False)

    @property
    def ready(self):
        return self.enabled and bool(self.tenant_id and self.client_id and self.secret_set)


def microsoft_settings(include_secret=False):
    config = MicrosoftConfig.objects.filter(pk=1).first()
    if config:
        secret = crypto.unseal(config.secret_payload, "integration:microsoft:secret") if include_secret and config.secret_payload else ""
        return MicrosoftSettings(config.enabled, config.tenant_id, config.client_id, bool(config.secret_payload), "database", config.revision, secret)
    secret = settings.ENTRA_CLIENT_SECRET
    return MicrosoftSettings(bool(settings.ENTRA_TENANT_ID and settings.ENTRA_CLIENT_ID and secret),
        settings.ENTRA_TENANT_ID, settings.ENTRA_CLIENT_ID, bool(secret), "environment", 0, secret if include_secret else "")
