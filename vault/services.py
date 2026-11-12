import ipaddress
import time
import pyotp
from django.core.exceptions import ValidationError
from .models import AuditEvent, Vault


def audit(request, action, target="", vault=None, **details):
    # Forwarded addresses are accepted only by middleware from an explicitly trusted proxy.
    address = getattr(request, "client_ip", request.META.get("REMOTE_ADDR", ""))
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        address = None
    actor = request.user if request.user.is_authenticated else None
    return AuditEvent.objects.create(actor=actor, actor_name=str(actor) if actor else "Неавторизованный пользователь",
        action=action, target=str(target), vault=vault, ip=address, details=details)


def personal_vault(user):
    return Vault.objects.get_or_create(personal_owner=user, defaults={"name": "Мои рабочие секреты"})[0]


def totp_data(configuration):
    try:
        if configuration.startswith("otpauth://"):
            otp = pyotp.parse_uri(configuration)
            if not isinstance(otp, pyotp.TOTP):
                raise ValueError("Only TOTP is supported")
        else:
            otp = pyotp.TOTP(configuration.replace(" ", "").upper())
        algorithm = otp.digest().name.lower()
        if otp.digits not in (6, 8) or algorithm not in ("sha1", "sha256", "sha512") or not 15 <= otp.interval <= 120:
            raise ValueError("Unsupported TOTP parameters")
        # Decode and validate the secret before accepting it. An empty key is not valid.
        if len(otp.byte_secret()) < 10:
            raise ValueError("Secret too short")
        otp.now()
        return {"secret": otp.secret, "digits": otp.digits, "interval": otp.interval, "algorithm": algorithm}
    except Exception:
        # Do not echo malformed configuration or its exception message to a user/log.
        raise ValidationError("Не удалось прочитать настройку. Нужен секрет или URI временного кода TOTP.") from None


def generate_totp(data):
    import hashlib
    otp = pyotp.TOTP(data["secret"], digits=data["digits"], interval=data["interval"], digest=getattr(hashlib, data["algorithm"]))
    instant = int(time.time())
    return otp.at(instant), (instant // otp.interval + 1) * otp.interval
