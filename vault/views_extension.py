import datetime
import hashlib
import json
import time
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from . import crypto
from .access import permissions, visible_vaults, totp_access
from .models import Item, TotpConfig, LoginAttempt
from .services import audit, generate_totp
from .views import item_for


def extension_api(view_func=None, *, require_auth=True):
    def decorator(fn):
        @csrf_exempt
        def wrapped(request, *args, **kwargs):
            if request.headers.get("X-TeamVault-Extension") != "1":
                return JsonResponse({"error": "Требуется заголовок расширения."}, status=403)

            if not request.user.is_authenticated:
                auth_header = request.headers.get("Authorization", "")
                session_key = None
                if auth_header.startswith("Bearer "):
                    session_key = auth_header[7:].strip()
                elif request.headers.get("X-Session-Key"):
                    session_key = request.headers.get("X-Session-Key", "").strip()

                if session_key:
                    store = SessionStore(session_key=session_key)
                    user_id = store.get("_auth_user_id")
                    if user_id:
                        User = get_user_model()
                        try:
                            user = User.objects.get(pk=user_id, is_active=True)
                            request.user = user
                        except User.DoesNotExist:
                            pass

            if require_auth and not request.user.is_authenticated:
                return JsonResponse({"error": "Необходима авторизация."}, status=401)

            return fn(request, *args, **kwargs)
        return wrapped

    if view_func is not None:
        return decorator(view_func)
    return decorator


@require_GET
@extension_api(require_auth=False)
def extension_status(request):
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False})
    display_name = getattr(request.user, "display_name", "") or request.user.get_full_name() or request.user.username
    if display_name.startswith("ad_") and request.user.email:
        display_name = request.user.email.split("@")[0]
    return JsonResponse({
        "authenticated": True,
        "username": request.user.username,
        "name": display_name,
        "email": getattr(request.user, "email", "") or "",
    })


@require_POST
@extension_api(require_auth=False)
def extension_login(request):
    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        data = request.POST

    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return JsonResponse({"error": "Укажите логин и пароль."}, status=400)

    client_ip = getattr(request, "client_ip", request.META.get("REMOTE_ADDR", ""))
    key = hashlib.sha256((client_ip + "|ext-login").encode()).hexdigest()
    with transaction.atomic():
        attempt, _ = LoginAttempt.objects.get_or_create(key=key, defaults={"started_at": timezone.now()})
        attempt = LoginAttempt.objects.select_for_update().get(pk=key)
        if attempt.started_at < timezone.now() - datetime.timedelta(minutes=15):
            attempt.count, attempt.started_at = 0, timezone.now()
        if attempt.count >= 10:
            return JsonResponse({"error": "Слишком много попыток входа. Повторите позже."}, status=429)
        attempt.count += 1
        attempt.save()

    user = authenticate(request, username=username, password=password)
    if user and user.is_active:
        login(request, user)
        LoginAttempt.objects.filter(key=key).delete()
        audit(request, "extension.login")
        display_name = getattr(user, "display_name", "") or user.get_full_name() or user.username
        if display_name.startswith("ad_") and user.email:
            display_name = user.email.split("@")[0]
        return JsonResponse({
            "status": "ok",
            "token": request.session.session_key,
            "username": user.username,
            "name": display_name,
        })

    audit(request, "extension.login_denied")
    return JsonResponse({"error": "Неверный логин или пароль."}, status=400)


@require_POST
@extension_api
def extension_logout(request):
    audit(request, "extension.logout")
    logout(request)
    return JsonResponse({"status": "ok"})


@require_GET
@extension_api
def extension_find(request):
    domain = request.GET.get("domain", "").strip().lower()
    query = request.GET.get("q", "").strip().lower()

    vaults = visible_vaults(request.user)
    items_qs = Item.objects.filter(deleted=False, vault__in=vaults).select_related("vault")

    results = []
    # If a specific search query is given, filter items
    for item in items_qs:
        version_obj = item.versions.filter(number=item.version).first()
        if not version_obj:
            continue
        try:
            payload = crypto.unseal(version_obj.payload, f"item:{item.pk}:{item.version}")
        except Exception:
            continue

        item_url = (payload.get("url") or "").strip().lower()
        item_title = item.title.lower()
        item_login = (payload.get("login") or "").strip().lower()
        item_tags = (item.tags or "").lower()

        match = False
        if domain:
            # Clean domain matching (e.g. "crm.company.kz" or "company.kz")
            clean_domain = domain.removeprefix("www.")
            if clean_domain and clean_domain in item_url:
                match = True
            elif clean_domain and clean_domain in item_title:
                match = True

        if query:
            if query in item_title or query in item_login or query in item_url or query in item_tags:
                match = True

        if match or (not domain and not query):
            results.append({
                "id": str(item.pk),
                "title": item.title,
                "vault": item.vault.name,
                "login": payload.get("login", ""),
                "url": payload.get("url", ""),
                "has_totp": TotpConfig.objects.filter(item=item).exists(),
            })

    return JsonResponse({"items": results})


@require_POST
@extension_api
def extension_fill(request, item_id):
    item = item_for(request, item_id, "read")
    version_obj = item.versions.filter(number=item.version).first()
    if not version_obj:
        return JsonResponse({"error": "Версия записи не найдена."}, status=404)

    payload = crypto.unseal(version_obj.payload, f"item:{item.pk}:{item.version}")
    audit(request, "extension.item_filled", item.pk, item.vault)
    return JsonResponse({
        "login": payload.get("login", ""),
        "password": payload.get("password", ""),
    })


@require_POST
@extension_api
def extension_totp(request, item_id):
    item = item_for(request, item_id, "read")
    if not (permissions(request.user, item.vault)["totp"] or totp_access(request.user, item)):
        audit(request, "access.extension_totp_denied", item.pk)
        raise PermissionDenied

    config = TotpConfig.objects.filter(item=item).first()
    if not config:
        return JsonResponse({"error": "TOTP не настроен для этой записи."}, status=404)

    config_data = crypto.unseal(config.payload, f"totp:{item.pk}:{config.revision}")
    code, expiry = generate_totp(config_data)
    seconds_left = max(1, expiry - int(time.time()))
    audit(request, "extension.totp_issued", item.pk, item.vault)

    return JsonResponse({
        "code": code,
        "seconds_left": seconds_left,
    })
