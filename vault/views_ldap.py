import datetime
import hashlib
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST, require_http_methods
from . import crypto
from .forms import LdapForm, LdapLoginForm
from .ldap_directory import ldap_settings, check_directory, authenticate_directory, DirectoryError
from .models import LdapConfig, SystemState, LoginAttempt, User
from .services import audit, personal_vault


@login_required
@require_http_methods(["GET", "POST"])
@sensitive_post_parameters("bind_password", "ca_certificate")
def ldap_config(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    current = ldap_settings()
    fields = ("enabled", "host", "port", "transport", "base_dn", "bind_dn", "allowed_group_dn", "ca_certificate", "allow_plain", "revision")
    form = LdapForm(request.POST if request.method == "POST" else None, current=current,
        initial={key: getattr(current, key) for key in fields})
    if request.method == "POST" and form.is_valid():
        values = form.cleaned_data
        with transaction.atomic():
            SystemState.objects.get_or_create(key="ldap_settings_lock", defaults={"value": ""})
            SystemState.objects.select_for_update().get(key="ldap_settings_lock")
            config = ldap_settings()
            if config.revision != values["revision"]:
                form.add_error(None, "Настройки уже изменены. Обновите страницу и повторите.")
            else:
                for key in fields:
                    if key != "revision":
                        setattr(config, key, values[key])
                if values["clear_password"]:
                    config.bind_secret_payload = None
                elif values["bind_password"]:
                    config.bind_secret_payload = crypto.seal(values["bind_password"], "integration:ldap:bind-password")
                config.updated_by = request.user
                config.revision += 1
                config.save()
                audit(request, "ldap.settings_saved", "ldap", enabled=config.enabled, transport=config.transport,
                    password_changed=bool(values["bind_password"] or values["clear_password"]), revision=config.revision)
                messages.success(request, "Настройки AD / LDAP сохранены. Перезапуск не требуется.")
                return redirect("ldap_config")
    return render(request, "ldap.html", {"form": form, "ldap": current})


@login_required
@require_POST
def ldap_check(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    config = ldap_settings()
    if not all((config.host, config.base_dn, config.bind_dn, config.bind_secret_payload)):
        return JsonResponse({"error": "Сначала сохраните сервер, Base DN, служебную учётную запись и её пароль."}, status=400)
    try:
        check_directory(config)
    except DirectoryError as error:
        audit(request, "ldap.connection_checked", "ldap", success=False)
        return JsonResponse({"error": str(error) + " Проверьте адрес, порт, режим защиты, CA, учётную запись и область поиска."}, status=400)
    audit(request, "ldap.connection_checked", "ldap", success=True)
    return JsonResponse({"message": "Подключение и вход служебной учётной записи работают. Base DN и указанная группа доступны. Вход сотрудника проверьте отдельно на странице входа."})


def login_rate_allowed(request, username):
    peer = getattr(request, "client_ip", request.META.get("REMOTE_ADDR", ""))
    keys = [("ldap-peer:" + peer, 1000), ("ldap-user:" + username.casefold(), 10)]
    allowed = True
    with transaction.atomic():
        for raw, limit in keys:
            key = hashlib.sha256(raw.encode()).hexdigest()
            attempt, _ = LoginAttempt.objects.get_or_create(key=key, defaults={"started_at": timezone.now()})
            attempt = LoginAttempt.objects.select_for_update().get(pk=key)
            if attempt.started_at < timezone.now() - datetime.timedelta(minutes=15):
                attempt.count, attempt.started_at = 0, timezone.now()
            if attempt.count >= limit:
                allowed = False
            else:
                attempt.count += 1
                attempt.save()
    return allowed


@require_POST
@sensitive_post_parameters("password")
def ldap_login(request):
    form = LdapLoginForm(request.POST)
    error = "Не удалось войти через AD. Проверьте логин и пароль или обратитесь к администратору."
    if not form.is_valid():
        return render(request, "login.html", {"ldap_login_form": form, "ldap_error": error}, status=400)
    username = form.cleaned_data["username"]
    if not login_rate_allowed(request, username):
        audit(request, "auth.ldap_rate_limited")
        return render(request, "login.html", {"ldap_login_form": form, "ldap_error": "Слишком много попыток. Повторите через 15 минут."}, status=429)
    try:
        identity = authenticate_directory(ldap_settings(), username, form.cleaned_data["password"])
        with transaction.atomic():
            user, created = User.objects.get_or_create(ad_object_guid=identity.guid,
                defaults={"username": "ad_" + identity.guid.hex})
            if not user.is_active or user.is_local_admin or user.entra_oid:
                raise DirectoryError("Вход отключён.")
            user.display_name = identity.name
            user.email = identity.email
            if created or user.has_usable_password():
                user.set_unusable_password()
            user.save(update_fields=["display_name", "email", "password"])
            personal_vault(user)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        LoginAttempt.objects.filter(key=hashlib.sha256(("ldap-user:" + username.casefold()).encode()).hexdigest()).delete()
        audit(request, "auth.ldap_login")
        return redirect("home")
    except DirectoryError:
        audit(request, "auth.ldap_denied")
        return render(request, "login.html", {"ldap_login_form": form, "ldap_error": error}, status=400)
