import datetime
import hashlib
import uuid
import requests
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction, IntegrityError
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST
from authlib.integrations.django_client import OAuth
from . import crypto
from .access import permissions, recovery_access, recovery_manager_for, visible_vaults, effective_manager, manages_team, totp_access
from .forms import ItemForm, VaultForm, TotpForm, RecoveryForm, MicrosoftForm
from .models import User, Vault, Membership, Item, ItemVersion, TotpConfig, RecoveryCode, AuditEvent, IssuedCode, LoginAttempt, MicrosoftConfig, SystemState
from .microsoft import microsoft_settings
from .services import audit, personal_vault, totp_data, generate_totp
from .records import locked_item_for
from .transfers import can_move_item, can_copy_item


def health(request):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    return JsonResponse({"status": "ok"})


@sensitive_post_parameters("password")
def sign_in(request):
    if request.user.is_authenticated:
        return redirect("home")
    if request.method == "POST":
        key = hashlib.sha256((getattr(request, "client_ip", request.META.get("REMOTE_ADDR", "")) + "|local-login").encode()).hexdigest()
        with transaction.atomic():
            attempt, _ = LoginAttempt.objects.get_or_create(key=key, defaults={"started_at": timezone.now()})
            attempt = LoginAttempt.objects.select_for_update().get(pk=key)
            if attempt.started_at < timezone.now() - datetime.timedelta(minutes=15):
                attempt.count, attempt.started_at = 0, timezone.now()
            if attempt.count >= 10:
                return render(request, "login.html", {"error": "Слишком много попыток. Повторите позже."}, status=429)
            attempt.count += 1
            attempt.save()
        user = authenticate(request, username=request.POST.get("username", ""), password=request.POST.get("password", ""))
        if user and user.is_active:
            login(request, user)
            LoginAttempt.objects.filter(key=key).delete()
            personal_vault(user)
            audit(request, "auth.local_admin_login" if user.is_local_admin else "auth.local_login")
            return redirect("home")
        audit(request, "auth.login_denied")
        return render(request, "login.html", {"error": "Не удалось войти. Проверьте логин и пароль."}, status=400)
    return render(request, "login.html")


@login_required
@require_POST
def sign_out(request):
    audit(request, "auth.logout")
    logout(request)
    return redirect("login")


def oauth_client():
    config = microsoft_settings(include_secret=True)
    if not config.ready:
        raise PermissionDenied("Вход Microsoft ещё не настроен администратором.")
    oauth = OAuth()
    return oauth.register("entra", client_id=config.client_id, client_secret=config.client_secret,
        server_metadata_url=f"https://login.microsoftonline.com/{config.tenant_id}/v2.0/.well-known/openid-configuration",
        client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"})


def sso_start(request):
    return oauth_client().authorize_redirect(request, settings.PUBLIC_URL + reverse("sso_callback"))


def sso_callback(request):
    try:
        token = oauth_client().authorize_access_token(request)
        identity = token["userinfo"]
        if identity.get("tid") != microsoft_settings().tenant_id or not identity.get("oid"):
            raise ValueError("Wrong tenant or identity")
        with transaction.atomic():
            user = User.objects.filter(entra_tenant=identity["tid"], entra_oid=identity["oid"]).first()
            if user is None:
                username = "entra_" + hashlib.sha256((identity["tid"] + ":" + identity["oid"]).encode()).hexdigest()[:40]
                user = User(username=username, entra_tenant=identity["tid"], entra_oid=identity["oid"])
                user.set_unusable_password()
            if not user.is_active:
                raise ValueError("User disabled")
            user.email = identity.get("email", "")
            user.display_name = identity.get("name", "Сотрудник")
            if user._state.adding:
                user.save()
            else:
                user.save(update_fields=["email", "display_name"])
            personal_vault(user)
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        audit(request, "auth.microsoft_login")
        return redirect("home")
    except Exception:
        audit(request, "auth.microsoft_denied")
        return render(request, "login.html", {"error": "Не удалось войти через Microsoft. Проверьте назначение приложения и обратитесь к администратору."}, status=400)


def item_for(request, item_id, right="read"):
    item = get_object_or_404(Item.objects.select_related("vault__personal_owner", "owner"), pk=item_id, deleted=False, vault__deleted=False)
    if not permissions(request.user, item.vault)[right]:
        audit(request, "access.denied", item_id)
        raise PermissionDenied
    return item


@login_required
def home(request):
    from .views_workspace import workspace
    return workspace(request, mode="personal" if request.GET.get("section") == "personal" else "shared")


@login_required
def vault_new(request):
    if not manages_team(request.user):
        raise PermissionDenied
    from .views_team import team_url, team
    if request.method == "POST":
        request.POST = request.POST.copy()
        request.POST["action"] = "vault"
        return team(request)
    return redirect(team_url(request.GET.get("department", "all"), "vaults", new_vault=1))


@login_required
def vault_members(request, vault_id):
    vault = get_object_or_404(Vault, pk=vault_id, deleted=False)
    if vault.personal_owner_id or not permissions(request.user, vault)["manage"]:
        raise PermissionDenied
    if vault.department_id:
        if request.method == "GET":
            from .views_team import team_url
            return redirect(team_url(vault.department_id, "vaults", access=vault.pk))
        # Department grants use the team endpoint's scope checks and revision lock.
        return HttpResponse(status=405)
    if request.method == "POST":
        user = get_object_or_404(User, pk=request.POST.get("user"), is_active=True)
        role = request.POST.get("role")
        if role not in ("reader", "editor", "owner", "remove"):
            return HttpResponse(status=400)
        with transaction.atomic():
            vault = get_object_or_404(Vault.objects.select_for_update(), pk=vault.pk, deleted=False)
            if vault.department_id or not permissions(request.user, vault)["manage"]:
                raise PermissionDenied
            if role == "remove":
                Membership.objects.filter(vault=vault, user=user).delete()
            else:
                Membership.objects.update_or_create(vault=vault, user=user, defaults={"role": role, "can_totp": request.POST.get("can_totp") == "on"})
            audit(request, "vault.membership_changed", user.pk, vault, role=role)
            vault.access_revision += 1
            vault.save(update_fields=["access_revision"])
        return redirect("members", vault_id=vault.pk)
    return render(request, "members.html", {"vault": vault, "members": vault.memberships.select_related("user")})


@login_required
@sensitive_post_parameters("password", "note", "login")
def item_edit(request, item_id=None):
    item = item_for(request, item_id, "edit") if item_id else None
    initial = {"kind": "account", "vault": request.GET.get("vault")}
    if item:
        initial.update({"title": item.title, "kind": item.kind, "vault": item.vault_id, "tags": item.tags})
        initial.update(crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}"))
        initial.pop("password", None)
        audit(request, "item.edit_opened", item.pk, item.vault)
    form = ItemForm(request.POST or None, initial=initial, user=request.user)
    if request.method == "POST" and form.is_valid():
        data = form.cleaned_data
        if item and item.vault_id != data["vault"].pk:
            form.add_error("vault", "Для переноса используйте действие «Переместить» в карточке записи.")
        else:
            with transaction.atomic():
                if item:
                    item = locked_item_for(request, item.pk, "edit")
                    if str(item.version) != request.POST.get("version"):
                        return render(request, "error.html", {"heading": "Запись уже изменена", "message": "Обновите страницу, чтобы не перезаписать работу коллеги."}, status=409)
                    previous = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
                    item.version += 1
                else:
                    target = get_object_or_404(Vault.objects.select_for_update(), pk=data["vault"].pk, deleted=False)
                    if not permissions(request.user, target)["edit"]:
                        raise PermissionDenied
                    data["vault"] = target
                    item = Item(owner=request.user)
                    previous = {}
                item.title, item.kind, item.tags, item.vault = data["title"], data["kind"], data["tags"], data["vault"]
                item.save()
                payload = {name: data[name] for name in ("login", "password", "url", "note")}
                if not payload["password"] and previous:
                    payload["password"] = previous.get("password", "")
                ItemVersion.objects.create(item=item, number=item.version, payload=crypto.seal(payload, f"item:{item.pk}:{item.version}"), author=request.user)
                audit(request, "item.saved", item.pk, item.vault, version=item.version)
            return redirect("item", item_id=item.pk)
    return render(request, "form.html", {"form": form, "heading": "Изменить запись" if item else "Добавить рабочий доступ", "subtitle": "Пароль, токен и заметка сохраняются зашифрованными. Пустой пароль при изменении сохраняет прежний.", "version": item.version if item else None})


@login_required
def item_detail(request, item_id):
    item = item_for(request, item_id)
    rights = permissions(request.user, item.vault)
    with transaction.atomic():
        item = locked_item_for(request, item.pk)
        recovery_manager = recovery_manager_for(item)
        leader = recovery_access(request.user, item)
        can_manage_totp = totp_access(request.user, item)
        payload = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
        visible_values = {field: payload.get(field, "") for field in ("login", "url", "note")}
        audit(request, "item.opened", item.pk, item.vault, fields=list(visible_values), version=item.version)
    from .views_workspace import vault_url
    versions = item.versions.select_related("author").order_by("-number")
    return render(request, "item.html", {"item": item, "rights": rights, "leader": leader, "can_manage_totp": can_manage_totp, "visible_values": visible_values,
        "back_url": vault_url(request.user, item.vault), "recovery_manager": recovery_manager,
        "can_move_item": can_move_item(request.user,item), "can_copy_item": can_copy_item(request.user,item),
        "personal_manager": effective_manager(item.vault.personal_owner) if item.vault.personal_owner_id else None,
        "has_totp": TotpConfig.objects.filter(item=item).exists(), "totp_form": TotpForm(), "recovery_form": RecoveryForm(),
        "codes": item.recovery_codes.all() if leader else [], "members": item.vault.memberships.select_related("user"),
        "versions": versions})


@login_required
def item_version_detail(request, item_id, version_number):
    item = item_for(request, item_id)
    rights = permissions(request.user, item.vault)
    version_obj = get_object_or_404(ItemVersion.objects.select_related("author"), item=item, number=version_number)
    with transaction.atomic():
        locked_item = locked_item_for(request, item.pk)
        payload = crypto.unseal(version_obj.payload, f"item:{item.pk}:{version_obj.number}")
        visible_values = {field: payload.get(field, "") for field in ("login", "url", "note")}
        audit(request, "item.version_opened", item.pk, item.vault, version=version_number)
    return render(request, "item_version.html", {
        "item": item,
        "version_obj": version_obj,
        "rights": rights,
        "visible_values": visible_values,
        "is_current": (version_number == item.version),
        "back_url": reverse("item", args=[item.pk]),
    })


@login_required
@require_POST
def item_version_reveal(request, item_id, version_number):
    item = item_for(request, item_id)
    version_obj = get_object_or_404(ItemVersion, item=item, number=version_number)
    field = request.POST.get("field")
    if field not in ("login", "password", "url", "note"):
        return JsonResponse({"error": "Поле недоступно."}, status=400)
    with transaction.atomic():
        locked_item = locked_item_for(request, item.pk)
        payload = crypto.unseal(version_obj.payload, f"item:{item.pk}:{version_obj.number}")
        audit(request, "item.version_revealed", item.pk, item.vault, field=field, version=version_number)
    return JsonResponse({"value": payload.get(field, "")})


@login_required
@require_POST
def item_version_restore(request, item_id, version_number):
    with transaction.atomic():
        item = locked_item_for(request, item_id, "edit")
        version_obj = get_object_or_404(ItemVersion, item=item, number=version_number)
        payload = crypto.unseal(version_obj.payload, f"item:{item.pk}:{version_obj.number}")
        previous_version = item.version
        item.version += 1
        item.save()
        ItemVersion.objects.create(
            item=item,
            number=item.version,
            payload=crypto.seal(payload, f"item:{item.pk}:{item.version}"),
            author=request.user,
        )
        audit(request, "item.version_restored", item.pk, item.vault, restored_from=version_number, previous_version=previous_version, new_version=item.version)
        messages.success(request, f"Запись восстановлена из версии №{version_number}. Создана новая версия №{item.version}.")
    return redirect("item", item_id=item.pk)


@login_required
@require_POST
def reveal(request, item_id):
    item = item_for(request, item_id)
    field = request.POST.get("field")
    if field not in ("login", "password", "url", "note"):
        return JsonResponse({"error": "Поле недоступно."}, status=400)
    with transaction.atomic():
        item = locked_item_for(request, item.pk)
        payload = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
        audit(request, "item.revealed", item.pk, item.vault, field=field)
    return JsonResponse({"value": payload.get(field, "")})


@login_required
@require_POST
@sensitive_post_parameters("configuration")
def totp_setup(request, item_id):
    item = item_for(request, item_id)
    if not totp_access(request.user, item):
        audit(request, "access.totp_setup_denied", item.pk)
        raise PermissionDenied
    form = TotpForm(request.POST)
    if form.is_valid():
        try:
            configuration = totp_data(form.cleaned_data["configuration"])
        except ValidationError as error:
            form.add_error("configuration", error)
        else:
            with transaction.atomic():
                item = locked_item_for(request, item.pk, lock_team=True)
                if not totp_access(request.user, item):
                    raise PermissionDenied
                current = TotpConfig.objects.filter(item=item).first()
                revision = current.revision + 1 if current else 1
                TotpConfig.objects.update_or_create(item=item, defaults={"payload": crypto.seal(configuration, f"totp:{item.pk}:{revision}"), "revision": revision})
                IssuedCode.objects.filter(item=item).update(expires_at=timezone.now())
                audit(request, "totp.configured", item.pk, item.vault, revision=revision)
            messages.success(request, "Коды подтверждения подключены.")
            return redirect("item", item_id=item.pk)
    return render(request, "form.html", {"form": form, "heading": "Подключить коды подтверждения"}, status=400)


@login_required
@require_POST
def totp_issue(request, item_id):
    item = item_for(request, item_id)
    if not (permissions(request.user, item.vault)["totp"] or totp_access(request.user, item)):
        audit(request, "access.totp_denied", item.pk)
        raise PermissionDenied
    try:
        request_id = uuid.UUID(request.POST.get("request_id", ""))
    except (ValueError, TypeError):
        return JsonResponse({"error": "Повторите запрос кода."}, status=400)
    with transaction.atomic():
        # Serialize on this item, including retries and concurrent request IDs.
        item = locked_item_for(request, item.pk)
        if not (permissions(request.user, item.vault)["totp"] or totp_access(request.user, item)):
            raise PermissionDenied
        existing = IssuedCode.objects.filter(actor=request.user, item=item, request_id=request_id).first()
        context = f"issued:{item.pk}:{request.user.pk}:{request_id}"
        if existing:
            if existing.expires_at <= timezone.now():
                return JsonResponse({"error": "Этот запрос уже истёк. Нажмите «Получить код» ещё раз."}, status=409)
            result = crypto.unseal(existing.payload, context)
            return JsonResponse({**result, "server_time": int(timezone.now().timestamp())})
        if IssuedCode.objects.filter(actor=request.user, item=item, created_at__gte=timezone.now()-datetime.timedelta(minutes=1)).count() >= 10:
            audit(request, "totp.rate_limited", item.pk, item.vault)
            return JsonResponse({"error": "Слишком много запросов. Подождите минуту."}, status=429)
        configuration = get_object_or_404(TotpConfig, item=item)
        code, expiry = generate_totp(crypto.unseal(configuration.payload, f"totp:{item.pk}:{configuration.revision}"))
        result = {"code": code, "expires_at": expiry}
        IssuedCode.objects.create(actor=request.user, item=item, request_id=request_id, payload=crypto.seal(result, context), expires_at=datetime.datetime.fromtimestamp(expiry, tz=datetime.timezone.utc))
        audit(request, "totp.requested", item.pk, item.vault, request_id=str(request_id), expires_at=expiry, revision=configuration.revision)
    return JsonResponse({**result, "server_time": int(timezone.now().timestamp())})


@login_required
@require_POST
@sensitive_post_parameters("codes")
def recovery_replace(request, item_id):
    item = item_for(request, item_id)
    if not recovery_access(request.user, item):
        audit(request, "access.recovery_denied", item.pk)
        raise PermissionDenied
    form = RecoveryForm(request.POST)
    if form.is_valid():
        with transaction.atomic():
            item = locked_item_for(request, item.pk, lock_team=True)
            if not recovery_access(request.user, item):
                raise PermissionDenied
            item.recovery_codes.all().delete()
            for value in form.cleaned_data["codes"]:
                code = RecoveryCode(item=item)
                code.payload = crypto.seal(value, f"recovery:{item.pk}:{code.pk}")
                code.save()
            audit(request, "recovery.replaced", item.pk, item.vault, count=len(form.cleaned_data["codes"]))
        messages.success(request, "Резервные коды сохранены. Предыдущий набор заменён.")
        return redirect("item", item_id=item.pk)
    return render(request, "form.html", {"form": form, "heading": "Заменить резервные коды"}, status=400)


@login_required
@require_POST
def recovery_action(request, item_id, code_id):
    item = item_for(request, item_id)
    if not recovery_access(request.user, item):
        audit(request, "access.recovery_denied", item.pk)
        raise PermissionDenied
    with transaction.atomic():
        item = locked_item_for(request, item.pk, lock_team=True)
        if not recovery_access(request.user, item):
            raise PermissionDenied
        code = get_object_or_404(RecoveryCode.objects.select_for_update(), pk=code_id, item=item)
        if request.POST.get("action") == "used":
            code.used = True
            code.save(update_fields=["used"])
            audit(request, "recovery.marked_used", code.pk, item.vault, item=str(item.pk))
            return JsonResponse({"used": True})
        if code.used:
            return JsonResponse({"error": "Код уже отмечен использованным."}, status=409)
        value = crypto.unseal(code.payload, f"recovery:{item.pk}:{code.pk}")
        audit(request, "recovery.revealed", code.pk, item.vault, item=str(item.pk))
    return JsonResponse({"value": value})


@login_required
def users(request):
    if request.method == "GET":
        from .views_team import team
        return team(request)
    if request.method != "POST":
        return HttpResponse(status=405)
    with transaction.atomic():
        SystemState.objects.get_or_create(key="team_management_lock", defaults={"value": ""})
        SystemState.objects.select_for_update().get(key="team_management_lock")
        request.user = User.objects.get(pk=request.user.pk)
        if not request.user.is_superuser or not request.user.is_active:
            raise PermissionDenied
        user = get_object_or_404(User.objects.select_for_update(), pk=request.POST.get("user"))
        if user.is_local_admin:
            messages.error(request, "Резервный администратор управляется через .env.")
        else:
            manager = User.objects.filter(pk=request.POST.get("manager") or None, is_active=True).first()
            if manager and manager.pk == user.pk:
                return HttpResponse("Нельзя назначить сотрудника собственным руководителем.", status=400)
            user.manager = manager
            user.is_manager = request.POST.get("is_manager") == "on"
            if (user.is_superuser, user.is_active) != (request.POST.get("is_superuser") == "on", request.POST.get("is_active") == "on"):
                user.auth_revision += 1
            user.is_superuser = request.POST.get("is_superuser") == "on"
            user.is_active = request.POST.get("is_active") == "on"
            user.team_revision += 1
            user.save()
            audit(request, "user.permissions_changed", user.pk, manager=user.manager_id, admin=user.is_superuser, active=user.is_active, leader=user.is_manager)
            messages.success(request, "Полномочия сотрудника обновлены.")
    return redirect("users")


@login_required
def activity(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    events = AuditEvent.objects.select_related("actor", "vault").order_by("-created_at")
    action = request.GET.get("action", "")[:80]
    if action:
        events = events.filter(action=action)
    return render(request, "audit.html", {"events": events[:200], "action": action})


@login_required
@sensitive_post_parameters("client_secret")
def microsoft_config(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    current = microsoft_settings()
    initial = {"enabled": current.enabled, "tenant_id": current.tenant_id, "client_id": current.client_id, "revision": current.revision}
    form = MicrosoftForm(request.POST if request.method == "POST" else None, initial=initial, current=current)
    if request.method == "POST" and form.is_valid():
        values = form.cleaned_data
        with transaction.atomic():
            # Serialize the first save too, before the singleton configuration exists.
            SystemState.objects.get_or_create(key="microsoft_settings_lock", defaults={"value": ""})
            SystemState.objects.select_for_update().get(key="microsoft_settings_lock")
            config = MicrosoftConfig.objects.select_for_update().filter(pk=1).first()
            revision = config.revision if config else 0
            if values["revision"] != revision:
                form.add_error(None, "Настройки уже изменены другим администратором. Обновите страницу и повторите.")
            else:
                previous = microsoft_settings(include_secret=True)
                config = config or MicrosoftConfig(id=1)
                config.enabled = values["enabled"]
                config.tenant_id = str(values.get("tenant_id") or "")
                config.client_id = str(values.get("client_id") or "")
                secret = "" if values["clear_secret"] else (values["client_secret"] or previous.client_secret)
                config.secret_payload = crypto.seal(secret, "integration:microsoft:secret") if secret else None
                config.updated_by = request.user
                config.revision = revision + 1
                config.save()
                audit(request, "microsoft.settings_saved", "microsoft", enabled=config.enabled,
                    secret_changed=bool(values["client_secret"] or values["clear_secret"]), revision=config.revision)
                messages.success(request, "Настройки Microsoft 365 сохранены. Перезапуск приложения не требуется.")
                return redirect("microsoft_config")
    return render(request, "microsoft.html", {"form": form, "microsoft": current,
        "callback_url": settings.PUBLIC_URL + reverse("sso_callback"), "section": "microsoft"})


@login_required
@require_POST
def microsoft_check(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    config = microsoft_settings()
    if not config.tenant_id:
        return JsonResponse({"error": "Сначала сохраните Tenant ID в настройках."}, status=400)
    try:
        # Fixed authority and a UUID tenant prevent arbitrary URL requests from this tool.
        tenant = str(uuid.UUID(config.tenant_id))
        response = requests.get(f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
            timeout=10, allow_redirects=False)
        response.raise_for_status()
        metadata = response.json()
        valid = metadata.get("issuer") == f"https://login.microsoftonline.com/{tenant}/v2.0"
        if not valid:
            raise ValueError("Unexpected issuer")
    except (requests.RequestException, ValueError, KeyError):
        audit(request, "microsoft.connection_checked", "microsoft", success=False)
        return JsonResponse({"error": "Не удалось проверить каталог Microsoft. Проверьте Tenant ID и доступ сервера в интернет."}, status=400)
    audit(request, "microsoft.connection_checked", "microsoft", success=True)
    return JsonResponse({"message": "Каталог Microsoft доступен. Проверка секрета, Redirect URI и допуска пользователя выполняется при реальном входе."})
