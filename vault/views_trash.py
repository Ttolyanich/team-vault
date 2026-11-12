import uuid
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.db.models.functions import Coalesce
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from . import crypto
from .access import permissions
from .models import Item, Vault, IssuedCode, SystemState
from .records import locked_item_for
from .services import audit


def require_admin(request):
    if not request.user.is_superuser:
        raise PermissionDenied


def lock_team_management():
    SystemState.objects.get_or_create(key="team_management_lock", defaults={"value": ""})
    SystemState.objects.select_for_update().get(key="team_management_lock")


@login_required
@require_POST
def item_delete(request, item_id):
    with transaction.atomic():
        item = locked_item_for(request, item_id, "edit")
        item.deleted, item.deleted_at, item.deleted_by = True, timezone.now(), request.user
        item.save(update_fields=["deleted", "deleted_at", "deleted_by"])
        IssuedCode.objects.filter(item=item).update(expires_at=timezone.now())
        audit(request, "item.trashed", item.pk, item.vault)
    messages.success(request, "Секрет перемещён в корзину. Администратор сможет его восстановить.")
    return redirect("home")


@login_required
@require_POST
def vault_delete(request, vault_id):
    with transaction.atomic():
        lock_team_management()
        vault = get_object_or_404(Vault.objects.select_for_update(), pk=vault_id, deleted=False)
        if vault.personal_owner_id or not permissions(request.user, vault)["manage"]:
            raise PermissionDenied
        vault.deleted, vault.deleted_at, vault.deleted_by = True, timezone.now(), request.user
        vault.access_revision += 1
        vault.save(update_fields=["deleted", "deleted_at", "deleted_by", "access_revision"])
        IssuedCode.objects.filter(item__vault=vault).update(expires_at=timezone.now())
        audit(request, "vault.trashed", vault.pk, vault, items=vault.items.count())
    messages.success(request, "Хранилище с содержимым перемещено в корзину. Восстановление доступно администратору.")
    return redirect("home")


@login_required
def trash(request):
    require_admin(request)
    query = request.GET.get("q", "").strip()[:150]
    tab = "vaults" if request.GET.get("tab") == "vaults" else "items"
    stores = Vault.objects.filter(deleted=True).select_related("department", "deleted_by")
    items = Item.objects.filter(Q(deleted=True) | Q(vault__deleted=True)).select_related("vault", "deleted_by").annotate(trash_date=Coalesce("deleted_at", "vault__deleted_at"))
    vault_count, item_count = stores.count(), items.count()
    selected = None
    if request.GET.get("vault"):
        try:
            selected_id = uuid.UUID(request.GET["vault"])
        except ValueError:
            return HttpResponse(status=400)
        selected = get_object_or_404(stores, pk=selected_id)
        items = items.filter(vault=selected)
        tab = "items"
    if query:
        stores = stores.filter(name__icontains=query)
        items = items.filter(Q(title__icontains=query) | Q(vault__name__icontains=query))
    page = Paginator(stores.order_by("-deleted_at", "name") if tab == "vaults" else items.order_by("-trash_date", "title"), 25).get_page(request.GET.get("page"))
    return render(request, "trash.html", {"page_obj": page, "tab": tab, "query": query, "selected_vault": selected,
        "vault_count": vault_count, "item_count": item_count})


@login_required
def trash_item(request, item_id):
    require_admin(request)
    item = get_object_or_404(Item.objects.select_related("vault", "deleted_by"), Q(deleted=True) | Q(vault__deleted=True), pk=item_id)
    with transaction.atomic():
        payload = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
        visible = {key: payload.get(key, "") for key in ("login", "url", "note")}
        audit(request, "trash.item_viewed", item.pk, item.vault)
    return render(request, "trash_item.html", {"item": item, "visible_values": visible})


@login_required
@require_POST
def trash_reveal(request, item_id):
    require_admin(request)
    field = request.POST.get("field")
    if field not in ("login", "password", "url", "note"):
        return JsonResponse({"error": "Поле недоступно."}, status=400)
    with transaction.atomic():
        reference = get_object_or_404(Item, pk=item_id)
        vault = get_object_or_404(Vault.objects.select_for_update(), pk=reference.vault_id)
        item = get_object_or_404(Item.objects.select_for_update(), pk=item_id)
        if not (item.deleted or vault.deleted):
            return JsonResponse({"error": "Эта запись уже восстановлена. Откройте её в хранилище."}, status=409)
        payload = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
        audit(request, "trash.item_revealed", item.pk, vault, field=field)
    return JsonResponse({"value": payload.get(field, "")})


@login_required
@require_POST
def item_restore(request, item_id):
    require_admin(request)
    with transaction.atomic():
        reference = get_object_or_404(Item, pk=item_id)
        vault = get_object_or_404(Vault.objects.select_for_update(), pk=reference.vault_id)
        item = get_object_or_404(Item.objects.select_for_update(), pk=item_id)
        if vault.deleted:
            messages.error(request, "Сначала восстановите хранилище. Отдельно удалённые секреты можно будет восстановить после него.")
            return redirect("trash")
        if not item.deleted:
            return HttpResponse(status=409)
        item.deleted, item.deleted_at, item.deleted_by = False, None, None
        item.save(update_fields=["deleted", "deleted_at", "deleted_by"])
        audit(request, "item.restored", item.pk, vault)
    messages.success(request, "Секрет восстановлен с действующими правами хранилища.")
    return redirect("item", item_id=item.pk)


@login_required
@require_POST
def vault_restore(request, vault_id):
    require_admin(request)
    with transaction.atomic():
        lock_team_management()
        vault = get_object_or_404(Vault.objects.select_for_update(), pk=vault_id, deleted=True)
        vault.deleted, vault.deleted_at, vault.deleted_by = False, None, None
        vault.access_revision += 1
        vault.save(update_fields=["deleted", "deleted_at", "deleted_by", "access_revision"])
        audit(request, "vault.restored", vault.pk, vault)
    messages.success(request, "Хранилище восстановлено. Ранее отдельно удалённые секреты остались в корзине.")
    return redirect("home")
