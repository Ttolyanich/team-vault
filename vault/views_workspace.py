from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse
from .access import working_vaults, visible_vaults, effective_manager, permissions, editable_vaults, manages_team
from .models import User, Item, Vault
from .services import audit


def vault_url(user, vault):
    if vault.personal_owner_id:
        if vault.personal_owner_id == user.pk:
            return reverse("home") + "?section=personal"
        return reverse("staff_secrets", args=[vault.personal_owner_id])
    if working_vaults(user).filter(pk=vault.pk).exists():
        return reverse("home") + f"?vault={vault.pk}"
    if user.is_superuser:
        return reverse("all_vaults") + f"?vault={vault.pk}"
    return reverse("vault_open", args=[vault.pk])


def workspace(request, *, mode="shared", target=None, vault=None):
    actor = request.user
    selected = vault
    if mode == "personal":
        vaults = Vault.objects.filter(deleted=False, personal_owner=actor)
    elif mode == "staff":
        vaults = Vault.objects.filter(deleted=False, personal_owner=target)
    elif mode == "all_shared":
        if not actor.is_superuser:
            raise PermissionDenied
        vaults = visible_vaults(actor).filter(personal_owner__isnull=True)
    elif mode == "single":
        vaults = visible_vaults(actor).filter(pk=vault.pk)
    else:
        vaults = working_vaults(actor).filter(personal_owner__isnull=True)
    vaults = vaults.order_by("name")
    if request.GET.get("vault") and selected is None:
        try:
            selected = vaults.filter(pk=request.GET["vault"]).first()
            if selected is None:
                if mode == "shared":
                    other = get_object_or_404(visible_vaults(actor), pk=request.GET["vault"])
                    return redirect(vault_url(actor, other))
                get_object_or_404(vaults, pk=request.GET["vault"])
        except (ValidationError, ValueError):
            from django.http import HttpResponse
            return HttpResponse(status=400)
    if mode in ("personal", "staff"):
        selected = vaults.first()
    elif mode == "shared" and selected is None and vaults.count() == 1 and "vault" not in request.GET:
        selected = vaults.first()
    items = Item.objects.filter(vault__in=vaults, deleted=False).select_related("vault", "owner").order_by("-updated_at", "pk")
    if selected:
        items = items.filter(vault=selected)
    query = request.GET.get("q", "").strip()[:200]
    if query:
        items = items.filter(Q(title__icontains=query) | Q(tags__icontains=query))
    page = Paginator(items, 30).get_page(request.GET.get("page"))
    title = {"personal": "Мои рабочие секреты", "staff": f"Рабочие секреты: {target}" if target else "Рабочие секреты сотрудника",
        "all_shared": "Все общие хранилища", "single": selected.name if selected else "Хранилище", "shared": "Общие хранилища"}[mode]
    source_purpose = "all_shared" if mode == "all_shared" else "workspace_shared"
    create_target = selected.pk if selected else ""
    can_add = mode != "staff" and (permissions(actor,selected)["edit"] if selected else editable_vaults(actor,vaults).exists())
    can_create_vault = mode not in ("staff","personal") and manages_team(actor)
    return render(request, "home.html", {"vaults": vaults, "items": page.object_list, "page_obj": page, "selected": selected,
        "section": "personal" if mode == "personal" else "shared", "mode": mode, "heading": title,
        "query": query, "total": page.paginator.count, "target_person": target,
        "source_purpose": source_purpose, "create_target": create_target, "can_add": can_add, "can_create_vault": can_create_vault,
        "selected_can_manage": bool(selected and permissions(actor, selected)["manage"])})


@login_required
def all_vaults(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    return workspace(request, mode="all_shared")


@login_required
def vault_open(request, vault_id):
    vault = get_object_or_404(visible_vaults(request.user), pk=vault_id)
    if request.user.is_superuser or working_vaults(request.user).filter(pk=vault_id).exists() or vault.personal_owner_id:
        return redirect(vault_url(request.user, vault))
    return workspace(request, mode="single", vault=vault)


@login_required
def staff_secrets(request, user_id):
    person = get_object_or_404(User.objects.select_related("department__head", "manager"), pk=user_id)
    if person.pk == request.user.pk:
        return redirect(reverse("home") + "?section=personal")
    manager = effective_manager(person)
    if not (request.user.is_superuser or (manager and manager.pk == request.user.pk)):
        raise PermissionDenied
    audit(request, "workspace.reviewed", person.pk)
    return workspace(request, mode="staff", target=person)


@login_required
def staff_directory(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    query = request.GET.get("q", "").strip()[:150]
    people = User.objects.exclude(pk=request.user.pk).select_related("department").annotate(
        secret_count=Count("personal_vault__items", filter=Q(personal_vault__items__deleted=False, personal_vault__deleted=False)))
    if query:
        people = people.filter(Q(display_name__icontains=query) | Q(email__icontains=query) | Q(username__icontains=query) | Q(department__name__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query))
    page = Paginator(people.order_by("display_name", "username", "pk"), 25).get_page(request.GET.get("page"))
    return render(request, "staff_directory.html", {"page_obj": page, "query": query})


@login_required
def settings_page(request):
    if not request.user.is_superuser:
        raise PermissionDenied
    return render(request, "settings.html")
