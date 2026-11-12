from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .access import working_vaults, visible_vaults, permissions, editable_vaults
from .models import User, Department, Vault, Item
from .transfers import transfer_targets


@login_required
def choices(request):
    actor = request.user
    kind, purpose = request.GET.get("kind"), request.GET.get("purpose")
    query = request.GET.get("q", "").strip()[:150]
    try:
        page = max(1, min(10000, int(request.GET.get("page", "1"))))
        if kind == "people":
            people = User.objects.select_related("department")
            if purpose == "membership":
                vault = get_object_or_404(Vault, pk=request.GET.get("vault"), deleted=False, personal_owner__isnull=True)
                if not permissions(actor, vault)["manage"]:
                    raise PermissionDenied
                people = people.filter(is_active=True)
                if not actor.is_superuser and vault.department_id:
                    people = people.filter(department=vault.department)
                if vault.access_mode == "department":
                    people = people.exclude(department=vault.department)
            else:
                if not actor.is_superuser:
                    raise PermissionDenied
                if purpose == "head":
                    people = people.filter(is_active=True)
                elif purpose == "unassigned":
                    people = people.filter(department__isnull=True, is_local_admin=False)
                elif purpose == "recovery":
                    people = people.filter(is_active=True).filter(Q(is_manager=True) | Q(is_superuser=True) | Q(headed_departments__isnull=False)).distinct()
                else:
                    return JsonResponse({"error": "Неизвестный список."}, status=400)
            people = people.filter(Q(display_name__icontains=query) | Q(username__icontains=query) | Q(email__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query) | Q(department__name__icontains=query))
            queryset = people.order_by("display_name", "username", "pk")
        elif kind == "departments":
            queryset = Department.objects.all() if actor.is_superuser else Department.objects.filter(head=actor)
            queryset = queryset.filter(name__icontains=query).order_by("name", "pk")
        elif kind == "vaults":
            if purpose == "transfer":
                item = get_object_or_404(Item.objects.select_related("vault__department"), pk=request.GET.get("item"), deleted=False, vault__deleted=False)
                queryset = transfer_targets(actor, item, request.GET.get("operation"))
            elif purpose == "all_shared":
                if not actor.is_superuser:
                    raise PermissionDenied
                queryset = visible_vaults(actor).filter(personal_owner__isnull=True)
            elif purpose in ("workspace_shared", "editable"):
                queryset = working_vaults(actor)
                if purpose == "workspace_shared":
                    queryset = queryset.filter(personal_owner__isnull=True)
                elif request.GET.get("include"):
                    included = visible_vaults(actor).filter(pk=request.GET["include"])
                    queryset = visible_vaults(actor).filter(Q(pk__in=queryset) | Q(pk__in=included)).distinct()
                if purpose == "editable":
                    queryset = editable_vaults(actor, queryset)
            else:
                return JsonResponse({"error": "Неизвестный список."}, status=400)
            queryset = queryset.select_related("department", "personal_owner").filter(Q(name__icontains=query) | Q(department__name__icontains=query)).order_by("name", "pk")
        else:
            return JsonResponse({"error": "Неизвестный список."}, status=400)
        rows = list(queryset[(page-1)*20:page*20+1])
        results = []
        for item in rows[:20]:
            detail = ""
            if isinstance(item, User):
                detail = " · ".join(part for part in (item.email, str(item.department) if item.department_id else "Без подразделения") if part)
            elif isinstance(item, Vault):
                detail = str(item.personal_owner) if item.personal_owner_id else str(item.department) if item.department_id else "Без подразделения"
            results.append({"id": str(item.pk), "label": str(item), "detail": detail})
        return JsonResponse({"results": results, "more": len(rows) > 20})
    except (ValidationError, ValueError, TypeError):
        return JsonResponse({"error": "Некорректный запрос."}, status=400)
