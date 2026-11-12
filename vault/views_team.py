from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Q, Exists, OuterRef
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from .access import manages_team, permissions
from .forms_team import DepartmentForm, TeamUserForm, TeamVaultForm, CreateLocalUserForm, ResetPasswordForm
from .models import Department, User, Vault, Membership, SystemState
from .services import audit, personal_vault


def team_url(department="all", tab="staff", **extra):
    return reverse("team") + "?" + urlencode({"department": str(department), "tab": tab, **extra})


def departments_for(actor):
    return Department.objects.all() if actor.is_superuser else Department.objects.filter(head=actor)


def people_for(actor):
    return User.objects.all() if actor.is_superuser else User.objects.filter(department__head=actor)


def vaults_for(actor):
    queryset = Vault.objects.filter(personal_owner__isnull=True, deleted=False)
    return queryset if actor.is_superuser else queryset.filter(department__head=actor)


@login_required
@require_http_methods(["GET", "POST"])
def team(request):
    if not manages_team(request.user):
        raise PermissionDenied
    try:
        if request.method == "POST":
            return change_team(request)
        return team_page(request)
    except (ValidationError, ValueError):
        return HttpResponse("Некорректный идентификатор. Обновите страницу и повторите.", status=400)


def change_team(request):
    # Serialize assignments, access changes and head replacement, including the first save.
    with transaction.atomic():
        SystemState.objects.get_or_create(key="team_management_lock", defaults={"value": ""})
        SystemState.objects.select_for_update().get(key="team_management_lock")
        request.user = User.objects.get(pk=request.user.pk)
        actor = request.user
        if not actor.is_active or not manages_team(actor):
            raise PermissionDenied
        action = request.POST.get("action")
        if action == "sessions":
            if not actor.is_superuser:
                raise PermissionDenied
            person = get_object_or_404(User.objects.select_for_update(), pk=request.POST.get("object"))
            person.auth_revision += 1
            person.team_revision += 1
            person.save(update_fields=["auth_revision", "team_revision"])
            audit(request, "auth.sessions_revoked", person.pk)
            messages.success(request, "Сессии сотрудника завершены. При следующем запросе потребуется повторный вход.")
            return redirect(team_url(person.department_id or "unassigned", person=person.pk))
        if action == "department":
            if not actor.is_superuser:
                raise PermissionDenied
            department = get_object_or_404(Department, pk=request.POST["object"]) if request.POST.get("object") else Department()
            form = DepartmentForm(request.POST, instance=department)
            if not form.is_valid():
                return team_page(request, drawer="department", drawer_form=form)
            if form.cleaned_data["revision"] != Department.objects.filter(pk=department.pk).values_list("revision", flat=True).first() and not department._state.adding:
                form.add_error(None, "Подразделение уже изменено. Обновите страницу.")
                return team_page(request, drawer="department", drawer_form=form, status=409)
            old_head = Department.objects.filter(pk=department.pk).values_list("head_id", flat=True).first()
            department = form.save(commit=False)
            department.revision += 1
            department.save()
            audit(request, "department.saved", department.pk, head=department.head_id, previous_head=old_head)
            messages.success(request, "Подразделение сохранено.")
            return redirect(team_url(department.pk))
        if action == "person":
            if not actor.is_superuser:
                raise PermissionDenied
            person = get_object_or_404(User.objects.select_for_update(), pk=request.POST.get("object"))
            if person.is_local_admin:
                raise PermissionDenied
            form = TeamUserForm(request.POST)
            if not form.is_valid():
                return team_page(request, drawer="person", drawer_form=form, person=person)
            values = form.cleaned_data
            if values["revision"] != person.team_revision:
                form.add_error(None, "Сотрудник уже изменён. Обновите страницу.")
                return team_page(request, drawer="person", drawer_form=form, person=person, status=409)
            old_department = person.department_id
            department = values["department"]
            if old_department != (department.pk if department else None):
                # Transfer removes explicit grants in the previous department as well as inherited access.
                if old_department:
                    Membership.objects.filter(user=person, vault__department_id=old_department).delete()
                person.manager = None
            person.department = department
            if (person.is_superuser, person.is_active) != (values["is_superuser"], values["is_active"]):
                person.auth_revision += 1
            person.is_superuser, person.is_active = values["is_superuser"], values["is_active"]
            person.team_revision += 1
            person.save()
            audit(request, "user.permissions_changed", person.pk, admin=person.is_superuser, active=person.is_active,
                department=str(person.department_id or ""), previous_department=str(old_department or ""))
            messages.success(request, "Сотрудник и его полномочия обновлены.")
            return redirect(team_url(person.department_id or "unassigned", person=person.pk))
        if action == "new_person":
            if not actor.is_superuser:
                raise PermissionDenied
            form = CreateLocalUserForm(request.POST)
            if not form.is_valid():
                return team_page(request, drawer="new_person", drawer_form=form)
            data = form.cleaned_data
            user = User.objects.create_user(
                username=data["username"],
                email=data.get("email") or "",
                password=data["password"],
                display_name=data["display_name"],
                department=data.get("department"),
                is_superuser=data.get("is_superuser", False),
                is_staff=data.get("is_superuser", False),
                is_active=True,
            )
            personal_vault(user)
            audit(request, "user.created", user.pk, admin=user.is_superuser, department=str(user.department_id or ""))
            messages.success(request, f"Локальный пользователь «{user}» успешно создан.")
            return redirect(team_url(user.department_id or "unassigned", person=user.pk))
        if action == "reset_password":
            if not actor.is_superuser:
                raise PermissionDenied
            person = get_object_or_404(User.objects.select_for_update(), pk=request.POST.get("object"))
            if person.is_local_admin or person.ad_object_guid or person.entra_oid:
                raise PermissionDenied
            form = ResetPasswordForm(request.POST)
            if not form.is_valid():
                messages.error(request, "Ошибка при смене пароля: " + "; ".join(f"{','.join(errs)}" for errs in form.errors.values()))
                return redirect(team_url(person.department_id or "unassigned", person=person.pk))
            person.set_password(form.cleaned_data["new_password"])
            person.auth_revision += 1
            person.team_revision += 1
            person.save(update_fields=["password", "auth_revision", "team_revision"])
            audit(request, "user.password_reset", person.pk)
            messages.success(request, f"Пароль пользователя «{person}» успешно обновлен. Активные сессии завершены.")
            return redirect(team_url(person.department_id or "unassigned", person=person.pk))
        if action == "assign_person":
            if not actor.is_superuser:
                raise PermissionDenied
            department = get_object_or_404(Department, pk=request.POST.get("department"))
            person = get_object_or_404(User.objects.select_for_update(), pk=request.POST.get("object"), department__isnull=True, is_local_admin=False)
            person.department, person.manager = department, None
            person.team_revision += 1
            person.save()
            audit(request, "user.permissions_changed", person.pk, department=str(department.pk), previous_department="", admin=person.is_superuser, active=person.is_active)
            messages.success(request, "Сотрудник добавлен в подразделение.")
            return redirect(team_url(department.pk))
        if action == "vault":
            vault = get_object_or_404(vaults_for(actor).select_for_update(), pk=request.POST["object"]) if request.POST.get("object") else Vault()
            old_department, old_mode = vault.department_id, vault.access_mode
            form = TeamVaultForm(request.POST, actor=actor, instance=vault)
            if not form.is_valid():
                return team_page(request, drawer="vault", drawer_form=form)
            if not vault._state.adding and form.cleaned_data["revision"] != Vault.objects.get(pk=vault.pk).access_revision:
                form.add_error(None, "Хранилище уже изменено. Обновите страницу.")
                return team_page(request, drawer="vault", drawer_form=form, status=409)
            created = vault._state.adding
            vault = form.save(commit=False)
            if old_department != vault.department_id or old_mode != vault.access_mode:
                vault.memberships.all().delete()
            vault.access_revision += 1
            vault.save()
            audit(request, "vault.created" if created else "vault.policy_changed", vault.pk, vault,
                department=str(vault.department_id or ""), access_mode=vault.access_mode)
            messages.success(request, "Хранилище сохранено.")
            return redirect(team_url(vault.department_id or "unassigned", "vaults", access=vault.pk))
        if action == "permission":
            vault = get_object_or_404(vaults_for(actor).select_for_update(), pk=request.POST.get("vault"))
            person = get_object_or_404(User, pk=request.POST.get("person"))
            if not actor.is_superuser and person.department_id != vault.department_id:
                raise PermissionDenied
            if vault.access_mode == "department" and person.department_id == vault.department_id:
                return HttpResponse("Права сотрудников задаются общим режимом хранилища.", status=400)
            if str(vault.access_revision) != request.POST.get("revision"):
                messages.error(request, "Доступ уже изменён. Проверьте актуальные права и повторите.")
                return redirect(team_url(vault.department_id or "unassigned", "vaults", access=vault.pk))
            role = request.POST.get("role")
            if role not in ("none", "reader", "editor"):
                return HttpResponse(status=400)
            if role == "none":
                Membership.objects.filter(vault=vault, user=person).delete()
            else:
                Membership.objects.update_or_create(vault=vault, user=person,
                    defaults={"role": role, "can_totp": request.POST.get("can_totp") == "on"})
            vault.access_revision += 1
            vault.save(update_fields=["access_revision"])
            audit(request, "vault.membership_changed", person.pk, vault, role=role, can_totp=request.POST.get("can_totp") == "on")
            messages.success(request, "Доступ сотрудника обновлён.")
            if request.POST.get("return_person"):
                return redirect(team_url(person.department_id or "unassigned", person=person.pk))
            return redirect(team_url(vault.department_id or "unassigned", "vaults", access=vault.pk))
        return HttpResponse(status=400)


def access_rows(actor, *, person=None, vault=None):
    rows = []
    if person:
        vaults = vaults_for(actor).filter(Q(department_id=person.department_id, department__isnull=False) | Q(memberships__user=person)).distinct().select_related("department__head")
        pairs = ((person, item) for item in vaults.order_by("name"))
    else:
        users = User.objects.filter(membership__vault=vault).distinct().order_by("display_name", "username")
        if vault.access_mode == "department":
            users = users.exclude(department_id=vault.department_id)
        pairs = ((user, vault) for user in users)
    for user, item in pairs:
        membership = Membership.objects.filter(vault=item, user=user).first()
        inherited = item.access_mode == "department" and item.department_id == user.department_id
        automatic = user.is_superuser or bool(item.department_id and item.department.head_id == user.pk)
        rows.append({"person": user, "vault": item, "role": (item.department_role if inherited else ("editor" if membership and membership.role == "owner" else membership.role if membership else "none")),
            "totp": item.department_totp if inherited else bool(membership and membership.can_totp),
            "automatic": automatic, "inherited": inherited, "editable": actor.is_superuser or user.department_id == item.department_id})
    return rows


def team_page(request, *, drawer=None, drawer_form=None, person=None, status=200):
    actor = request.user
    departments = departments_for(actor).select_related("head").annotate(employee_count=Count("employees", distinct=True)).order_by("name")
    selection = request.GET.get("department", "all")
    selected = None
    if selection not in ("all", "unassigned"):
        selected = get_object_or_404(departments, pk=selection)
    if selection == "unassigned" and not actor.is_superuser:
        raise PermissionDenied
    tab = "vaults" if request.GET.get("tab") == "vaults" else "staff"
    people = people_for(actor).select_related("department__head").annotate(department_head=Exists(Department.objects.filter(head_id=OuterRef("pk"))))
    vaults = vaults_for(actor).select_related("department__head")
    if selected:
        people, vaults = people.filter(department=selected), vaults.filter(department=selected)
    elif selection == "unassigned":
        people, vaults = people.filter(department__isnull=True), vaults.filter(department__isnull=True)
    query = request.GET.get("q", "").strip()[:150]
    people_count, vault_count = people.count(), vaults.count()
    if query:
        people = people.filter(Q(display_name__icontains=query) | Q(username__icontains=query) | Q(email__icontains=query) | Q(first_name__icontains=query) | Q(last_name__icontains=query))
        vaults = vaults.filter(name__icontains=query)
    page = Paginator(vaults.order_by("name") if tab == "vaults" else people.order_by("display_name", "username"), 25).get_page(request.GET.get("page"))
    access_vault = None
    if not drawer:
        if request.GET.get("person"):
            person = get_object_or_404(people_for(actor).select_related("department__head"), pk=request.GET["person"])
            drawer = "person"
        elif request.GET.get("edit_department") or request.GET.get("new_department"):
            if not actor.is_superuser:
                raise PermissionDenied
            instance = get_object_or_404(departments, pk=request.GET["edit_department"]) if request.GET.get("edit_department") else Department()
            drawer, drawer_form = "department", DepartmentForm(instance=instance)
        elif request.GET.get("new_person"):
            if not actor.is_superuser:
                raise PermissionDenied
            drawer, drawer_form = "new_person", CreateLocalUserForm(initial={"department": selected.pk if selected else None})
        elif request.GET.get("assign"):
            if not actor.is_superuser or not selected:
                raise PermissionDenied
            drawer = "assign"
        elif request.GET.get("edit_vault") or request.GET.get("new_vault"):
            instance = get_object_or_404(vaults_for(actor), pk=request.GET["edit_vault"]) if request.GET.get("edit_vault") else Vault(department=selected)
            drawer, drawer_form = "vault", TeamVaultForm(actor=actor, instance=instance)
        elif request.GET.get("access"):
            access_vault = get_object_or_404(vaults_for(actor).select_related("department__head"), pk=request.GET["access"])
            drawer = "access"
    if person and not drawer_form and actor.is_superuser and not person.is_local_admin:
        drawer_form = TeamUserForm(initial={"department": person.department_id, "is_active": person.is_active, "is_superuser": person.is_superuser, "revision": person.team_revision})
    close_url = team_url(selection, tab, **({"q": query} if query else {}))
    access_people = User.objects.none()
    if access_vault:
        access_people = (User.objects.all() if actor.is_superuser else User.objects.filter(department=access_vault.department)).filter(is_active=True).order_by("display_name", "username")
        if access_vault.access_mode == "department":
            access_people = access_people.exclude(department_id=access_vault.department_id)
    form_instance = getattr(drawer_form, "instance", None)
    return render(request, "team.html", {"departments": departments, "selection": selection, "department": selected, "tab": tab,
        "page_obj": page, "people_count": people_count, "vault_count": vault_count, "query": query,
        "drawer": drawer, "drawer_form": drawer_form, "person": person, "access_vault": access_vault,
        "access_rows": access_rows(actor, person=person) if person else access_rows(actor, vault=access_vault) if access_vault else [],
        "access_people": access_people.exists(), "close_url": close_url, "nav_section": "team",
        "all_count": people_for(actor).count(), "unassigned_count": people_for(actor).filter(department__isnull=True).count(),
        "unassigned_people": User.objects.filter(department__isnull=True, is_local_admin=False).exists() if drawer == "assign" else False,
        "drawer_object_id": form_instance.pk if form_instance and not form_instance._state.adding else ""}, status=status)
