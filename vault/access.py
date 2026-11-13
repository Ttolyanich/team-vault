from django.db.models import Q
from .models import Vault, Membership, User, Department, TotpConfig


def visible_vaults(user):
    if user.is_superuser:
        return Vault.objects.filter(deleted=False)
    return Vault.objects.filter(
        Q(personal_owner=user) |
        Q(personal_owner__department__head=user) |
        Q(personal_owner__department__isnull=True, personal_owner__manager=user) |
        Q(department__head=user) |
        Q(department_id=user.department_id, access_mode="department", department__isnull=False) |
        Q(memberships__user=user)
    ).filter(deleted=False).distinct()


def effective_manager(user):
    return user.department.head if user.department_id else user.manager


def working_vaults(user):
    """The user's working set; global administrative visibility is intentionally separate."""
    shared = Q(personal_owner__isnull=True) & (Q(department_id=user.department_id, department__isnull=False) | Q(memberships__user=user))
    return visible_vaults(user).filter(Q(personal_owner=user) | shared).distinct()


def editable_vaults(user, queryset=None):
    queryset = visible_vaults(user) if queryset is None else queryset
    if user.is_superuser:
        return queryset
    direct = Q(memberships__user=user, memberships__role__in=("editor", "owner"))
    if user.department_id:
        direct &= ~Q(department_id=user.department_id, access_mode="department")
    inherited = Q(department_id=user.department_id, department__isnull=False, access_mode="department", department_role="editor")
    return queryset.filter(Q(personal_owner=user) | Q(department__head=user) | inherited | direct).distinct()


def manages_team(user):
    return user.is_superuser or user.headed_departments.exists()


def permissions(user, vault):
    if vault.deleted:
        return {key: False for key in ("read", "edit", "manage", "totp")}
    own = vault.personal_owner_id == user.id
    manager = effective_manager(vault.personal_owner) if vault.personal_owner_id else None
    managed = bool(manager and manager.pk == user.id)
    head = bool(vault.department_id and vault.department.head_id == user.id)
    inherited = bool(vault.department_id and vault.department_id == user.department_id and vault.access_mode == "department")
    membership = Membership.objects.filter(vault=vault, user=user).first()
    if inherited:
        membership = None
    return {
        "read": user.is_superuser or own or managed or head or inherited or membership is not None,
        "edit": user.is_superuser or own or head or (inherited and vault.department_role == "editor") or (membership is not None and membership.role in ("editor", "owner")),
        "manage": user.is_superuser or head or (not vault.department_id and membership is not None and membership.role == "owner"),
        "totp": user.is_superuser or own or managed or head or (inherited and vault.department_totp) or (membership is not None and membership.can_totp),
    }


def recovery_manager_for(item):
    """Resolve the current hierarchy, never an assignment copied onto a record."""
    if item.vault.personal_owner_id:
        owner = User.objects.select_related("department__head", "manager").get(pk=item.vault.personal_owner_id)
        manager = effective_manager(owner)
    elif item.vault.department_id:
        department = Department.objects.select_related("head").get(pk=item.vault.department_id)
        manager = department.head
    else:
        manager = None
    return manager if manager and manager.is_active else None


def recovery_access(user, item):
    manager = recovery_manager_for(item)
    return bool(user.is_active and manager and manager.pk == user.pk)


def totp_admin_access(user, item):
    if not user.is_active:
        return False
    if recovery_access(user, item):
        return True
    if item.vault.personal_owner_id and item.vault.personal_owner_id == user.pk:
        return True
    if user.is_superuser:
        return True
    return False

totp_access = totp_admin_access


def can_setup_totp(user, item):
    if not user.is_active:
        return False
    if totp_admin_access(user, item):
        return True
    if TotpConfig.objects.filter(item=item).exists():
        return False
    return permissions(user, item.vault)["edit"]
