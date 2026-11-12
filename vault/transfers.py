from django.core.exceptions import PermissionDenied
from .access import editable_vaults


def can_move_item(user, item):
    vault = item.vault
    return bool(user.is_active and not item.deleted and not vault.deleted and not vault.personal_owner_id
        and vault.department_id and (user.is_superuser or vault.department.head_id == user.pk))


def can_copy_item(user, item):
    return bool(user.is_active and not item.deleted and not item.vault.deleted and item.vault.personal_owner_id == user.pk)


def transfer_targets(user, item, operation):
    if operation == "move":
        if not can_move_item(user, item):
            raise PermissionDenied
        return editable_vaults(user).filter(personal_owner__isnull=True, department_id=item.vault.department_id).exclude(pk=item.vault_id)
    if operation == "copy":
        if not can_copy_item(user, item):
            raise PermissionDenied
        return editable_vaults(user).filter(personal_owner__isnull=True)
    raise PermissionDenied
