from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from .access import permissions
from .models import Vault, Item, SystemState, User
from .services import audit


def locked_item_for(request, item_id, right="read", *, lock_team=False):
    """Inside atomic(): optional team lock, then vault, then item; match hierarchy/trash lock order."""
    if lock_team:
        # Same lock/order as hierarchy changes: a completed reassignment revokes old access.
        SystemState.objects.get_or_create(key="team_management_lock", defaults={"value": ""})
        SystemState.objects.select_for_update().get(key="team_management_lock")
        request.user = User.objects.get(pk=request.user.pk)
        if not request.user.is_active:
            raise PermissionDenied
    reference = get_object_or_404(Item.objects.only("vault_id"), pk=item_id)
    vault = get_object_or_404(Vault.objects.select_for_update(), pk=reference.vault_id, deleted=False)
    item = get_object_or_404(Item.objects.select_for_update(), pk=item_id, deleted=False, vault=vault)
    item.vault = vault
    if not permissions(request.user, vault)[right]:
        audit(request, "access.denied", item.pk)
        raise PermissionDenied
    return item
