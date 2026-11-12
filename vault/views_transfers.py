import uuid
from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from . import crypto
from .access import permissions
from .models import User, Vault, Item, ItemVersion, IssuedCode, AuditEvent, SystemState
from .services import audit
from .transfers import transfer_targets
from .widgets import search_field


class TransferForm(forms.Form):
    target = forms.ModelChoiceField(label="В хранилище", queryset=Vault.objects.none())
    version = forms.IntegerField(widget=forms.HiddenInput, min_value=1)
    request_id = forms.UUIDField(widget=forms.HiddenInput)

    def __init__(self, *args, user, item, operation, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["target"].queryset = transfer_targets(user, item, operation).select_related("department").order_by("name", "pk")
        search_field(self.fields["target"], "vaults", "transfer", extra={"item": item.pk, "operation": operation})


@login_required
@require_http_methods(["GET", "POST"])
def transfer(request, item_id, operation):
    item = get_object_or_404(Item.objects.select_related("vault__department", "vault__personal_owner"), pk=item_id, deleted=False, vault__deleted=False)
    form = TransferForm(request.POST if request.method == "POST" else None, user=request.user, item=item, operation=operation,
        initial={"version": item.version, "request_id": uuid.uuid4()})
    status = 400 if request.method == "POST" and not form.is_valid() else 200
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            # Hierarchy/membership changes take this lock before vaults; use the same order.
            SystemState.objects.get_or_create(key="team_management_lock", defaults={"value": ""})
            SystemState.objects.select_for_update().get(key="team_management_lock")
            actor = User.objects.get(pk=request.user.pk); request.user = actor
            if not actor.is_active:
                raise PermissionDenied
            reference = get_object_or_404(Item.objects.only("vault_id"), pk=item.pk, deleted=False)
            target_id = form.cleaned_data["target"].pk
            locked = {vault.pk: vault for vault in Vault.objects.select_for_update().filter(pk__in=[reference.vault_id,target_id],deleted=False).order_by("pk")}
            source, target = locked.get(reference.vault_id), locked.get(target_id)
            if not source or not target:
                raise PermissionDenied
            item = get_object_or_404(Item.objects.select_for_update(), pk=item.pk, vault=source, deleted=False)
            item.vault = source
            if not transfer_targets(actor, item, operation).filter(pk=target.pk).exists() or not permissions(actor, target)["edit"]:
                raise PermissionDenied
            request_id = str(form.cleaned_data["request_id"])
            # Successful copies have an atomic audit receipt. A repeated form cannot create another record.
            receipt = AuditEvent.objects.filter(actor=actor, action="item.copied", details__request_id=request_id).first() if operation == "copy" else None
            if receipt:
                if receipt.details.get("source_item") != str(item.pk) or receipt.details.get("source_version") != form.cleaned_data["version"] or receipt.vault_id != target.pk:
                    form.add_error(None, "Этот запрос уже использован. Откройте форму заново."); status=409
                else:
                    copied = get_object_or_404(Item, pk=receipt.target, vault=target, deleted=False)
                    return redirect("item", item_id=copied.pk)
            elif item.version != form.cleaned_data["version"]:
                form.add_error(None, "Запись уже изменена. Обновите страницу и повторите."); status=409
            else:
                payload = crypto.unseal(item.versions.get(number=item.version).payload, f"item:{item.pk}:{item.version}")
                if operation == "move":
                    previous_version = item.version
                    item.vault = target; item.version += 1; item.save()
                    ItemVersion.objects.create(item=item,number=item.version,author=actor,payload=crypto.seal(payload,f"item:{item.pk}:{item.version}"))
                    IssuedCode.objects.filter(item=item).update(expires_at=timezone.now())
                    audit(request,"item.moved",item.pk,target,source_vault=str(source.pk),target_vault=str(target.pk),previous_version=previous_version,version=item.version)
                    messages.success(request,"Запись перемещена. Доступ определяется правами нового хранилища.")
                    return redirect("item",item_id=item.pk)
                copied = Item.objects.create(vault=target,title=item.title,kind=item.kind,tags=item.tags,owner=actor)
                fields = {name:payload.get(name,"") for name in ("login","password","url","note")}
                ItemVersion.objects.create(item=copied,number=1,author=actor,payload=crypto.seal(fields,f"item:{copied.pk}:1"))
                audit(request,"item.copied",copied.pk,target,source_item=str(item.pk),source_vault=str(source.pk),source_version=item.version,request_id=request_id)
                messages.success(request,"Копия добавлена в общее хранилище.")
                return redirect("item",item_id=copied.pk)
    return render(request,"transfer.html",{"item":item,"form":form,"operation":operation,"has_targets":form.fields["target"].queryset.exists()},status=status)
