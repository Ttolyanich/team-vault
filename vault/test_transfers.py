import base64
import uuid
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from . import crypto
from .models import Department, Vault, Membership, Item, ItemVersion, TotpConfig, RecoveryCode, AuditEvent
from .services import totp_data


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"t"*32).decode())
class TransferTests(TestCase):
    def setUp(self):
        User=get_user_model()
        self.admin=User.objects.create_user(username="admin",is_superuser=True)
        self.head=User.objects.create_user(username="head")
        self.member=User.objects.create_user(username="member")
        self.other=User.objects.create_user(username="other")
        self.unit=Department.objects.create(name="Контент",head=self.head)
        self.foreign_unit=Department.objects.create(name="Финансы",head=self.other)
        self.member.department=self.unit;self.member.save()
        self.source=Vault.objects.create(name="Первое",department=self.unit)
        self.target=Vault.objects.create(name="Второе",department=self.unit)
        self.foreign=Vault.objects.create(name="Чужое",department=self.foreign_unit)
        self.private=Vault.objects.create(name="Личное",personal_owner=self.member)
        Membership.objects.create(vault=self.source,user=self.member,role="editor")
        self.payload={"login":"synthetic-login","password":"synthetic-password","url":"https://example.com","note":"synthetic-note"}
        self.item=self.record(self.source)
        self.personal=self.record(self.private)
        for item in (self.item,self.personal):
            TotpConfig.objects.create(item=item,payload=crypto.seal(totp_data("JBSWY3DPEHPK3PXP"),f"totp:{item.pk}:1"))
            code=RecoveryCode(item=item);code.payload=crypto.seal("synthetic-recovery",f"recovery:{item.pk}:{code.pk}");code.save()

    def record(self,vault):
        item=Item.objects.create(vault=vault,owner=self.member,title="Тестовая запись",tags="tag")
        ItemVersion.objects.create(item=item,number=1,author=self.member,payload=crypto.seal(self.payload,f"item:{item.pk}:1"))
        return item

    def submit(self,operation,item=None,target=None,**extra):
        item=item or self.item
        return self.client.post(reverse("item_"+operation,args=[item.pk]),dict(target=(target or self.target).pk,version=item.version,request_id=str(uuid.uuid4()),**extra))

    def test_head_move_preserves_data_history_and_mfa_and_changes_visibility(self):
        self.client.force_login(self.head)
        old_totp=self.item.totp_config.payload;old_code=self.item.recovery_codes.get().payload
        self.assertEqual(self.submit("move").status_code,302)
        self.item.refresh_from_db();self.assertEqual(self.item.vault,self.target);self.assertEqual(self.item.version,2)
        self.assertEqual(self.item.versions.count(),2)
        for version in self.item.versions.all():
            self.assertEqual(crypto.unseal(version.payload,f"item:{self.item.pk}:{version.number}"),self.payload)
        self.assertEqual(self.item.totp_config.payload,old_totp)
        self.assertEqual(self.item.recovery_codes.get().payload,old_code)
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("item",args=[self.item.pk])).status_code,403)
        self.assertTrue(AuditEvent.objects.filter(action="item.moved",target=str(self.item.pk),vault=self.target).exists())

    def test_admin_may_move_across_departments_while_head_restricted_to_own_department(self):
        self.client.force_login(self.head)
        self.assertEqual(self.submit("move", target=self.foreign).status_code, 400)
        self.client.force_login(self.admin)
        self.assertEqual(self.submit("move", target=self.foreign).status_code, 302)
        self.item.refresh_from_db()
        self.assertEqual(self.item.vault, self.foreign)
        self.assertEqual(self.item.version, 2)

    def test_editor_and_other_department_head_cannot_move(self):
        for person in (self.member,self.other):
            self.client.force_login(person)
            self.assertEqual(self.client.get(reverse("item_move",args=[self.item.pk])).status_code,403)
            self.assertEqual(self.submit("move").status_code,403)
        self.client.force_login(self.head)
        self.assertEqual(self.submit("move",target=self.source).status_code,400)
        self.assertEqual(self.submit("move",target=self.private).status_code,400)

    def test_copy_own_record_reencrypts_fields_without_history_or_mfa(self):
        Membership.objects.create(vault=self.target,user=self.member,role="editor")
        self.client.force_login(self.member)
        request_id=str(uuid.uuid4())
        data=dict(target=self.target.pk,version=1,request_id=request_id,password="forged",include_totp="on")
        url=reverse("item_copy",args=[self.personal.pk])
        self.assertEqual(self.client.post(url,data).status_code,302)
        copied=Item.objects.get(vault=self.target)
        self.assertNotEqual(copied.pk,self.personal.pk)
        self.assertEqual(copied.tags,self.personal.tags)
        self.assertEqual(crypto.unseal(copied.versions.get().payload,f"item:{copied.pk}:1"),self.payload)
        self.assertNotEqual(copied.versions.get().payload,self.personal.versions.get().payload)
        self.assertFalse(TotpConfig.objects.filter(item=copied).exists())
        self.assertFalse(copied.recovery_codes.exists())
        self.personal.refresh_from_db();self.assertEqual(self.personal.vault,self.private)
        self.assertEqual(self.personal.versions.count(),1)
        self.assertEqual(self.personal.recovery_codes.count(),1)
        self.assertEqual(self.client.post(url,data).status_code,302)
        self.assertEqual(Item.objects.filter(vault=self.target).count(),1)
        event=AuditEvent.objects.get(action="item.copied")
        self.assertNotIn(self.payload["password"],str(event.details))

    def test_copy_requires_own_personal_workspace_and_shared_write_permission(self):
        self.client.force_login(self.member)
        self.assertEqual(self.submit("copy",item=self.personal).status_code,400)
        Membership.objects.create(vault=self.target,user=self.member,role="reader")
        self.assertEqual(self.submit("copy",item=self.personal).status_code,400)
        self.assertEqual(self.submit("copy",item=self.personal,target=self.private).status_code,400)
        self.assertEqual(self.submit("copy").status_code,403)
        for person in (self.admin,self.head,self.other):
            self.client.force_login(person)
            self.assertEqual(self.submit("copy",item=self.personal).status_code,403)

    def test_choices_are_scoped_and_deleted_targets_are_rejected(self):
        self.client.force_login(self.head)
        result=self.client.get(reverse("choices"),dict(kind="vaults",purpose="transfer",operation="move",item=self.item.pk)).json()
        self.assertEqual([row["id"] for row in result["results"]],[str(self.target.pk)])
        self.target.deleted=True;self.target.save()
        self.assertEqual(self.submit("move").status_code,400)
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("choices"),dict(kind="vaults",purpose="transfer",operation="move",item=self.item.pk)).status_code,403)

    def test_stale_move_rejected_and_audit_failure_rolls_back_copy(self):
        self.client.force_login(self.head)
        Item.objects.filter(pk=self.item.pk).update(version=2)
        self.assertEqual(self.submit("move").status_code,409)
        self.client.force_login(self.member)
        Membership.objects.create(vault=self.target,user=self.member,role="editor")
        with patch("vault.views_transfers.audit",side_effect=RuntimeError("audit unavailable")):
            with self.assertRaises(RuntimeError):self.submit("copy",item=self.personal)
        self.assertFalse(Item.objects.filter(vault=self.target).exists())

    def test_revoked_target_grant_is_rechecked_inside_transaction(self):
        from .transfers import transfer_targets
        Membership.objects.create(vault=self.target,user=self.member,role="editor")
        self.client.force_login(self.member)
        calls=0
        def revoke_then_check(*args,**kwargs):
            nonlocal calls
            calls+=1
            if calls==2:Membership.objects.filter(vault=self.target,user=self.member).delete()
            return transfer_targets(*args,**kwargs)
        with patch("vault.views_transfers.transfer_targets",side_effect=revoke_then_check):
            self.assertEqual(self.submit("copy",item=self.personal).status_code,403)
        self.assertFalse(Item.objects.filter(vault=self.target).exists())

    def test_empty_vault_offers_records_and_create_vault_is_management_only(self):
        for person,can_create in ((self.admin,True),(self.head,True),(self.member,False)):
            self.client.force_login(person)
            page=self.client.get(reverse("home"),{"vault":self.source.pk},follow=True)
            # Empty the fixture first so the empty state is exercised below too.
            self.assertContains(page,"Создать хранилище",count=1) if can_create else self.assertNotContains(page,"Создать хранилище")
        self.item.deleted=True;self.item.save()
        self.client.force_login(self.head)
        page=self.client.get(reverse("home"),{"vault":self.source.pk},follow=True)
        self.assertContains(page,"Добавьте первый рабочий доступ")
        self.assertContains(page,"Создать хранилище",count=1)
        self.assertContains(page,"Добавить доступ",count=2)
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("vault_new")).status_code,403)
        Membership.objects.filter(vault=self.source,user=self.member).update(role="reader")
        readonly=self.client.get(reverse("home"),{"vault":self.source.pk},follow=True)
        self.assertNotContains(readonly,"Добавить доступ")
        self.assertNotContains(readonly,"Создать хранилище")
