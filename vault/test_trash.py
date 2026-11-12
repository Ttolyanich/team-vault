import base64
import uuid
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from . import crypto
from .access import permissions, visible_vaults
from .models import Department, Vault, Membership, Item, ItemVersion, TotpConfig, RecoveryCode, IssuedCode, AuditEvent
from .services import totp_data


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode())
class TrashTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", is_superuser=True)
        self.head = User.objects.create_user(username="head")
        self.editor = User.objects.create_user(username="editor")
        self.reader = User.objects.create_user(username="reader")
        self.outsider = User.objects.create_user(username="outsider")
        self.department = Department.objects.create(name="Контент", head=self.head)
        self.vault = Vault.objects.create(name="Хранилище", department=self.department)
        Membership.objects.create(vault=self.vault, user=self.editor, role="editor", can_totp=True)
        Membership.objects.create(vault=self.vault, user=self.reader, role="reader")
        self.item = Item.objects.create(vault=self.vault, title="Секрет", owner=self.editor)
        self.payload = crypto.seal({"login": "visible-login", "url": "https://example.com", "note": "visible-note", "password": "synthetic-password"}, f"item:{self.item.pk}:1")
        ItemVersion.objects.create(item=self.item, number=1, payload=self.payload, author=self.editor)
        self.seed = "JBSWY3DPEHPK3PXP"
        TotpConfig.objects.create(item=self.item, payload=crypto.seal(totp_data(self.seed), f"totp:{self.item.pk}:1"))
        self.recovery = RecoveryCode(item=self.item)
        self.recovery.payload = crypto.seal("synthetic-recovery", f"recovery:{self.item.pk}:{self.recovery.pk}")
        self.recovery.save()
        self.client.force_login(self.admin)

    def post(self, route, target=None, **data):
        return self.client.post(reverse(route, args=[target or self.item.pk]), data)

    def assert_payload_retained(self):
        self.assertEqual(ItemVersion.objects.get(item=self.item, number=1).payload, self.payload)
        self.assertTrue(TotpConfig.objects.filter(item=self.item).exists())
        self.assertTrue(RecoveryCode.objects.filter(pk=self.recovery.pk).exists())

    def test_editor_can_trash_secret_without_destroying_any_data(self):
        self.client.force_login(self.editor)
        self.assertEqual(self.post("item_delete").status_code, 302)
        self.item.refresh_from_db()
        self.assertTrue(self.item.deleted)
        self.assertEqual(self.item.deleted_by_id, self.editor.pk)
        self.assertIsNotNone(self.item.deleted_at)
        self.assert_payload_retained()
        self.assertTrue(AuditEvent.objects.filter(action="item.trashed", actor=self.editor).exists())

    def test_reader_and_outsider_cannot_delete(self):
        for user in (self.reader, self.outsider):
            self.client.force_login(user)
            self.assertEqual(self.post("item_delete").status_code, 403)
            self.assertEqual(self.post("vault_delete", self.vault.pk).status_code, 403)
        self.item.refresh_from_db()
        self.assertFalse(self.item.deleted)

    def test_trashed_records_are_blocked_in_all_normal_endpoints(self):
        self.post("item_delete")
        for user in (self.admin, self.editor, self.head):
            self.client.force_login(user)
            for route in ("item", "item_edit"):
                self.assertEqual(self.client.get(reverse(route, args=[self.item.pk])).status_code, 404)
            for route, data in (("reveal", {"field": "password"}), ("totp_issue", {"request_id": str(uuid.uuid4())}), ("totp_setup", {"configuration": self.seed, "confirmed": "on"}), ("recovery_replace", {"codes": "new-code"})):
                self.assertEqual(self.post(route, **data).status_code, 404)
            self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.recovery.pk])).status_code, 404)

    def test_head_trashes_entire_vault_and_active_items_are_hidden(self):
        self.client.force_login(self.head)
        self.assertEqual(self.post("vault_delete", self.vault.pk).status_code, 302)
        self.vault.refresh_from_db()
        self.assertTrue(self.vault.deleted)
        self.assertNotIn(self.vault, visible_vaults(self.admin))
        self.assertFalse(any(permissions(self.admin, self.vault).values()))
        self.item.refresh_from_db()
        self.assertFalse(self.item.deleted, "Vault deletion must not overwrite individual deletion state")
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 404)
        self.assert_payload_retained()

    def test_vault_restore_preserves_individually_deleted_children(self):
        earlier = Item.objects.create(vault=self.vault, title="Ранее удалён", owner=self.editor, deleted=True, deleted_at=timezone.now())
        self.post("vault_delete", self.vault.pk)
        self.assertEqual(self.post("vault_restore", self.vault.pk).status_code, 302)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 200)
        earlier.refresh_from_db()
        self.assertTrue(earlier.deleted)
        self.assertEqual(self.client.get(reverse("item", args=[earlier.pk])).status_code, 404)
        self.assert_payload_retained()

    def test_trash_pages_preview_reveal_and_restore_are_admin_only(self):
        self.post("item_delete")
        for user in (self.editor, self.reader, self.head):
            self.client.force_login(user)
            self.assertEqual(self.client.get(reverse("trash")).status_code, 403)
            self.assertEqual(self.client.get(reverse("trash_item", args=[self.item.pk])).status_code, 403)
            self.assertEqual(self.post("trash_reveal", field="password").status_code, 403)
            self.assertEqual(self.post("item_restore").status_code, 403)
            self.assertEqual(self.post("vault_restore", self.vault.pk).status_code, 403)
            self.assertNotContains(self.client.get(reverse("home")), 'href="/trash/"')

    def test_preview_hides_password_seed_and_recovery_until_explicit_request(self):
        self.post("item_delete")
        response = self.client.get(reverse("trash_item", args=[self.item.pk]))
        self.assertContains(response, "visible-login")
        for secret in ("synthetic-password", self.seed, "synthetic-recovery"):
            self.assertNotContains(response, secret)
        self.assertTrue(AuditEvent.objects.filter(action="trash.item_viewed", actor=self.admin).exists())
        self.assertEqual(self.post("trash_reveal", field="password").json()["value"], "synthetic-password")
        for field in ("seed", "recovery", "payload"):
            self.assertEqual(self.post("trash_reveal", field=field).status_code, 400)
        self.assertNotIn("synthetic-password", str(list(AuditEvent.objects.values_list("details", flat=True))))

    def test_restore_rechecks_current_vault_permissions(self):
        self.post("item_delete")
        Membership.objects.filter(vault=self.vault, user=self.editor).delete()
        self.assertEqual(self.post("item_restore").status_code, 302)
        self.item.refresh_from_db()
        self.assertFalse(self.item.deleted)
        self.assertIsNone(self.item.deleted_at)
        self.assertIsNone(self.item.deleted_by_id)
        self.client.force_login(self.editor)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 403)
        self.assert_payload_retained()

    def test_item_cannot_be_restored_while_parent_is_trashed(self):
        self.post("item_delete")
        self.post("vault_delete", self.vault.pk)
        self.assertEqual(self.post("item_restore").status_code, 302)
        self.item.refresh_from_db()
        self.assertTrue(self.item.deleted)
        self.post("vault_restore", self.vault.pk)
        self.assertEqual(self.post("item_restore").status_code, 302)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 200)

    def test_personal_vault_container_cannot_be_deleted(self):
        personal = Vault.objects.create(name="Личное рабочее", personal_owner=self.editor)
        self.assertEqual(self.post("vault_delete", personal.pk).status_code, 403)
        personal.refresh_from_db()
        self.assertFalse(personal.deleted)

    def test_expired_cached_totp_is_not_reused_after_restore(self):
        request_id = str(uuid.uuid4())
        self.assertEqual(self.post("totp_issue", request_id=request_id).status_code, 200)
        self.post("item_delete")
        self.assertLessEqual(IssuedCode.objects.get().expires_at, timezone.now())
        self.post("item_restore")
        self.assertEqual(self.post("totp_issue", request_id=request_id).status_code, 409)

    def test_trashed_vault_is_absent_from_team_forms_and_legacy_management(self):
        self.post("vault_delete", self.vault.pk)
        self.assertNotIn(self.vault, self.client.get(reverse("team") + "?tab=vaults").context["page_obj"].object_list)
        self.assertEqual(self.client.get(reverse("team") + f"?edit_vault={self.vault.pk}").status_code, 404)
        self.assertEqual(self.client.get(reverse("members", args=[self.vault.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse("home") + f"?vault={self.vault.pk}").status_code, 404)
        self.assertNotIn(self.vault, self.client.get(reverse("item_new")).context["form"].fields["vault"].queryset)

    def test_delete_and_restore_require_post_and_csrf(self):
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        for route, target in (("item_delete", self.item.pk), ("vault_delete", self.vault.pk), ("item_restore", self.item.pk), ("vault_restore", self.vault.pk)):
            self.assertEqual(self.client.get(reverse(route, args=[target])).status_code, 405)
            self.assertEqual(strict.post(reverse(route, args=[target])).status_code, 403)

    def test_failed_audit_rolls_back_deletion(self):
        self.client.raise_request_exception = False
        with patch("vault.views_trash.audit", side_effect=RuntimeError("Synthetic failure")):
            self.assertEqual(self.post("item_delete").status_code, 500)
            self.assertEqual(self.post("vault_delete", self.vault.pk).status_code, 500)
        self.item.refresh_from_db()
        self.vault.refresh_from_db()
        self.assertFalse(self.item.deleted or self.vault.deleted)

    def test_deletion_between_initial_check_and_write_blocks_stale_edit(self):
        from .views import item_for
        def trash_after_check(request, item_id, right="read"):
            item = item_for(request, item_id, right)
            Item.objects.filter(pk=item.pk).update(deleted=True)
            return item
        with patch("vault.views.item_for", side_effect=trash_after_check):
            response = self.client.post(reverse("item_edit", args=[self.item.pk]), dict(title="Changed", kind="account", vault=str(self.vault.pk), login="new", password="new", url="", note="", tags="", version=1))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(ItemVersion.objects.filter(item=self.item).count(), 1)
        self.assert_payload_retained()

    def test_trash_listing_search_and_vault_contents_render(self):
        self.post("vault_delete", self.vault.pk)
        for query in ("", "?tab=vaults", f"?vault={self.vault.pk}", "?q=Секрет"):
            self.assertEqual(self.client.get(reverse("trash") + query).status_code, 200)
        self.assertEqual(self.client.get(reverse("trash") + "?vault=bad").status_code, 400)
        self.assertEqual(self.client.get(reverse("trash_item", args=[self.item.pk])).status_code, 200)

    def test_old_trash_reveal_endpoint_cannot_be_used_after_restore(self):
        self.post("item_delete")
        self.post("item_restore")
        self.assertEqual(self.post("trash_reveal", field="password").status_code, 409)
        self.assertEqual(self.client.get(reverse("trash_item", args=[self.item.pk])).status_code, 404)
