import base64
import uuid
from unittest.mock import patch
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from . import crypto
from .models import Department, Vault, Membership, Item, ItemVersion, TotpConfig, RecoveryCode, IssuedCode, AuditEvent
from .services import totp_data


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode())
class VaultSecurityTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", password="Admin-test-password-2026", is_superuser=True, is_local_admin=True)
        self.member = User.objects.create_user(username="member")
        self.leader = User.objects.create_user(username="leader", is_manager=True)
        self.other = User.objects.create_user(username="other")
        self.department = Department.objects.create(name="Контент", head=self.leader)
        self.vault = Vault.objects.create(name="Контент", department=self.department)
        for user in (self.member, self.leader):
            Membership.objects.create(vault=self.vault, user=user, role="editor", can_totp=True)
        self.item = Item.objects.create(vault=self.vault, title="Рабочая УЗ", owner=self.member)
        self.secret = "Synthetic-secret-123"
        ItemVersion.objects.create(item=self.item, number=1, author=self.member,
            payload=crypto.seal({"login": "work", "password": self.secret, "url": "https://example.com", "note": "note"}, f"item:{self.item.pk}:1"))
        self.seed = "JBSWY3DPEHPK3PXP"
        TotpConfig.objects.create(item=self.item, payload=crypto.seal(totp_data(self.seed), f"totp:{self.item.pk}:1"))
        self.code = RecoveryCode(item=self.item)
        self.code.payload = crypto.seal("recovery-synthetic-123", f"recovery:{self.item.pk}:{self.code.pk}")
        self.code.save()

    def as_user(self, user):
        user.refresh_from_db()
        self.client.force_login(user)

    def test_encryption_tamper_and_context(self):
        envelope = crypto.seal("value", "record:1")
        self.assertEqual(crypto.unseal(envelope, "record:1"), "value")
        self.assertNotEqual(envelope, crypto.seal("value", "record:1"))
        with self.assertRaises(Exception):
            crypto.unseal(envelope, "record:2")
        envelope["data"] = envelope["data"][:-4] + "AAAA"
        with self.assertRaises(Exception):
            crypto.unseal(envelope, "record:1")

    def test_local_admin_and_local_user_login(self):
        response = self.client.post(reverse("login"), {"username": "admin", "password": "Admin-test-password-2026"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get(reverse("home")).status_code, 200)
        self.client.logout()
        self.member.set_password("Member-test-password-2026")
        self.member.save()
        # Active local user can log in
        response = self.client.post(reverse("login"), {"username": "member", "password": "Member-test-password-2026"})
        self.assertEqual(response.status_code, 302)
        self.client.logout()
        # Inactive local user cannot log in
        self.member.is_active = False
        self.member.save()
        response = self.client.post(reverse("login"), {"username": "member", "password": "Member-test-password-2026"})
        self.assertEqual(response.status_code, 400)

    def test_bootstrap_idempotent_and_password_rotation(self):
        with override_settings(LOCAL_ADMIN_USERNAME="admin", LOCAL_ADMIN_PASSWORD="A-fresh-admin-password-2026"):
            call_command("bootstrap_admin", verbosity=0)
            call_command("bootstrap_admin", verbosity=0)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password("A-fresh-admin-password-2026"))
        self.assertEqual(Vault.objects.filter(personal_owner=self.admin).count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="admin.bootstrap").count(), 1)

    def test_startup_refuses_changed_encryption_key(self):
        from django.core.management.base import CommandError
        with override_settings(LOCAL_ADMIN_PASSWORD="A-fresh-admin-password-2026"):
            call_command("bootstrap_admin", verbosity=0)
            with override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"z" * 32).decode()):
                with self.assertRaises(CommandError):
                    call_command("bootstrap_admin", verbosity=0)

    def test_oidc_identity_survives_email_change_and_bad_tenant_is_denied(self):
        from types import SimpleNamespace
        identity = {"tid": "test-tenant", "oid": "test-oid", "name": "Сотрудник", "email": "first@example.com"}
        with override_settings(ENTRA_TENANT_ID="test-tenant"):
            for email in ["first@example.com", "changed@example.com"]:
                identity["email"] = email
                with patch("vault.views.oauth_client", return_value=SimpleNamespace(authorize_access_token=lambda request: {"userinfo": dict(identity)})):
                    self.assertEqual(self.client.get(reverse("sso_callback")).status_code, 302)
            self.assertEqual(get_user_model().objects.filter(entra_oid="test-oid").count(), 1)
            self.client.logout()
            identity["tid"] = "other-tenant"
            with patch("vault.views.oauth_client", return_value=SimpleNamespace(authorize_access_token=lambda request: {"userinfo": dict(identity)})):
                self.assertEqual(self.client.get(reverse("sso_callback")).status_code, 400)

    def test_create_and_edit_version_conflict(self):
        self.as_user(self.admin)
        data = {"title": "Новая запись", "kind": "account", "vault": str(self.vault.pk), "login": "example", "password": "Synthetic-123", "url": "", "note": "", "tags": "test"}
        response = self.client.post(reverse("item_new"), data)
        self.assertEqual(response.status_code, 302)
        item = Item.objects.get(title="Новая запись")
        data["version"] = "0"
        self.assertEqual(self.client.post(reverse("item_edit", args=[item.pk]), data).status_code, 409)
        data["version"] = "1"
        self.assertEqual(self.client.post(reverse("item_edit", args=[item.pk]), data).status_code, 302)
        item.refresh_from_db()
        self.assertEqual(item.version, 2)

    def test_csrf_enforced(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.member)
        self.assertEqual(client.post(reverse("reveal", args=[self.item.pk]), {"field": "password"}).status_code, 403)

    def test_outsider_cannot_read_search_or_reveal(self):
        self.as_user(self.other)
        self.assertNotContains(self.client.get(reverse("home")), self.item.title)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse("reveal", args=[self.item.pk]), {"field": "password"}).status_code, 403)

    def test_item_page_never_embeds_secret_material(self):
        self.as_user(self.member)
        response = self.client.get(reverse("item", args=[self.item.pk]))
        for value in [self.secret, self.seed, "recovery-synthetic-123"]:
            self.assertNotContains(response, value)
        self.assertEqual(response.context["visible_values"], {"login": "work", "url": "https://example.com", "note": "note"})
        self.assertContains(response, 'value="work"')
        self.assertContains(response, 'value="https://example.com"')
        self.assertContains(response, 'placeholder="Заметка не добавлена">note</textarea>')
        event = AuditEvent.objects.get(action="item.opened", actor=self.member)
        self.assertEqual(event.details["fields"], ["login", "url", "note"])
        self.assertNotIn("https://example.com", str(event.details))

    def test_reveal_allowlist_excludes_seed_and_codes(self):
        self.as_user(self.member)
        for name in ["secret", "seed", "recovery", "payload"]:
            self.assertEqual(self.client.post(reverse("reveal", args=[self.item.pk]), {"field": name}).status_code, 400)
        result = self.client.post(reverse("reveal", args=[self.item.pk]), {"field": "password"})
        self.assertEqual(result.json()["value"], self.secret)

    def test_admin_cannot_read_recovery_without_assignment(self):
        for user in [self.admin, self.member, self.other]:
            self.as_user(user)
            self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 403)

    def test_leader_recovery_and_used_state(self):
        self.as_user(self.leader)
        url = reverse("recovery_action", args=[self.item.pk, self.code.pk])
        self.assertEqual(self.client.post(url).json()["value"], "recovery-synthetic-123")
        self.assertEqual(self.client.post(url, {"action": "used"}).status_code, 200)
        self.assertEqual(self.client.post(url).status_code, 409)

    def test_two_totp_clicks_are_two_events_and_retry_is_one(self):
        self.as_user(self.member)
        url = reverse("totp_issue", args=[self.item.pk])
        first_id = str(uuid.uuid4())
        result = self.client.post(url, {"request_id": first_id})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(len(result.json()["code"]), 6)
        self.assertEqual(self.client.post(url, {"request_id": first_id}).json()["code"], result.json()["code"])
        self.assertEqual(self.client.post(url, {"request_id": str(uuid.uuid4())}).status_code, 200)
        self.assertEqual(AuditEvent.objects.filter(action="totp.requested").count(), 2)
        event = AuditEvent.objects.filter(action="totp.requested").first()
        self.assertNotIn(self.seed, str(event.details))
        self.assertNotIn("code", event.details)

    def test_distinct_actors_in_totp_audit(self):
        for user in [self.member, self.leader]:
            self.as_user(user)
            self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())})
        self.assertEqual(set(AuditEvent.objects.filter(action="totp.requested").values_list("actor_id", flat=True)), {self.member.pk, self.leader.pk})

    def test_failed_audit_does_not_issue_code(self):
        self.as_user(self.member)
        self.client.raise_request_exception = False
        with patch("vault.views.audit", side_effect=RuntimeError("Synthetic audit failure")):
            response = self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())})
        self.assertEqual(response.status_code, 500)
        self.assertEqual(IssuedCode.objects.count(), 0)

    def test_membership_revocation_applies_to_open_session(self):
        self.as_user(self.member)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 200)
        Membership.objects.filter(user=self.member).delete()
        self.assertEqual(self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())}).status_code, 403)

    def test_totp_permission_independent_of_read_permission(self):
        Membership.objects.filter(user=self.member).update(can_totp=False)
        self.as_user(self.member)
        self.assertEqual(self.client.get(reverse("item", args=[self.item.pk])).status_code, 200)
        self.assertEqual(self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())}).status_code, 403)

    def test_editor_cannot_replace_totp_or_recovery(self):
        self.as_user(self.member)
        self.assertEqual(self.client.post(reverse("totp_setup", args=[self.item.pk]), {"configuration": self.seed, "confirmed": "on"}).status_code, 403)
        self.assertEqual(self.client.post(reverse("recovery_replace", args=[self.item.pk]), {"codes": "test"}).status_code, 403)

    def test_personal_manager_scope(self):
        self.member.manager = self.leader
        self.member.save()
        vault = Vault.objects.create(name="Личное рабочее", personal_owner=self.member)
        Item.objects.create(vault=vault, title="Личная рабочая запись", owner=self.member)
        self.as_user(self.leader)
        self.assertNotContains(self.client.get(reverse("home") + "?section=personal"), "Личная рабочая запись")
        self.assertContains(self.client.get(reverse("staff_secrets", args=[self.member.pk])), "Личная рабочая запись")
        self.as_user(self.other)
        self.assertNotContains(self.client.get(reverse("home") + "?section=personal"), "Личная рабочая запись")

    def test_totp_validation_rejects_hotp_and_empty_secret(self):
        from django.core.exceptions import ValidationError
        for value in ["", "X", "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP&counter=1"]:
            with self.assertRaises(ValidationError):
                totp_data(value)

    def test_readonly_user_cannot_edit(self):
        Membership.objects.filter(user=self.member).update(role="reader")
        self.as_user(self.member)
        self.assertEqual(self.client.get(reverse("item_edit", args=[self.item.pk])).status_code, 403)

    def test_department_head_change_transfers_recovery_access(self):
        self.department.head = self.admin
        self.department.save()
        self.as_user(self.admin)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 200)
        self.as_user(self.leader)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 403)

    def test_personal_recovery_follows_owner_manager_not_record_author(self):
        self.member.manager = self.leader; self.member.save()
        private = Vault.objects.create(name="Личное", personal_owner=self.member)
        self.item.vault = private; self.item.owner = self.other; self.item.save()
        url = reverse("recovery_action", args=[self.item.pk, self.code.pk])
        self.as_user(self.leader); self.assertEqual(self.client.post(url).status_code, 200)
        self.member.manager = self.other; self.member.save()
        self.assertEqual(self.client.post(url).status_code, 403)
        self.as_user(self.other); self.assertEqual(self.client.post(url).status_code, 200)
        self.as_user(self.admin); self.assertEqual(self.client.post(url).status_code, 403)

    def test_personal_recovery_tracks_department_head_and_transfer(self):
        self.member.department = self.department; self.member.manager = self.other; self.member.save()
        self.item.vault = Vault.objects.create(name="Личное", personal_owner=self.member); self.item.save()
        url = reverse("recovery_action", args=[self.item.pk, self.code.pk])
        self.as_user(self.other); self.assertEqual(self.client.post(url).status_code, 403)
        self.as_user(self.leader); self.assertEqual(self.client.post(url).status_code, 200)
        self.department.head = self.other; self.department.save()
        self.assertEqual(self.client.post(url).status_code, 403)
        self.as_user(self.other); self.assertEqual(self.client.post(url).status_code, 200)
        self.member.department = Department.objects.create(name="Новый отдел", head=self.admin); self.member.save()
        self.assertEqual(self.client.post(url).status_code, 403)
        self.as_user(self.admin); self.assertEqual(self.client.post(url).status_code, 200)

    def test_no_head_or_inactive_head_does_not_grant_recovery_to_admin(self):
        self.department.head = None; self.department.save()
        for user in (self.admin, self.member, self.leader):
            self.as_user(user)
            self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 403)
        self.leader.is_active = False; self.leader.save()
        self.department.head = self.leader; self.department.save()
        self.as_user(self.admin)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 403)

    def test_record_form_cannot_override_inherited_recovery_manager(self):
        self.as_user(self.admin)
        self.assertNotContains(self.client.get(reverse("item_edit", args=[self.item.pk])), 'name="recovery_manager"')
        self.assertEqual(self.client.post(reverse("item_edit", args=[self.item.pk]), dict(title=self.item.title,kind="account",vault=self.vault.pk,login="",password="",url="",note="",tags="",version=1,recovery_manager=self.admin.pk)).status_code, 302)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk])).status_code, 403)

    def test_new_head_can_manage_existing_codes_and_totp_old_head_cannot(self):
        self.department.head = self.other; self.department.save()
        for user, expected in ((self.leader, 403), (self.other, 302)):
            self.as_user(user)
            self.assertEqual(self.client.post(reverse("totp_setup", args=[self.item.pk]), {"configuration":self.seed,"confirmed":"on"}).status_code, expected)
            self.assertEqual(self.client.post(reverse("recovery_replace", args=[self.item.pk]), {"codes":"new-recovery-code"}).status_code, expected)

    def test_head_replacement_between_initial_check_and_locked_read_is_rechecked(self):
        from .records import locked_item_for
        def replace_then_lock(*args, **kwargs):
            Department.objects.filter(pk=self.department.pk).update(head=self.other)
            return locked_item_for(*args, **kwargs)
        self.as_user(self.leader)
        with patch("vault.views.locked_item_for", side_effect=replace_then_lock):
            response = self.client.post(reverse("recovery_action", args=[self.item.pk, self.code.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AuditEvent.objects.filter(action="recovery.revealed").exists())

    def test_config_replacement_invalidates_prior_request(self):
        self.as_user(self.leader)
        request_id = str(uuid.uuid4())
        url = reverse("totp_issue", args=[self.item.pk])
        self.assertEqual(self.client.post(url, {"request_id": request_id}).status_code, 200)
        self.assertEqual(self.client.post(reverse("totp_setup", args=[self.item.pk]), {"configuration": self.seed, "confirmed": "on"}).status_code, 302)
        self.assertEqual(self.client.post(url, {"request_id": request_id}).status_code, 409)

    def test_totp_rate_limit(self):
        self.as_user(self.member)
        for _ in range(10):
            self.assertEqual(self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())}).status_code, 200)
        self.assertEqual(self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())}).status_code, 429)

    def test_activity_is_admin_only_in_menu_and_direct_requests(self):
        for user in (self.member, self.leader):
            self.as_user(user)
            self.assertNotContains(self.client.get(reverse("home")), 'href="/activity/"')
            self.assertEqual(self.client.get(reverse("activity")).status_code, 403)
        self.as_user(self.admin)
        self.assertContains(self.client.get(reverse("home")), 'href="/activity/"')
        self.assertEqual(self.client.get(reverse("activity")).status_code, 200)

    def test_external_accounts_can_be_promoted_and_demoted_by_admin(self):
        for identity in ({"ad_object_guid": uuid.uuid4()}, {"entra_tenant": "tenant", "entra_oid": "object-id"}):
            user = get_user_model().objects.create_user(username="external_" + uuid.uuid4().hex, **identity)
            self.as_user(self.admin)
            self.assertEqual(self.client.post(reverse("users"), {"user": user.pk, "is_active": "on", "is_superuser": "on"}).status_code, 302)
            user.refresh_from_db()
            self.assertTrue(user.is_superuser)
            self.as_user(user)
            for route in ("users", "activity", "microsoft_config", "ldap_config"):
                self.assertEqual(self.client.get(reverse(route)).status_code, 200)
            self.as_user(self.admin)
            self.client.post(reverse("users"), {"user": user.pk, "is_active": "on"})
            self.as_user(user)
            self.assertEqual(self.client.get(reverse("activity")).status_code, 403)
            self.assertTrue(AuditEvent.objects.filter(action="user.permissions_changed", target=str(user.pk), details__admin=False).exists())

    def test_member_cannot_promote_self(self):
        self.as_user(self.member)
        self.assertEqual(self.client.post(reverse("users"), {"user": self.member.pk, "is_active": "on", "is_superuser": "on"}).status_code, 403)
        self.member.refresh_from_db()
        self.assertFalse(self.member.is_superuser)

    def test_oidc_login_preserves_assigned_admin_role(self):
        from types import SimpleNamespace
        user = get_user_model().objects.create_user(username="entra-admin", entra_tenant="test-tenant", entra_oid="admin-oid", is_superuser=True)
        identity = {"tid": "test-tenant", "oid": "admin-oid", "name": "Admin", "email": "admin@example.com"}
        self.client.logout()
        with override_settings(ENTRA_TENANT_ID="test-tenant"), patch("vault.views.oauth_client", return_value=SimpleNamespace(authorize_access_token=lambda request: {"userinfo": identity})):
            self.assertEqual(self.client.get(reverse("sso_callback")).status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.is_superuser)
        self.assertEqual(self.client.get(reverse("activity")).status_code, 200)
