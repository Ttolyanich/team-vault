import base64
import uuid
from types import SimpleNamespace
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from . import crypto
from .access import permissions, visible_vaults
from .models import Department, Vault, Membership, Item, ItemVersion, AuditEvent, TotpConfig, RecoveryCode
from .services import totp_data


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode())
class TeamTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", is_superuser=True, is_local_admin=True)
        self.head = User.objects.create_user(username="head")
        self.other_head = User.objects.create_user(username="other-head")
        self.member = User.objects.create_user(username="member")
        self.outsider = User.objects.create_user(username="outsider")
        self.unit = Department.objects.create(name="Контент", head=self.head)
        self.other_unit = Department.objects.create(name="Финансы", head=self.other_head)
        self.member.department = self.unit
        self.member.save()
        self.outsider.department = self.other_unit
        self.outsider.save()
        self.vault = Vault.objects.create(name="Социальные сети", department=self.unit)
        self.item = Item.objects.create(vault=self.vault, owner=self.member, title="Рабочий доступ")
        ItemVersion.objects.create(item=self.item, number=1, author=self.member,
            payload=crypto.seal({"login": "test", "password": "synthetic-secret", "url": "", "note": ""}, f"item:{self.item.pk}:1"))
        TotpConfig.objects.create(item=self.item, payload=crypto.seal(totp_data("JBSWY3DPEHPK3PXP"), f"totp:{self.item.pk}:1"))
        self.client.force_login(self.admin)

    def post(self, action, **values):
        return self.client.post(reverse("team"), {"action": action, **values})

    def vault_values(self, **values):
        data = dict(name="Новое хранилище", description="", department=str(self.unit.pk), access_mode="selected", department_role="reader", revision=0)
        data.update(values)
        return data

    def grant(self, person=None, **values):
        data = dict(vault=str(self.vault.pk), person=(person or self.member).pk, role="reader", revision=self.vault.access_revision)
        data.update(values)
        result = self.post("permission", **data)
        self.vault.refresh_from_db()
        return result

    def transfer(self, user, department):
        self.client.force_login(self.admin)
        user.refresh_from_db()
        return self.post("person", object=user.pk, department=str(department.pk) if department else "", is_active="on", revision=user.team_revision)

    def test_team_pages_and_drawers_render_with_one_navigation_entry(self):
        for query in ("", f"?department={self.unit.pk}", f"?department={self.unit.pk}&assign=1", f"?department={self.unit.pk}&tab=vaults", "?department=unassigned", "?new_department=1", f"?edit_department={self.unit.pk}", f"?person={self.member.pk}", f"?department={self.unit.pk}&new_vault=1", f"?edit_vault={self.vault.pk}", f"?access={self.vault.pk}"):
            response = self.client.get(reverse("team") + query)
            self.assertEqual(response.status_code, 200, query)
        response = self.client.get(reverse("team"))
        self.assertContains(response, 'href="/team/" class="active"')
        self.assertNotContains(response, 'href="/users/"')

    def test_only_admin_and_actual_department_heads_manage_team(self):
        for user in (self.member, self.outsider):
            self.client.force_login(user)
            self.assertEqual(self.client.get(reverse("team")).status_code, 403)
            self.assertEqual(self.post("department", name="Bad", revision=0).status_code, 403)
        self.client.force_login(self.head)
        response = self.client.get(reverse("team"))
        self.assertContains(response, "Контент")
        self.assertNotContains(response, "Финансы")
        for query in (f"?department={self.other_unit.pk}", f"?person={self.outsider.pk}"):
            self.assertEqual(self.client.get(reverse("team") + query).status_code, 404)
        self.assertEqual(self.client.get(reverse("team") + "?department=unassigned").status_code, 403)
        self.assertEqual(self.client.get(reverse("activity")).status_code, 403)

    def test_department_creation_and_head_assignment_are_admin_only(self):
        self.assertEqual(self.post("department", name="Продажи", head=self.member.pk, revision=0).status_code, 302)
        self.assertEqual(Department.objects.get(name="Продажи").head_id, self.member.pk)
        self.client.force_login(self.head)
        self.assertEqual(self.post("department", name="Bad", head=self.head.pk, revision=0).status_code, 403)
        self.assertFalse(Department.objects.filter(name="Bad").exists())

    def test_head_can_create_vault_only_in_own_department(self):
        self.client.force_login(self.head)
        self.assertEqual(self.post("vault", **self.vault_values()).status_code, 302)
        vault = Vault.objects.get(name="Новое хранилище")
        self.assertEqual(vault.department_id, self.unit.pk)
        self.assertFalse(vault.memberships.exists(), "Head access must be derived, not a permanent creator grant")
        self.assertTrue(permissions(self.head, vault)["manage"])
        response = self.post("vault", **self.vault_values(name="Foreign", department=str(self.other_unit.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["drawer_form"].errors)
        self.assertFalse(Vault.objects.filter(name="Foreign").exists())

    def test_selected_access_and_totp_are_independent(self):
        self.client.force_login(self.head)
        self.assertFalse(permissions(self.member, self.vault)["read"])
        self.assertEqual(self.grant().status_code, 302)
        self.assertTrue(permissions(self.member, self.vault)["read"])
        self.assertFalse(permissions(self.member, self.vault)["edit"])
        self.assertFalse(permissions(self.member, self.vault)["totp"])
        self.grant(role="editor", can_totp="on")
        self.assertTrue(permissions(self.member, self.vault)["edit"])
        self.assertTrue(permissions(self.member, self.vault)["totp"])
        self.client.force_login(self.member)
        self.assertEqual(self.client.post(reverse("totp_issue", args=[self.item.pk]), {"request_id": str(uuid.uuid4())}).status_code, 200)

    def test_head_cannot_grant_cross_department_or_promote_anyone(self):
        self.client.force_login(self.head)
        self.assertEqual(self.grant(self.outsider).status_code, 403)
        self.assertEqual(self.post("person", object=self.member.pk, department=str(self.unit.pk), is_active="on", is_superuser="on", revision=0).status_code, 403)
        self.member.refresh_from_db()
        self.assertFalse(self.member.is_superuser)
        self.assertFalse(Membership.objects.filter(user=self.outsider).exists())

    def test_admin_can_grant_explicit_cross_department_access(self):
        self.assertEqual(self.grant(self.outsider).status_code, 302)
        self.assertTrue(permissions(self.outsider, self.vault)["read"])
        self.assertFalse(permissions(self.outsider, self.vault)["manage"])

    def test_all_department_mode_inherits_and_transfer_revokes(self):
        self.vault.access_mode, self.vault.department_totp = "department", True
        self.vault.save()
        self.assertTrue(permissions(self.member, self.vault)["read"])
        self.assertTrue(permissions(self.member, self.vault)["totp"])
        self.assertFalse(permissions(self.outsider, self.vault)["read"])
        self.assertEqual(self.transfer(self.member, self.other_unit).status_code, 302)
        self.member.refresh_from_db()
        self.assertFalse(permissions(self.member, self.vault)["read"])
        self.assertNotIn(self.vault, visible_vaults(self.member))
        self.assertEqual(self.transfer(self.outsider, self.unit).status_code, 302)
        self.outsider.refresh_from_db()
        self.assertTrue(permissions(self.outsider, self.vault)["read"])

    def test_transfer_removes_old_direct_grants_and_keeps_other_grants(self):
        Membership.objects.create(vault=self.vault, user=self.member, role="editor")
        legacy = Vault.objects.create(name="Прежнее хранилище")
        Membership.objects.create(vault=legacy, user=self.member, role="reader")
        self.transfer(self.member, self.other_unit)
        self.member.refresh_from_db()
        self.assertFalse(Membership.objects.filter(vault=self.vault, user=self.member).exists())
        self.assertTrue(permissions(self.member, legacy)["read"])

    def test_new_head_replaces_personal_and_department_access_without_copying_keys(self):
        personal = Vault.objects.create(name="Личное рабочее", personal_owner=self.member)
        self.assertTrue(permissions(self.head, personal)["read"])
        self.assertTrue(permissions(self.head, self.vault)["edit"])
        response = self.post("department", object=str(self.unit.pk), name=self.unit.name, head=self.other_head.pk, revision=0)
        self.assertEqual(response.status_code, 302)
        personal.refresh_from_db()
        self.vault.refresh_from_db()
        self.assertFalse(permissions(self.head, personal)["read"])
        self.assertFalse(permissions(self.head, self.vault)["manage"])
        self.assertTrue(permissions(self.other_head, personal)["read"])
        self.assertTrue(permissions(self.other_head, self.vault)["manage"])
        self.assertEqual(ItemVersion.objects.filter(item=self.item).count(), 1)

    def test_only_current_department_head_receives_recovery_codes(self):
        code = RecoveryCode(item=self.item)
        code.payload = crypto.seal("test-recovery", f"recovery:{self.item.pk}:{code.pk}")
        code.save()
        self.client.force_login(self.head)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, code.pk])).status_code, 200)
        self.client.force_login(self.other_head)
        self.assertEqual(self.client.post(reverse("recovery_action", args=[self.item.pk, code.pk])).status_code, 403)

    def test_all_mode_cannot_be_overridden_by_individual_grant(self):
        self.vault.access_mode = "department"
        self.vault.save()
        Membership.objects.create(vault=self.vault, user=self.member, role="editor", can_totp=True)
        self.assertFalse(permissions(self.member, self.vault)["edit"])
        self.assertFalse(permissions(self.member, self.vault)["totp"])
        self.assertEqual(self.grant(role="editor").status_code, 400)

    def test_policy_switch_clears_individual_grants_but_keeps_contents(self):
        self.grant(role="editor", can_totp="on")
        self.assertEqual(self.post("vault", object=str(self.vault.pk), **self.vault_values(name=self.vault.name, revision=self.vault.access_revision, access_mode="department")).status_code, 302)
        self.assertFalse(Membership.objects.filter(vault=self.vault).exists())
        self.assertTrue(Item.objects.filter(pk=self.item.pk).exists())
        self.vault.refresh_from_db()
        self.assertEqual(self.vault.access_mode, "department")

    def test_stale_department_and_user_forms_are_rejected(self):
        self.post("department", object=str(self.unit.pk), name=self.unit.name, head=self.head.pk, revision=0)
        self.assertEqual(self.post("department", object=str(self.unit.pk), name="Stale", head=self.other_head.pk, revision=0).status_code, 409)
        self.transfer(self.member, self.other_unit)
        self.assertEqual(self.post("person", object=self.member.pk, department=str(self.unit.pk), is_active="on", revision=0).status_code, 409)
        self.member.refresh_from_db()
        self.assertEqual(self.member.department_id, self.other_unit.pk)

    def test_stale_policy_and_permission_forms_do_not_overwrite(self):
        self.grant(role="editor")
        self.assertEqual(self.post("vault", object=str(self.vault.pk), **self.vault_values(revision=0)).status_code, 409)
        self.grant(role="none", revision=0)
        self.assertEqual(Membership.objects.get(vault=self.vault, user=self.member).role, "editor")

    def test_personal_vault_and_foreign_vault_cannot_be_managed_via_team(self):
        personal = Vault.objects.create(name="Личное", personal_owner=self.member)
        self.assertEqual(self.post("permission", person=self.member.pk, vault=str(personal.pk), role="editor", revision=0).status_code, 404)
        self.client.force_login(self.other_head)
        self.assertEqual(self.grant().status_code, 404)
        self.assertEqual(self.client.get(reverse("team") + f"?access={self.vault.pk}").status_code, 404)

    def test_local_admin_is_protected_and_csrf_required(self):
        self.assertEqual(self.post("person", object=self.admin.pk, department="", revision=0).status_code, 403)
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        self.assertEqual(strict.post(reverse("team"), {"action": "department", "name": "Bad", "revision": 0}).status_code, 403)

    def test_legacy_members_endpoint_cannot_bypass_department_rules(self):
        self.client.force_login(self.head)
        self.assertEqual(self.client.post(reverse("members", args=[self.vault.pk]), {"user": self.outsider.pk, "role": "editor"}).status_code, 405)
        self.assertEqual(self.client.post(reverse("members", args=[self.vault.pk]), {"user": self.member.pk, "role": "owner"}).status_code, 405)

    def test_bad_ids_and_unknown_actions_are_safe(self):
        self.assertEqual(self.client.get(reverse("team") + "?department=bad").status_code, 400)
        self.assertEqual(self.post("unknown").status_code, 400)
        self.assertEqual(self.post("person", object="bad").status_code, 400)

    def test_team_mutations_are_audited_without_secret_contents(self):
        self.grant()
        self.assertTrue(AuditEvent.objects.filter(action="vault.membership_changed", actor=self.admin).exists())
        self.assertNotIn("synthetic-secret", str(list(AuditEvent.objects.values_list("details", flat=True))))

    def test_add_unassigned_person_is_admin_only_and_does_not_overwrite_roles(self):
        person = get_user_model().objects.create_user(username="new", is_superuser=True)
        self.assertEqual(self.post("assign_person", object=person.pk, department=str(self.unit.pk)).status_code, 302)
        person.refresh_from_db()
        self.assertTrue(person.is_superuser)
        self.assertEqual(person.department_id, self.unit.pk)
        self.assertEqual(self.post("assign_person", object=person.pk, department=str(self.other_unit.pk)).status_code, 404)
        self.client.force_login(self.head)
        self.assertEqual(self.post("assign_person", object=self.outsider.pk, department=str(self.unit.pk)).status_code, 403)

    def test_external_grants_are_visible_but_not_editable_by_head(self):
        self.grant(self.outsider)
        self.client.force_login(self.head)
        response = self.client.get(reverse("team") + f"?access={self.vault.pk}")
        self.assertContains(response, "outsider")
        row = next(row for row in response.context["access_rows"] if row["person"].pk == self.outsider.pk)
        self.assertFalse(row["editable"])

    def test_parallel_external_login_cannot_overwrite_department_or_admin_changes(self):
        from .ldap_directory import DirectoryIdentity
        User = get_user_model()
        for provider in ("microsoft", "ldap"):
            with self.subTest(provider=provider):
                identity_guid = uuid.uuid4()
                fields = {"entra_tenant": "test-tenant", "entra_oid": str(identity_guid)} if provider == "microsoft" else {"ad_object_guid": identity_guid}
                person = User.objects.create_user(username="concurrent-" + provider, department=self.unit, is_superuser=True, **fields)
                self.client.logout()
                original_save = User.save
                changed = []
                def concurrent_change(instance, *args, **kwargs):
                    if instance.pk == person.pk and instance.display_name == "Changed" and not changed:
                        changed.append(True)
                        User.objects.filter(pk=person.pk).update(department=self.other_unit, is_superuser=False, team_revision=7)
                    return original_save(instance, *args, **kwargs)
                with patch.object(User, "save", concurrent_change):
                    if provider == "microsoft":
                        identity = {"tid": "test-tenant", "oid": str(identity_guid), "name": "Changed", "email": "test@example.com"}
                        with override_settings(ENTRA_TENANT_ID="test-tenant"), patch("vault.views.oauth_client", return_value=SimpleNamespace(authorize_access_token=lambda request: {"userinfo": identity})):
                            self.assertEqual(self.client.get(reverse("sso_callback")).status_code, 302)
                    else:
                        with patch("vault.views_ldap.authenticate_directory", return_value=DirectoryIdentity(identity_guid, "Changed", "test@example.com")):
                            self.assertEqual(self.client.post(reverse("ldap_login"), {"username": "test", "password": "synthetic-password"}).status_code, 302)
                person.refresh_from_db()
                self.assertTrue(changed)
                self.assertEqual(person.department_id, self.other_unit.pk)
                self.assertFalse(person.is_superuser)
                self.assertEqual(person.team_revision, 7)

    def test_create_local_user_and_login(self):
        User = get_user_model()
        self.client.force_login(self.admin)
        response = self.post("new_person",
            username="local_john",
            display_name="Джон Доу",
            email="john@example.com",
            password="A-Very-Secure-Password-1234!",
            password_confirm="A-Very-Secure-Password-1234!",
            department=str(self.unit.pk),
            is_superuser=False
        )
        self.assertEqual(response.status_code, 302)
        user = User.objects.get(username="local_john")
        self.assertEqual(user.display_name, "Джон Доу")
        self.assertEqual(user.department_id, self.unit.pk)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)
        self.assertTrue(hasattr(user, "personal_vault"))

        # Test local login
        self.client.logout()
        login_resp = self.client.post(reverse("login"), {
            "username": "local_john",
            "password": "A-Very-Secure-Password-1234!"
        })
        self.assertEqual(login_resp.status_code, 302)
        self.assertEqual(login_resp.url, reverse("home"))

    def test_reset_password_for_local_user(self):
        User = get_user_model()
        local_user = User.objects.create_user(
            username="local_alice",
            password="Old-Password-12345678!",
            display_name="Алиса",
            department=self.unit
        )
        old_revision = local_user.auth_revision
        self.client.force_login(self.admin)
        response = self.post("reset_password",
            object=str(local_user.pk),
            new_password="New-Password-12345678!",
            new_password_confirm="New-Password-12345678!"
        )
        self.assertEqual(response.status_code, 302)
        local_user.refresh_from_db()
        self.assertGreater(local_user.auth_revision, old_revision)

        # Test login with new password succeeds and old fails
        self.client.logout()
        fail_resp = self.client.post(reverse("login"), {
            "username": "local_alice",
            "password": "Old-Password-12345678!"
        })
        self.assertEqual(fail_resp.status_code, 400)
        ok_resp = self.client.post(reverse("login"), {
            "username": "local_alice",
            "password": "New-Password-12345678!"
        })
        self.assertEqual(ok_resp.status_code, 302)
