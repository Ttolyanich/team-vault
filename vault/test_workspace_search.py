import base64
import datetime
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.management import call_command
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from .models import Department, Vault, Item, Membership, AuditEvent, IssuedCode, LoginAttempt
from .forms_team import DepartmentForm


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode())
class WorkspaceSearchTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", is_superuser=True)
        self.head = User.objects.create_user(username="head")
        self.a = Department.objects.create(name="Контент", head=self.head)
        self.b = Department.objects.create(name="Финансы")
        self.admin.department = self.a; self.admin.save()
        self.member = User.objects.create_user(username="member", display_name="Мария Тестовая", email="member@example.test", department=self.a)
        self.other = User.objects.create_user(username="other", display_name="Иван Чужой", department=self.b)
        self.mine = Vault.objects.create(name="Личное", personal_owner=self.admin)
        self.theirs = Vault.objects.create(name="Личное сотрудника", personal_owner=self.member)
        Item.objects.create(vault=self.mine, title="Только моя запись", owner=self.admin)
        Item.objects.create(vault=self.theirs, title="Запись сотрудника", owner=self.member)
        self.shared = Vault.objects.create(name="Наше хранилище", department=self.a, access_mode="department")
        self.foreign = Vault.objects.create(name="Другой отдел", department=self.b, access_mode="department")
        Item.objects.create(vault=self.shared, title="Наш общий доступ", owner=self.admin)
        Item.objects.create(vault=self.foreign, title="Чужой общий доступ", owner=self.other)
        self.client.force_login(self.admin)

    def choice(self, **params):
        return self.client.get(reverse("choices"), params)

    def test_my_personal_workspace_never_contains_other_users_records(self):
        response = self.client.get(reverse("home") + "?section=personal")
        self.assertContains(response, "Только моя запись")
        self.assertNotContains(response, "Запись сотрудника")
        self.assertEqual(self.client.get(reverse("home") + f"?section=personal&vault={self.theirs.pk}").status_code, 404)

    def test_admin_default_shared_scope_is_department_and_explicit_grants(self):
        response = self.client.get(reverse("home"))
        self.assertContains(response, "Наш общий доступ")
        self.assertNotContains(response, "Чужой общий доступ")
        Membership.objects.create(vault=self.foreign, user=self.admin, role="reader")
        self.assertContains(self.client.get(reverse("home")), "Чужой общий доступ")

    def test_separate_admin_overviews_show_foreign_data(self):
        self.assertContains(self.client.get(reverse("all_vaults")), "Чужой общий доступ")
        self.assertContains(self.client.get(reverse("staff_directory"), {"q": "Мария"}), "Мария Тестовая")
        self.assertContains(self.client.get(reverse("staff_secrets", args=[self.member.pk])), "Запись сотрудника")
        self.assertTrue(AuditEvent.objects.filter(action="workspace.reviewed", target=str(self.member.pk)).exists())
        self.assertRedirects(self.client.get(reverse("home") + f"?vault={self.foreign.pk}"), reverse("all_vaults") + f"?vault={self.foreign.pk}")

    def test_ordinary_users_cannot_open_admin_overviews_or_settings(self):
        for actor in (self.member, self.head):
            self.client.force_login(actor)
            for route in ("staff_directory", "all_vaults", "settings_page"):
                self.assertEqual(self.client.get(reverse(route)).status_code, 403)
            self.assertEqual(self.choice(kind="vaults", purpose="all_shared").status_code, 403)

    def test_head_can_review_only_reports_via_separate_route(self):
        self.client.force_login(self.head)
        self.assertNotContains(self.client.get(reverse("home") + "?section=personal"), "Запись сотрудника")
        self.assertContains(self.client.get(reverse("staff_secrets", args=[self.member.pk])), "Запись сотрудника")
        self.assertEqual(self.client.get(reverse("staff_secrets", args=[self.other.pk])).status_code, 403)
        self.assertEqual(self.client.get(reverse("vault_open", args=[self.shared.pk])).status_code, 200)

    def test_directory_paginates_without_dumping_all_people(self):
        User = get_user_model()
        User.objects.bulk_create([User(username=f"load{i:03d}", display_name=f"Сотрудник {i:03d}", email=f"load{i:03d}@example.test", department=self.a) for i in range(320)])
        first = self.choice(kind="people", purpose="head").json()
        second = self.choice(kind="people", purpose="head", page=2).json()
        self.assertEqual(len(first["results"]), 20); self.assertTrue(first["more"])
        self.assertFalse(set(row["id"] for row in first["results"]) & set(row["id"] for row in second["results"]))
        result = self.choice(kind="people", purpose="head", q="load319@example.test").json()
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["label"], "Сотрудник 319")
        response = self.client.get(reverse("team") + "?new_department=1")
        self.assertNotContains(response, "load319@example.test")
        self.assertLess(len(response.content), 50000)
        response = self.client.get(reverse("team") + f"?access={self.shared.pk}")
        self.assertNotContains(response, "load319@example.test")
        self.assertLess(len(response.content), 40000)

    def test_choice_widget_keeps_only_selected_person_in_html(self):
        html = DepartmentForm(instance=self.a).as_p()
        self.assertIn(str(self.head.pk), html)
        self.assertNotIn("Мария Тестовая", html)
        self.assertIn("data-search-select", html)

    def test_head_cannot_search_or_assign_people_in_another_department(self):
        self.client.force_login(self.head)
        result = self.choice(kind="people", purpose="membership", vault=str(self.shared.pk), q="Иван").json()
        self.assertEqual(result["results"], [])
        self.assertEqual(self.choice(kind="people", purpose="head").status_code, 403)
        self.assertEqual(self.choice(kind="people", purpose="membership", vault=str(self.foreign.pk)).status_code, 403)
        departments = self.choice(kind="departments", purpose="managed").json()["results"]
        self.assertEqual([row["id"] for row in departments], [str(self.a.pk)])

    def test_legacy_shared_vault_owner_can_search_grantees_without_full_catalog_html(self):
        legacy = Vault.objects.create(name="Прежнее хранилище")
        Membership.objects.create(vault=legacy, user=self.head, role="owner")
        self.client.force_login(self.head)
        results = self.choice(kind="people", purpose="membership", vault=str(legacy.pk), q="Иван").json()["results"]
        self.assertEqual([row["id"] for row in results], [str(self.other.pk)])
        page = self.client.get(reverse("members", args=[legacy.pk]))
        self.assertContains(page, "data-search-select")
        self.assertNotContains(page, "Иван Чужой")
        self.client.force_login(self.other)
        self.assertEqual(self.choice(kind="people", purpose="membership", vault=str(legacy.pk)).status_code, 403)

    def test_workspace_vault_search_does_not_leak_global_visibility(self):
        result = self.choice(kind="vaults", purpose="workspace_shared").json()["results"]
        self.assertEqual([row["id"] for row in result], [str(self.shared.pk)])
        all_result = self.choice(kind="vaults", purpose="all_shared").json()["results"]
        self.assertEqual(len(all_result), 2)
        self.foreign.deleted = True; self.foreign.save()
        self.assertNotIn(str(self.foreign.pk), [row["id"] for row in self.choice(kind="vaults", purpose="all_shared").json()["results"]])

    def test_session_revocation_logs_out_all_old_sessions_without_disabling_account(self):
        devices = [Client(), Client()]
        for device in devices:
            device.force_login(self.member)
            self.assertEqual(device.get(reverse("home")).status_code, 200)
        self.assertEqual(self.client.post(reverse("team"), {"action":"sessions", "object":self.member.pk}).status_code, 302)
        for device in devices:
            self.assertEqual(device.get(reverse("home")).status_code, 302)
        self.member.refresh_from_db(); self.assertTrue(self.member.is_active)
        devices[0].force_login(self.member)
        self.assertEqual(devices[0].get(reverse("home")).status_code, 200)
        self.assertTrue(AuditEvent.objects.filter(action="auth.sessions_revoked", actor=self.admin).exists())

    def test_head_cannot_revoke_sessions_or_promote_user(self):
        self.client.force_login(self.head)
        self.assertEqual(self.client.post(reverse("team"), {"action":"sessions", "object":self.member.pk}).status_code, 403)

    def test_block_then_reactivate_does_not_revive_old_cookie(self):
        device = Client(); device.force_login(self.member)
        for active in (False, True):
            self.member.refresh_from_db()
            data = {"action":"person", "object":self.member.pk, "department":str(self.a.pk), "revision":self.member.team_revision}
            if active: data["is_active"]="on"
            self.client.post(reverse("team"), data)
        self.assertEqual(device.get(reverse("home")).status_code, 302)

    @override_settings(TRUSTED_PROXY_IPS=["172.30.0.1"])
    def test_client_ip_is_accepted_only_from_trusted_proxy_and_single_address(self):
        for peer, header, expected in (("172.30.0.1", "203.0.113.9", "203.0.113.9"), ("198.51.100.1", "203.0.113.9", "198.51.100.1"), ("172.30.0.1", "bad,203.0.113.9", "172.30.0.1")):
            self.client.get(reverse("staff_secrets", args=[self.member.pk]), REMOTE_ADDR=peer, HTTP_X_FORWARDED_FOR=header)
            self.assertEqual(AuditEvent.objects.filter(action="workspace.reviewed").latest("created_at").ip, expected)

    def test_sensitive_pages_deny_frames_and_browser_cache(self):
        for path in (reverse("home"), reverse("settings_page"), reverse("login")):
            response = self.client.get(path)
            self.assertEqual(response["X-Frame-Options"], "DENY")
            self.assertEqual(response["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", response["Content-Security-Policy"])

    def test_technical_cleanup_keeps_recycle_bin_and_audit(self):
        now = timezone.now()
        self.shared.deleted=True; self.shared.save()
        Session.objects.create(session_key="expired-session",session_data="",expire_date=now-datetime.timedelta(days=2))
        LoginAttempt.objects.create(key="old",started_at=now-datetime.timedelta(days=2))
        event = AuditEvent.objects.create(actor=self.admin,actor_name="admin",action="test",details={})
        call_command("cleanup_technical",dry_run=True,verbosity=0)
        self.assertTrue(Session.objects.filter(session_key="expired-session").exists())
        call_command("cleanup_technical",verbosity=0)
        self.assertFalse(Session.objects.filter(session_key="expired-session").exists())
        self.assertTrue(Vault.objects.filter(pk=self.shared.pk,deleted=True).exists())
        self.assertTrue(AuditEvent.objects.filter(pk=event.pk).exists())
