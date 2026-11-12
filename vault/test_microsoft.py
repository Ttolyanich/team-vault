import base64
import uuid
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from .models import MicrosoftConfig, AuditEvent
from .microsoft import microsoft_settings


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode(),
    ENTRA_TENANT_ID="", ENTRA_CLIENT_ID="", ENTRA_CLIENT_SECRET="")
class MicrosoftSettingsTests(TestCase):
    tenant = "11111111-2222-3333-4444-555555555555"
    client_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    secret = "Synthetic-client-secret-only-for-tests"

    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="admin", is_superuser=True, is_local_admin=True)
        self.member = get_user_model().objects.create_user(username="member")
        self.client.force_login(self.admin)

    def save_config(self, **changes):
        values = dict(enabled="on", tenant_id=self.tenant, client_id=self.client_id, client_secret=self.secret, revision=0)
        values.update(changes)
        return self.client.post(reverse("microsoft_config"), values)

    def test_panel_admin_only_and_csrf(self):
        self.assertContains(self.client.get(reverse("microsoft_config")), "/auth/microsoft/callback/")
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        self.assertEqual(strict.post(reverse("microsoft_config"), {}).status_code, 403)
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("microsoft_config")).status_code, 403)
        self.assertEqual(self.save_config().status_code, 403)
        self.assertEqual(self.client.post(reverse("microsoft_check")).status_code, 403)
        self.assertFalse(MicrosoftConfig.objects.exists())

    def test_encrypted_secret_preserved_and_never_rendered_or_audited(self):
        self.assertEqual(self.save_config().status_code, 302)
        stored = MicrosoftConfig.objects.get()
        self.assertNotIn(self.secret, str(stored.secret_payload))
        self.assertEqual(microsoft_settings(include_secret=True).client_secret, self.secret)
        self.assertEqual(microsoft_settings().client_secret, "")
        self.assertNotIn(self.secret, repr(microsoft_settings(include_secret=True)))
        self.assertNotContains(self.client.get(reverse("microsoft_config")), self.secret)
        self.assertEqual(self.save_config(client_secret="", revision=1).status_code, 302)
        self.assertEqual(microsoft_settings(include_secret=True).client_secret, self.secret)
        for event in AuditEvent.objects.all():
            self.assertNotIn(self.secret, str(event.details))

    def test_invalid_settings_not_saved_or_echoed(self):
        response = self.save_config(tenant_id="https://example.com/invalid")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["form"].errors)
        self.assertNotContains(response, self.secret)
        self.assertFalse(MicrosoftConfig.objects.exists())
        response = self.save_config(client_secret="")
        self.assertTrue(response.context["form"].errors)
        self.assertFalse(MicrosoftConfig.objects.exists())

    def test_disable_overrides_environment_and_local_admin_survives(self):
        with override_settings(ENTRA_TENANT_ID=self.tenant, ENTRA_CLIENT_ID=self.client_id, ENTRA_CLIENT_SECRET=self.secret):
            self.assertTrue(microsoft_settings().ready)
            self.assertEqual(self.save_config(enabled="", client_secret="").status_code, 302)
            self.assertFalse(microsoft_settings().ready)
            self.assertEqual(microsoft_settings().source, "database")
            self.assertEqual(self.client.get(reverse("sso_start")).status_code, 403)
            self.assertEqual(self.client.get(reverse("microsoft_config")).status_code, 200)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_change_client_requires_replacement_and_clear_requires_disable(self):
        self.save_config()
        response = self.save_config(client_secret="", client_id=str(uuid.uuid4()), revision=1)
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(microsoft_settings().client_id, self.client_id)
        response = self.save_config(client_secret="", clear_secret="on", revision=1)
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(self.save_config(enabled="", client_secret="", clear_secret="on", revision=1).status_code, 302)
        self.assertFalse(microsoft_settings().secret_set)

    def test_stale_revision_does_not_overwrite(self):
        self.save_config()
        response = self.save_config(client_secret="different-secret", revision=0)
        self.assertTrue(response.context["form"].non_field_errors())
        self.assertNotContains(response, "different-secret")
        self.assertEqual(microsoft_settings(include_secret=True).client_secret, self.secret)

    @patch("vault.views.requests.get")
    def test_discovery_check_validates_issuer_and_does_not_expose_secret(self, get):
        self.save_config()
        get.return_value.json.return_value = {"issuer": f"https://login.microsoftonline.com/{self.tenant}/v2.0"}
        response = self.client.post(reverse("microsoft_check"))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(self.secret, response.content.decode())
        get.assert_called_once_with(f"https://login.microsoftonline.com/{self.tenant}/v2.0/.well-known/openid-configuration", timeout=10, allow_redirects=False)
        get.return_value.json.return_value = {"issuer": "https://unexpected.example.com"}
        self.assertEqual(self.client.post(reverse("microsoft_check")).status_code, 400)

    @patch("vault.views.OAuth")
    def test_oauth_reads_saved_credentials(self, oauth):
        from .views import oauth_client
        self.save_config()
        oauth_client()
        kwargs = oauth.return_value.register.call_args.kwargs
        self.assertEqual(kwargs["client_id"], self.client_id)
        self.assertEqual(kwargs["client_secret"], self.secret)
        self.assertIn(self.tenant, kwargs["server_metadata_url"])
        self.assertEqual(kwargs["client_kwargs"]["code_challenge_method"], "S256")
