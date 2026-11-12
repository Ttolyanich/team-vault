import base64
import ssl
import uuid
from unittest.mock import MagicMock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
from . import crypto
from .models import LdapConfig, AuditEvent, Vault
from .ldap_directory import DirectoryError, DirectoryIdentity, authenticate_directory, bound_connection


@override_settings(VAULT_MASTER_KEY=base64.urlsafe_b64encode(b"k" * 32).decode())
class LdapTests(TestCase):
    password = "Synthetic-service-password-2026"
    user_password = "Synthetic-domain-password-2026"

    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_user(username="admin", is_superuser=True, is_local_admin=True)
        self.member = User.objects.create_user(username="member", email="user@example.com", entra_tenant="tenant", entra_oid="oid")
        self.client.force_login(self.admin)
        self.identity = DirectoryIdentity(uuid.uuid4(), "Сотрудник AD", "user@example.com")

    def values(self, **changes):
        data = dict(enabled="on", host="dc01.example.com", port=636, transport="ldaps",
            base_dn="DC=example,DC=com", bind_dn="svc@example.com", bind_password=self.password,
            allowed_group_dn="", ca_certificate="", revision=0)
        data.update(changes)
        return data

    def save_config(self, **changes):
        return self.client.post(reverse("ldap_config"), self.values(**changes))

    def domain_login(self, **changes):
        data = dict(username="user", password=self.user_password)
        data.update(changes)
        return self.client.post(reverse("ldap_login"), data)

    def test_settings_are_admin_only_and_csrf_protected(self):
        self.assertContains(self.client.get(reverse("ldap_config")), "Base DN")
        strict = Client(enforce_csrf_checks=True)
        strict.force_login(self.admin)
        self.assertEqual(strict.post(reverse("ldap_config"), self.values()).status_code, 403)
        self.assertEqual(strict.post(reverse("ldap_check")).status_code, 403)
        self.assertEqual(strict.post(reverse("ldap_login"), {}).status_code, 403)
        self.client.force_login(self.member)
        self.assertEqual(self.client.get(reverse("ldap_config")).status_code, 403)
        self.assertEqual(self.save_config().status_code, 403)
        self.assertEqual(self.client.post(reverse("ldap_check")).status_code, 403)
        self.assertFalse(LdapConfig.objects.exists())

    def test_password_encrypted_hidden_preserved_and_audited_without_values(self):
        self.assertEqual(self.save_config().status_code, 302)
        config = LdapConfig.objects.get()
        self.assertNotIn(self.password, str(config.bind_secret_payload))
        self.assertEqual(crypto.unseal(config.bind_secret_payload, "integration:ldap:bind-password"), self.password)
        self.assertNotContains(self.client.get(reverse("ldap_config")), self.password)
        self.assertEqual(self.save_config(bind_password="", revision=1).status_code, 302)
        self.assertEqual(LdapConfig.objects.get().bind_secret_payload, config.bind_secret_payload)
        self.assertNotIn(self.password, str(list(AuditEvent.objects.values_list("details", flat=True))))

    def test_plain_requires_explicit_consent_and_no_invalid_host_or_ca(self):
        for changes in [dict(transport="plain", port=389), dict(host="ldap://dc01.example.com"), dict(host="dc01.example.com/path"), dict(ca_certificate="not-a-certificate"), dict(bind_password="")]:
            response = self.save_config(**changes)
            self.assertTrue(response.context["form"].errors)
            self.assertNotContains(response, self.password)
            self.assertFalse(LdapConfig.objects.exists())
        self.assertEqual(self.save_config(transport="plain", port=389, allow_plain="on").status_code, 302)
        self.assertTrue(LdapConfig.objects.get().ready)

    def test_stale_and_changed_target_do_not_reuse_password(self):
        self.save_config()
        response = self.save_config(bind_password="replacement", revision=0)
        self.assertTrue(response.context["form"].non_field_errors())
        for changes in [dict(host="other.example.com"), dict(bind_dn="other@example.com"), dict(base_dn="DC=other")]:
            response = self.save_config(bind_password="", revision=1, **changes)
            self.assertTrue(response.context["form"].errors)
        self.assertEqual(LdapConfig.objects.get().host, "dc01.example.com")

    def test_clear_requires_disable(self):
        self.save_config()
        self.assertTrue(self.save_config(bind_password="", clear_password="on", revision=1).context["form"].errors)
        self.assertEqual(self.save_config(enabled="", bind_password="", clear_password="on", revision=1).status_code, 302)
        self.assertFalse(LdapConfig.objects.get().ready)
        self.assertIsNone(LdapConfig.objects.get().bind_secret_payload)

    @patch("vault.views_ldap.check_directory")
    def test_connection_check_and_failures_are_audited(self, check):
        self.save_config(enabled="")
        self.assertEqual(self.client.post(reverse("ldap_check")).status_code, 200)
        check.assert_called_once()
        check.side_effect = DirectoryError("Недоступен каталог.")
        self.assertEqual(self.client.post(reverse("ldap_check")).status_code, 400)
        self.assertEqual(list(AuditEvent.objects.filter(action="ldap.connection_checked").order_by("created_at").values_list("details__success", flat=True)), [True, False])

    @patch("vault.views_ldap.authenticate_directory")
    def test_domain_login_creates_separate_identity_and_preserves_sessions(self, authenticate):
        self.save_config()
        self.client.logout()
        authenticate.return_value = self.identity
        self.assertEqual(self.domain_login().status_code, 302)
        user = get_user_model().objects.get(ad_object_guid=self.identity.guid)
        self.assertNotEqual(user.pk, self.member.pk)
        self.assertFalse(user.is_superuser or user.is_manager or user.has_usable_password())
        self.assertTrue(Vault.objects.filter(personal_owner=user).exists())
        password_hash = user.password
        self.assertTrue(AuditEvent.objects.filter(action="auth.ldap_login", actor=user).exists())
        self.client.logout()
        self.assertEqual(self.domain_login(username="renamed-user@example.com").status_code, 302)
        user.refresh_from_db()
        self.assertEqual(user.password, password_hash)
        self.assertEqual(get_user_model().objects.filter(ad_object_guid=self.identity.guid).count(), 1)

    @patch("vault.views_ldap.authenticate_directory")
    def test_locally_disabled_domain_user_is_not_reactivated(self, authenticate):
        user = get_user_model().objects.create_user(username="blocked", ad_object_guid=self.identity.guid, is_active=False)
        authenticate.return_value = self.identity
        self.client.logout()
        self.assertEqual(self.domain_login().status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)
        user.refresh_from_db()
        self.assertFalse(user.is_active)

    @patch("vault.views_ldap.authenticate_directory")
    def test_domain_login_preserves_assigned_admin_role(self, authenticate):
        user = get_user_model().objects.create_user(username="domain-admin", ad_object_guid=self.identity.guid, is_superuser=True)
        authenticate.return_value = self.identity
        self.client.logout()
        self.assertEqual(self.domain_login().status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.is_superuser)
        self.assertEqual(self.client.get(reverse("activity")).status_code, 200)

    @patch("vault.views_ldap.authenticate_directory", side_effect=DirectoryError("Invalid credentials"))
    def test_failed_login_hides_password_and_rate_limits(self, authenticate):
        self.save_config()
        self.client.logout()
        for _ in range(10):
            response = self.domain_login()
            self.assertEqual(response.status_code, 400)
            self.assertNotContains(response, self.user_password, status_code=400)
        self.assertEqual(self.domain_login().status_code, 429)
        self.assertEqual(authenticate.call_count, 10)
        self.assertEqual(AuditEvent.objects.filter(action="auth.ldap_denied").count(), 10)
        self.assertNotIn(self.user_password, str(list(AuditEvent.objects.values_list("details", flat=True))))

    @patch("vault.ldap_directory.ldap3.Connection")
    def test_starttls_failure_never_sends_bind_and_certificate_validation_is_on(self, connection):
        config = LdapConfig(host="dc.example.com", transport="starttls", port=389)
        connection.return_value.start_tls.return_value = False
        with self.assertRaises(DirectoryError):
            with bound_connection(config, "user", "password"):
                pass
        connection.return_value.bind.assert_not_called()
        server = connection.call_args.args[0]
        self.assertEqual(server.tls.validate, ssl.CERT_REQUIRED)
        self.assertFalse(connection.call_args.kwargs["auto_referrals"])

    @patch("vault.ldap_directory.ldap3.Connection")
    def test_plain_requires_consent_even_if_database_tampered(self, connection):
        with self.assertRaises(DirectoryError):
            with bound_connection(LdapConfig(transport="plain", allow_plain=False), "user", "password"):
                pass
        connection.assert_not_called()

    @patch("vault.ldap_directory.ldap3.Connection")
    def test_directory_search_escapes_input_checks_group_and_binds_user(self, connection):
        self.save_config(allowed_group_dn="CN=Vault Users,DC=example,DC=com")
        service, person = MagicMock(), MagicMock()
        connection.side_effect = [service, person]
        service.response = [{"type": "searchResEntry", "dn": "CN=User,DC=example,DC=com", "raw_attributes": {
            "objectGUID": [self.identity.guid.bytes_le], "displayName": ["Сотрудник".encode()], "mail": [b"user@example.com"]}}]
        result = authenticate_directory(LdapConfig.objects.get(), "*)(sAMAccountName=*)", self.user_password)
        self.assertEqual(result.guid, self.identity.guid)
        search_filter = service.search.call_args.args[1]
        self.assertIn(r"\2a\29\28sAMAccountName=\2a\29", search_filter)
        self.assertIn("memberOf:1.2.840.113556.1.4.1941:=", search_filter)
        self.assertIn("userAccountControl:1.2.840.113556.1.4.803:=2", search_filter)
        self.assertEqual(connection.call_args_list[1].kwargs["user"], "CN=User,DC=example,DC=com")
        self.assertEqual(connection.call_args_list[1].kwargs["password"], self.user_password)

    @patch("vault.ldap_directory.ldap3.Connection")
    def test_missing_ambiguous_or_invalid_guid_does_not_bind_as_user(self, connection):
        self.save_config()
        for rows in ([], [{"type": "searchResEntry"}, {"type": "searchResEntry"}], [{"type": "searchResEntry", "raw_attributes": {"objectGUID": [b"bad"]}}]):
            connection.reset_mock()
            connection.return_value.response = rows
            with self.assertRaises(DirectoryError):
                authenticate_directory(LdapConfig.objects.get(), "user", self.user_password)
            self.assertEqual(connection.call_count, 1)

    @patch("vault.ldap_directory.ldap3.Connection")
    def test_ldap_errors_are_sanitized(self, connection):
        connection.return_value.bind.side_effect = LDAPInvalidCredentialsResult(message=self.password)
        with self.assertRaises(DirectoryError) as caught:
            with bound_connection(LdapConfig(host="dc.example.com"), "user", "password"):
                pass
        self.assertNotIn(self.password, str(caught.exception))

    def test_ldap_disabled_rejects_login_without_network(self):
        self.client.logout()
        self.assertEqual(self.domain_login().status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_real_tls_rejects_untrusted_certificate_and_wrong_hostname_before_bind(self):
        import datetime
        import socket
        import tempfile
        import threading
        from pathlib import Path
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM)
        with tempfile.TemporaryDirectory() as directory:
            certfile, keyfile = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            certfile.write_bytes(pem)
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(certfile, keyfile)
            for ca in ("", pem.decode()):
                with self.subTest(trusted_ca=bool(ca)), socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(1)
                    listener.settimeout(5)
                    received = []
                    def serve():
                        try:
                            raw, _ = listener.accept()
                            with raw:
                                raw.settimeout(5)
                                with server_tls.wrap_socket(raw, server_side=True) as secured:
                                    received.append(secured.recv(4096))
                        except (ssl.SSLError, OSError):
                            pass
                    thread = threading.Thread(target=serve, daemon=True)
                    thread.start()
                    config = LdapConfig(host="127.0.0.1", port=listener.getsockname()[1], transport="ldaps", ca_certificate=ca)
                    with self.assertRaises(DirectoryError):
                        with bound_connection(config, "user", self.user_password):
                            self.fail("TLS incorrectly accepted the certificate")
                    thread.join(timeout=6)
                    self.assertFalse(thread.is_alive())
                    self.assertFalse(any(received), "Credentials reached the server before its certificate was verified")
