"""AD password authentication. No user passwords are persisted or logged."""
import ssl
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
import ldap3
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from . import crypto
from .models import LdapConfig


class DirectoryError(Exception):
    pass


@dataclass(frozen=True)
class DirectoryIdentity:
    guid: uuid.UUID
    name: str
    email: str


def ldap_settings():
    return LdapConfig.objects.filter(pk=1).first() or LdapConfig(id=1)


@contextmanager
def bound_connection(config, user, password):
    if not user or not password or (config.transport == "plain" and not config.allow_plain):
        raise DirectoryError("Настройки подключения неполны.")
    connection = None
    try:
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_data=config.ca_certificate or None)
        server = ldap3.Server(config.host, port=config.port, use_ssl=config.transport == "ldaps",
            tls=tls, get_info=ldap3.NONE, connect_timeout=5)
        connection = ldap3.Connection(server, user=user, password=password, authentication=ldap3.SIMPLE,
            auto_referrals=False, read_only=True, receive_timeout=8, raise_exceptions=True,
            auto_range=False, auto_escape=True)
        connection.open(read_server_info=False)
        # Never fall back to plaintext when the TLS handshake fails.
        if config.transport == "starttls" and not connection.start_tls(read_server_info=False):
            raise DirectoryError("Не удалось установить защищённое подключение.")
        if not connection.bind(read_server_info=False):
            raise DirectoryError("Не удалось выполнить вход в каталог.")
        yield connection
    except (LDAPException, OSError, ValueError):
        # LDAP exceptions can contain directory details. Do not expose/log them.
        raise DirectoryError("Ошибка подключения или авторизации в каталоге.") from None
    finally:
        if connection:
            try:
                connection.unbind()
            except (LDAPException, OSError):
                pass


def service_password(config):
    if not config.bind_secret_payload:
        raise DirectoryError("Не сохранён пароль служебной учётной записи.")
    return crypto.unseal(config.bind_secret_payload, "integration:ldap:bind-password")


def check_directory(config):
    with bound_connection(config, config.bind_dn, service_password(config)) as connection:
        connection.search(config.base_dn, "(objectClass=*)", search_scope=ldap3.BASE,
            attributes=["distinguishedName"], size_limit=1, time_limit=5)
        if len([row for row in connection.response if row.get("type") == "searchResEntry"]) != 1:
            raise DirectoryError("Base DN не найден или недоступен служебной учётной записи.")
        if config.allowed_group_dn:
            connection.search(config.allowed_group_dn, "(objectClass=group)", search_scope=ldap3.BASE,
                attributes=["distinguishedName"], size_limit=1, time_limit=5)
            if len([row for row in connection.response if row.get("type") == "searchResEntry"]) != 1:
                raise DirectoryError("Разрешённая группа не найдена или недоступна.")


def authenticate_directory(config, username, password):
    if not config.ready or not username or not password:
        raise DirectoryError("Вход недоступен.")
    safe_name = escape_filter_chars(username)
    search_filter = ("(&(objectCategory=person)(objectClass=user)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        f"(|(sAMAccountName={safe_name})(userPrincipalName={safe_name}))")
    if config.allowed_group_dn:
        search_filter += f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(config.allowed_group_dn)})"
    search_filter += ")"
    with bound_connection(config, config.bind_dn, service_password(config)) as connection:
        connection.search(config.base_dn, search_filter, search_scope=ldap3.SUBTREE,
            attributes=["objectGUID", "displayName", "mail", "sAMAccountName"], size_limit=2, time_limit=5)
        matches = [row for row in connection.response if row.get("type") == "searchResEntry"]
        if len(matches) != 1:
            raise DirectoryError("Учётная запись не найдена или вход не разрешён.")
        row = matches[0]
        raw = {key.lower(): value for key, value in row.get("raw_attributes", {}).items()}
        try:
            guid = uuid.UUID(bytes_le=raw["objectguid"][0])
        except (KeyError, ValueError, IndexError, TypeError):
            raise DirectoryError("Не удалось получить идентификатор AD.") from None
        def text(name, fallback=""):
            values = raw.get(name, [])
            return values[0].decode("utf-8", errors="replace") if values else fallback
        identity = DirectoryIdentity(guid, text("displayname", text("samaccountname", username))[:200], text("mail")[:254])
        user_dn = row["dn"]
    # A fresh connection validates the actual user's password, never an anonymous bind.
    with bound_connection(config, user_dn, password):
        return identity
