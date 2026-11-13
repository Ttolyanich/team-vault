from django import forms
from .access import editable_vaults
from .models import Vault, Item, LdapConfig
from .widgets import search_field


class ItemForm(forms.Form):
    title = forms.CharField(label="Название", max_length=200)
    vault = forms.ModelChoiceField(label="Хранилище", queryset=Vault.objects.none())
    login = forms.CharField(label="Логин", max_length=500, required=False)
    password = forms.CharField(label="Пароль или токен", max_length=10000, required=False, widget=forms.PasswordInput(render_value=False))
    totp_key = forms.CharField(
        label="Секретный ключ аутентификатора (TOTP)",
        max_length=2048,
        required=False,
        widget=forms.PasswordInput(render_value=False, attrs={"placeholder": "Секретный ключ или ссылка otpauth://", "autocomplete": "off"}),
        help_text="Если для входа требуется двухфакторная аутентификация (2FA), укажите секрет или ссылку otpauth://."
    )
    url = forms.URLField(label="Адрес сервиса", required=False)
    note = forms.CharField(label="Рабочая заметка", max_length=20000, required=False, widget=forms.Textarea(attrs={"rows": 4}))
    tags = forms.CharField(label="Теги", max_length=250, required=False, help_text="Например: контент, площадки. Не указывайте здесь пароли.")

    def __init__(self, *args, user, show_totp=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["vault"].queryset = editable_vaults(user)
        included = self.initial.get("vault")
        search_field(self.fields["vault"], "vaults", "editable", extra={"include": included} if included else {})
        if not show_totp:
            self.fields.pop("totp_key", None)

    def clean_totp_key(self):
        val = self.cleaned_data.get("totp_key", "").strip()
        if not val:
            return None
        from .services import totp_data
        return totp_data(val)


class VaultForm(forms.Form):
    name = forms.CharField(label="Название хранилища", max_length=160)
    description = forms.CharField(label="Для чего оно нужно", max_length=500, required=False)


class TotpForm(forms.Form):
    configuration = forms.CharField(label="Строка настройки или секрет аутентификатора", max_length=2048, widget=forms.PasswordInput)
    confirmed = forms.BooleanField(label="Я проверил код в сервисе и подтверждаю подключение", required=True)


class RecoveryForm(forms.Form):
    codes = forms.CharField(label="Резервные коды — по одному на строку", max_length=10000, widget=forms.Textarea(attrs={"rows": 5}))

    def clean_codes(self):
        codes = [x.strip() for x in self.cleaned_data["codes"].splitlines() if x.strip()]
        if not 1 <= len(codes) <= 50 or any(len(x) > 200 for x in codes) or len(set(codes)) != len(codes):
            raise forms.ValidationError("Добавьте от 1 до 50 разных кодов, каждый длиной до 200 символов.")
        return codes


class MicrosoftForm(forms.Form):
    enabled = forms.BooleanField(label="Разрешить сотрудникам вход через Microsoft", required=False)
    tenant_id = forms.UUIDField(label="Directory Tenant ID", required=False, help_text="Идентификатор каталога из Entra → App registrations → Overview.")
    client_id = forms.UUIDField(label="Application Client ID", required=False, help_text="Идентификатор приложения. Object ID здесь не используется.")
    client_secret = forms.CharField(label="Client Secret — значение Value", required=False, strip=False, max_length=2048,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text="Пустое поле сохраняет действующий секрет. Сохранённое значение никогда не показывается.")
    clear_secret = forms.BooleanField(label="Удалить сохранённый секрет", required=False)
    revision = forms.IntegerField(widget=forms.HiddenInput, min_value=0)

    def __init__(self, *args, current, **kwargs):
        self.current = current
        super().__init__(*args, **kwargs)

    def clean(self):
        data = super().clean()
        changed = (str(data.get("tenant_id") or "") != self.current.tenant_id or str(data.get("client_id") or "") != self.current.client_id)
        if data.get("clear_secret") and data.get("client_secret"):
            self.add_error("client_secret", "Выберите одно действие: сохранить новый секрет или удалить прежний.")
        if changed and self.current.secret_set and not data.get("client_secret") and not data.get("clear_secret"):
            self.add_error("client_secret", "При смене приложения или каталога укажите новый секрет либо удалите прежний.")
        if data.get("enabled"):
            for name in ("tenant_id", "client_id"):
                if not data.get(name):
                    self.add_error(name, "Для включения входа заполните это поле.")
            if data.get("clear_secret") or not (data.get("client_secret") or self.current.secret_set):
                self.add_error("client_secret", "Для включения входа нужен секрет приложения.")
        return data


class LdapForm(forms.Form):
    enabled = forms.BooleanField(label="Разрешить вход через AD / LDAP", required=False)
    host = forms.CharField(label="Сервер каталога", max_length=253, required=False,
        help_text="DNS-имя контроллера или IP, без ldap:// и порта. Например dc01.company.local.")
    transport = forms.ChoiceField(label="Защита подключения", choices=LdapConfig.TRANSPORTS)
    port = forms.IntegerField(label="Порт", min_value=1, max_value=65535, initial=636,
        help_text="Обычно 636 для LDAPS, 389 для LDAP и StartTLS.")
    base_dn = forms.CharField(label="Base DN — область поиска сотрудников", max_length=1024, required=False,
        help_text="Например DC=company,DC=local или OU=Employees,DC=company,DC=local.")
    bind_dn = forms.CharField(label="Служебная учётная запись", max_length=1024, required=False,
        help_text="UPN (svc-vault@company.local) или полный DN. Достаточно права чтения каталога.")
    bind_password = forms.CharField(label="Пароль служебной учётной записи", max_length=2048, strip=False, required=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}),
        help_text="Пустое поле сохраняет прежний пароль. Сохранённое значение не показывается.")
    clear_password = forms.BooleanField(label="Удалить сохранённый пароль", required=False)
    allowed_group_dn = forms.CharField(label="Разрешённая группа AD — полный DN", max_length=1024, required=False,
        help_text="Например CN=Vault Users,OU=Groups,DC=company,DC=local. Учитываются вложенные группы. Пустое поле разрешает вход всем сотрудникам в Base DN.")
    ca_certificate = forms.CharField(label="Сертификат CA в формате PEM", max_length=65536, required=False,
        widget=forms.Textarea(attrs={"rows": 5}),
        help_text="Для внутреннего центра сертификации вставьте публичную цепочку CA без закрытого ключа. Пустое поле использует доверенные CA контейнера. Проверка сертификата обязательна для TLS.")
    allow_plain = forms.BooleanField(label="Разрешаю LDAP без шифрования: пароли будут передаваться по сети открытым текстом", required=False)
    revision = forms.IntegerField(widget=forms.HiddenInput, min_value=0)

    def __init__(self, *args, current, **kwargs):
        self.current = current
        super().__init__(*args, **kwargs)

    def clean_host(self):
        import ipaddress
        import re
        host = self.cleaned_data["host"]
        if not host:
            return host
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?", host) or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
                raise forms.ValidationError("Введите DNS-имя или IP без протокола, пути и порта.")
        return host.lower()

    def clean_ca_certificate(self):
        from cryptography import x509
        value = self.cleaned_data["ca_certificate"]
        if value:
            try:
                if "PRIVATE KEY" in value or not x509.load_pem_x509_certificates(value.encode("ascii")):
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise forms.ValidationError("Нужен публичный сертификат CA в PEM, без закрытого ключа.") from None
        return value

    def clean(self):
        data = super().clean()
        if data.get("bind_password") and data.get("clear_password"):
            self.add_error("bind_password", "Выберите замену пароля или его удаление.")
        changed = any(str(data.get(key) or "") != str(getattr(self.current, key) or "") for key in ("host", "base_dn", "bind_dn"))
        if changed and self.current.bind_secret_payload and not (data.get("bind_password") or data.get("clear_password")):
            self.add_error("bind_password", "При смене сервера, Base DN или служебной учётной записи укажите пароль заново либо удалите прежний.")
        if data.get("transport") == "plain" and not data.get("allow_plain"):
            self.add_error("allow_plain", "Для обычного LDAP требуется явное разрешение передачи паролей без шифрования.")
        if data.get("enabled"):
            for key in ("host", "base_dn", "bind_dn"):
                if not data.get(key):
                    self.add_error(key, "Заполните поле для включения входа.")
            if data.get("clear_password") or not (data.get("bind_password") or self.current.bind_secret_payload):
                self.add_error("bind_password", "Для включения входа нужен пароль служебной учётной записи.")
        return data


class LdapLoginForm(forms.Form):
    username = forms.CharField(label="Доменный логин", max_length=254,
        widget=forms.TextInput(attrs={"autocomplete": "username", "placeholder": "user или user@company.local"}))
    password = forms.CharField(label="Доменный пароль", max_length=2048, strip=False,
        widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "current-password"}))
