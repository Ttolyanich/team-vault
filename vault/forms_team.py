from django import forms
from .models import Department, User, Vault
from .widgets import SearchSelect, search_field


class DepartmentForm(forms.ModelForm):
    revision = forms.IntegerField(widget=forms.HiddenInput, min_value=0, initial=0)

    class Meta:
        model = Department
        fields = ["name", "head"]
        labels = {"name": "Название подразделения", "head": "Руководитель"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["head"].queryset = User.objects.filter(is_active=True).order_by("display_name", "username")
        self.fields["head"].empty_label = "Пока не назначен"
        search_field(self.fields["head"], "people", "head")
        self.initial["revision"] = self.instance.revision


class TeamUserForm(forms.Form):
    department = forms.ModelChoiceField(label="Подразделение", queryset=Department.objects.order_by("name"), required=False, empty_label="Без подразделения", widget=SearchSelect("departments", "managed"))
    is_active = forms.BooleanField(label="Вход разрешён", required=False)
    is_superuser = forms.BooleanField(label="Администратор приложения", required=False)
    revision = forms.IntegerField(widget=forms.HiddenInput, min_value=0)


class CreateLocalUserForm(forms.Form):
    username = forms.CharField(
        label="Логин (username)",
        max_length=150,
        help_text="Только латинские буквы, цифры и символы @/./+/-/_",
        widget=forms.TextInput(attrs={"autocomplete": "off"})
    )
    display_name = forms.CharField(
        label="ФИО или отображаемое имя",
        max_length=200,
        widget=forms.TextInput(attrs={"autocomplete": "off"})
    )
    email = forms.EmailField(label="Рабочая почта", required=False)
    password = forms.CharField(
        label="Пароль",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Минимум 16 символов по политике безопасности."
    )
    password_confirm = forms.CharField(
        label="Подтверждение пароля",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"})
    )
    department = forms.ModelChoiceField(
        label="Подразделение",
        queryset=Department.objects.order_by("name"),
        required=False,
        empty_label="Без подразделения",
        widget=SearchSelect("departments", "managed")
    )
    is_superuser = forms.BooleanField(label="Администратор приложения", required=False)

    def clean_username(self):
        username = self.cleaned_data["username"].strip()
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("Пользователь с таким логином уже существует.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm = cleaned_data.get("password_confirm")
        if password and confirm and password != confirm:
            self.add_error("password_confirm", "Пароли не совпадают.")
        if password:
            from django.contrib.auth.password_validation import validate_password
            try:
                validate_password(password)
            except forms.ValidationError as e:
                self.add_error("password", e)
        return cleaned_data


class ResetPasswordForm(forms.Form):
    new_password = forms.CharField(
        label="Новый пароль",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text="Минимум 16 символов."
    )
    new_password_confirm = forms.CharField(
        label="Подтверждение нового пароля",
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"})
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("new_password")
        confirm = cleaned_data.get("new_password_confirm")
        if password and confirm and password != confirm:
            self.add_error("new_password_confirm", "Пароли не совпадают.")
        if password:
            from django.contrib.auth.password_validation import validate_password
            try:
                validate_password(password)
            except forms.ValidationError as e:
                self.add_error("new_password", e)
        return cleaned_data


class TeamVaultForm(forms.ModelForm):
    revision = forms.IntegerField(widget=forms.HiddenInput, min_value=0, initial=0)

    class Meta:
        model = Vault
        fields = ["name", "description", "department", "access_mode", "department_role", "department_totp"]
        labels = {"name": "Название хранилища", "description": "Для чего оно нужно", "department": "Подразделение",
            "access_mode": "Кому доступно", "department_role": "Права для сотрудников подразделения", "department_totp": "Разрешить сотрудникам подразделения получать TOTP"}
        help_texts = {"access_mode": "«Все сотрудники» — одинаковые права для подразделения и автоматический доступ новичкам. Для разных прав используйте «Выбранные сотрудники».",
            "department_role": "Эти права и разрешение TOTP действуют в режиме «Все сотрудники подразделения»."}

    def __init__(self, *args, actor, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["department"].queryset = Department.objects.order_by("name") if actor.is_superuser else actor.headed_departments.order_by("name")
        search_field(self.fields["department"], "departments", "managed")
        self.fields["department"].required = not bool(self.instance.pk and not self.instance._state.adding and not self.instance.department_id)
        if not actor.is_superuser and not self.instance._state.adding:
            self.fields["department"].disabled = True
        self.initial["revision"] = self.instance.access_revision

    def clean(self):
        data = super().clean()
        if data.get("access_mode") == "department" and not data.get("department"):
            self.add_error("department", "Для общего доступа выберите подразделение.")
        return data
