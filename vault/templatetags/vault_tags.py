from django import template
register = template.Library()

LABELS = {"workspace.reviewed": "Открыто рабочее пространство сотрудника", "auth.sessions_revoked": "Завершены сессии сотрудника", "auth.local_login": "Вход локального администратора", "auth.microsoft_login": "Вход через Microsoft", "auth.login_denied": "Отказ во входе",
    "auth.microsoft_denied": "Отказ входа Microsoft", "auth.logout": "Выход", "admin.bootstrap": "Подготовка локального администратора",
    "vault.created": "Создано хранилище", "vault.membership_changed": "Изменён доступ к хранилищу", "item.saved": "Сохранена запись",
    "item.moved": "Запись перемещена между хранилищами", "item.copied": "Создана общая копия личной записи",
    "item.revealed": "Получено значение записи", "item.opened": "Открыта карточка записи", "item.edit_opened": "Открыто изменение записи", "totp.requested": "Запрошен код подтверждения",
    "totp.configured": "Настроены коды подтверждения", "totp.rate_limited": "Превышен лимит запросов кода", "recovery.replaced": "Заменены резервные коды",
    "recovery.revealed": "Просмотрен резервный код", "recovery.marked_used": "Резервный код отмечен использованным", "recovery.manager_assigned": "Назначен руководитель восстановления",
    "department.saved": "Изменено подразделение", "vault.policy_changed": "Изменён доступ к хранилищу",
    "item.trashed": "Секрет перемещён в корзину", "vault.trashed": "Хранилище перемещено в корзину",
    "item.restored": "Секрет восстановлен", "vault.restored": "Хранилище восстановлено",
    "trash.item_viewed": "Просмотрена запись в корзине", "trash.item_revealed": "Получено значение из корзины",
    "user.permissions_changed": "Изменены полномочия сотрудника", "access.denied": "Отказ доступа", "access.recovery_denied": "Отказ доступа к резервным кодам",
    "access.totp_denied": "Отказ выдачи кода", "access.totp_setup_denied": "Отказ изменения 2FA",
    "microsoft.settings_saved": "Изменены настройки Microsoft 365", "microsoft.connection_checked": "Проверено подключение Microsoft 365",
    "ldap.settings_saved": "Изменены настройки AD / LDAP", "ldap.connection_checked": "Проверено подключение AD / LDAP",
    "auth.ldap_login": "Вход через AD", "auth.ldap_denied": "Отказ входа AD", "auth.ldap_rate_limited": "Превышен лимит попыток входа AD"}


@register.filter
def action_label(value):
    return LABELS.get(value, value)
