from django.conf import settings
from .microsoft import microsoft_settings
from .ldap_directory import ldap_settings
from .forms import LdapLoginForm
from .access import manages_team


def common(request):
    route = request.resolver_match.url_name if request.resolver_match else None
    nav_section = {
        "activity": "activity", "users": "team", "team": "team", "vault_new": "team", "members": "team",
        "microsoft_config": "settings", "ldap_config": "settings", "settings_page": "settings",
        "staff_directory": "staff_directory", "all_vaults": "all_vaults", "staff_secrets": "staff_directory", "vault_open": "shared",
        "trash": "trash", "trash_item": "trash",
    }.get(route, "")
    if route == "home" or route in ("item", "item_edit", "item_new", "item_version", "item_move", "item_copy"):
        nav_section = "personal" if request.GET.get("section") == "personal" else "shared"
    is_admin_nav = nav_section in {"activity", "team", "settings", "staff_directory", "all_vaults", "trash"}
    return {
        "app_name": settings.APP_NAME,
        "entra_ready": microsoft_settings().ready,
        "ldap_ready": ldap_settings().ready,
        "ldap_login_form": LdapLoginForm(),
        "nav_section": nav_section,
        "is_admin_nav": is_admin_nav,
        "can_manage_team": request.user.is_authenticated and manages_team(request.user),
    }
