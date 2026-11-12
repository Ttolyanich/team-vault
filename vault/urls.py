from django.urls import path
from . import views
from . import views_ldap
from . import views_team
from . import views_trash
from . import views_workspace, views_choices
from . import views_transfers

urlpatterns = [
    path("health/", views.health, name="health"), path("login/", views.sign_in, name="login"), path("logout/", views.sign_out, name="logout"),
    path("auth/microsoft/", views.sso_start, name="sso_start"), path("auth/microsoft/callback/", views.sso_callback, name="sso_callback"),
    path("", views.home, name="home"), path("vaults/new/", views.vault_new, name="vault_new"), path("vaults/<uuid:vault_id>/members/", views.vault_members, name="members"),
    path("items/new/", views.item_edit, name="item_new"), path("items/<uuid:item_id>/", views.item_detail, name="item"), path("items/<uuid:item_id>/edit/", views.item_edit, name="item_edit"),
    path("items/<uuid:item_id>/move/", views_transfers.transfer, {"operation":"move"}, name="item_move"),
    path("items/<uuid:item_id>/copy/", views_transfers.transfer, {"operation":"copy"}, name="item_copy"),
    path("items/<uuid:item_id>/reveal/", views.reveal, name="reveal"), path("items/<uuid:item_id>/totp/setup/", views.totp_setup, name="totp_setup"), path("items/<uuid:item_id>/totp/", views.totp_issue, name="totp_issue"),
    path("items/<uuid:item_id>/recovery/", views.recovery_replace, name="recovery_replace"), path("items/<uuid:item_id>/recovery/<uuid:code_id>/", views.recovery_action, name="recovery_action"),
    path("users/", views.users, name="users"), path("activity/", views.activity, name="activity"),
    path("team/", views_team.team, name="team"),
    path("choices/", views_choices.choices, name="choices"),
    path("settings/", views_workspace.settings_page, name="settings_page"),
    path("oversight/people/", views_workspace.staff_directory, name="staff_directory"),
    path("oversight/vaults/", views_workspace.all_vaults, name="all_vaults"),
    path("team/people/<int:user_id>/secrets/", views_workspace.staff_secrets, name="staff_secrets"),
    path("vaults/<uuid:vault_id>/open/", views_workspace.vault_open, name="vault_open"),
    path("items/<uuid:item_id>/delete/", views_trash.item_delete, name="item_delete"),
    path("vaults/<uuid:vault_id>/delete/", views_trash.vault_delete, name="vault_delete"),
    path("trash/", views_trash.trash, name="trash"),
    path("trash/items/<uuid:item_id>/", views_trash.trash_item, name="trash_item"),
    path("trash/items/<uuid:item_id>/reveal/", views_trash.trash_reveal, name="trash_reveal"),
    path("trash/items/<uuid:item_id>/restore/", views_trash.item_restore, name="item_restore"),
    path("trash/vaults/<uuid:vault_id>/restore/", views_trash.vault_restore, name="vault_restore"),
    path("settings/microsoft/", views.microsoft_config, name="microsoft_config"),
    path("settings/microsoft/check/", views.microsoft_check, name="microsoft_check"),
    path("settings/ldap/", views_ldap.ldap_config, name="ldap_config"),
    path("settings/ldap/check/", views_ldap.ldap_check, name="ldap_check"),
    path("auth/ldap/", views_ldap.ldap_login, name="ldap_login"),
]
