from django.urls import path, include
from core.views.main import index, owner_dashboard  
from core.views.auth import RegisterView, LoginView,  Logout 
from core.views.settings import update_username, update_email, change_password,SettingsView
from core.views.groups import generate_link, join_group, GroupListView, GroupDeleteView, GroupDetailView, create_group
from core.views.media import upload_media, download_media, MediaListView, MediaDeleteView,download_file, generate_preview_link, preview_file
from django.contrib.auth import views as auth_views

# Authentication and password reset routes
auth_urls = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", Logout, name="logout"),

    # Password reset workflow
    path("reset-password/", auth_views.PasswordResetView.as_view(
        template_name="reset_password.html"), name="password_reset"),
    path("reset-password-sent/", auth_views.PasswordResetDoneView.as_view(
        template_name="reset_password_sent.html"), name="password_reset_done"),
    path("reset/<uidb64>/<token>/", auth_views.PasswordResetConfirmView.as_view(
        template_name="reset_password_confirm.html"), name="password_reset_confirm"),
    path("reset-password-complete/", auth_views.PasswordResetCompleteView.as_view(
        template_name="reset_password_complete.html"), name="password_reset_complete"),
]

# User settings management routes
settings_urls = [
    path("", SettingsView.as_view(), name="settings"),  # Main settings page
    path("update-username/", update_username, name="update_username"),  # AJAX or form-based
    path("update-email/", update_email, name="update_email"),
    path("password/", change_password, name="change_password"),  # Password change (authenticated user)
]

# Group management routes (create, list, delete, detail)
groups_urls = [
    path("groups/", GroupListView.as_view(), name="group_list"),
    path("create_group/", create_group, name="create_group"),
    path("groups/<int:pk>/", GroupDetailView.as_view(), name="group_files"),  # Show group files
    path("groups/delete/", GroupDeleteView.as_view(), name="group_delete"), # POST based
]

# Media management routes (upload, list, delete)
media_urls = [
    path("upload/", upload_media, name="upload_media"),
    path("media/", MediaListView.as_view(), name="media_list"),
    path("groups/delete/", GroupDeleteView.as_view(), name="group_delete"), # POST based
    path("media/delete/", MediaDeleteView.as_view(), name="media_delete"), 
]

# Top-level URL patterns
urlpatterns = [
    path("", index, name="index"),  # Homepage

    # Dashboard and nested subroutes
    path("dashboard/", include([
        path("", owner_dashboard, name="dashboard"),  # Dashboard homepage
        path("settings/", include(settings_urls)),     # Nested settings URLs
        path("", include(groups_urls)),                # Nested group management
        path("", include(media_urls)),                 # Nested media management
    ])),

    # Shared/External link-based file/group access
    path("group/generate_link/<int:pk>/", generate_link, name="generate_link"),  # Share group via link
    path("group/join/<str:token>/", join_group, name="join_group"),  # Join group via token

    # File preview & download via token (for sharing)
    path("media/download/<int:pk>/", download_media, name="download_media"),
    path("media/generate_preview/<int:pk>/", generate_preview_link, name="generate_preview"),
    path("media/preview/<str:token>/", preview_file, name="preview_file"),
    path("media/preview/<str:token>/download/", download_file, name="download_file"),
]

# Authentication routes added last
urlpatterns += auth_urls
