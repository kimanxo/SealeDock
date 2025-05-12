from django.urls import path
from .views import index, RegisterView, LoginView, DashboardView, Logout, SettingsView, upload_media, download_media, MediaListView, MediaView, GroupListView, GroupView, update_username, update_email, change_password
from django.contrib.auth import views as auth_views


urlpatterns = [
    path("", view=index, name="index"),
    path("register", view=RegisterView.as_view(), name="register"),
    path("login", view=LoginView.as_view(), name="login"),
    path(
        "reset-password/",
        auth_views.PasswordResetView.as_view(template_name="reset_password.html"),
        name="password_reset",
    ),
    path(
        "reset-password-sent/",
        auth_views.PasswordResetDoneView.as_view(
            template_name="reset_password_sent.html"
        ),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="reset_password_confirm.html"
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset-password-complete/",
        auth_views.PasswordResetCompleteView.as_view(
            template_name="reset_password_complete.html"
        ),
        name="password_reset_complete",
    ),
    path("logout", view=Logout, name="logout"),
    path("dashboard", view=DashboardView.as_view(), name="dashboard"),
    path("dashboard/upload", upload_media, name="upload_media"),
    path(
        "media/download/<int:pk>/",  # pk: Primary key of the media file
        download_media,
        name="download_media",
    ),
    path("dashboard/files", MediaListView.as_view(), name="media_list"),
    path("dashboard/groups", GroupListView.as_view(), name="group_list"),
    path("dashboard/files/delete", view=MediaView.as_view(), name="media_delete"),
    path("dashboard/groups/delete", view=GroupView.as_view(), name="group_delete"),
    path("settings", view=SettingsView.as_view(), name="settings"),
    path("update-username/", update_username, name="update_username"),
    path("update-email/", update_email, name="update_email"),
    path("settings/password/", change_password, name="change_password"),
]
