from django.urls import path
from .views import index, RegisterView, LoginView, DashboardView, Logout, SettingsView, upload_media, download_media, GroupDetailView,MediaListView, MediaView, GroupListView, GroupView, update_username, update_email, change_password, generate_preview_link, preview_file, download_file, create_group, generate_link, join_group
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
    path("dashboard/create_group", create_group, name="create_group"),
    
    path(
        "media/download/<int:pk>/",  # pk: Primary key of the media file
        download_media,
        name="download_media",
    ),
    path(
        "media/generate_preview/<int:pk>/",  # pk: Primary key of the media file
        generate_preview_link,
        name="generate_preview",
    ),
    path(
        "media/preview/<str:token>/",  # pk: Primary key of the media file
        preview_file,
        name="preview_file",
    ),
    path("media/preview/<str:token>/download/", download_file, name="download_file"),
    path("dashboard/files", MediaListView.as_view(), name="media_list"),
    path("dashboard/groups", GroupListView.as_view(), name="group_list"),
    path("dashboard/groups/<int:pk>", GroupDetailView.as_view(), name="group_files"),
    path("dashboard/groups/delete", view=GroupView.as_view(), name="group_delete"),
    path(
        "group/generate_link/<int:pk>/",  # pk: Primary key of the media file
        generate_link,
        name="generate_link",
    ),
    path(
        "group/join/<str:token>/",  # pk: Primary key of the media file
        join_group,
        name="join_group",
    ),
    path("dashboard/files/delete", view=MediaView.as_view(), name="media_delete"),
    path("settings", view=SettingsView.as_view(), name="settings"),
    path("update-username/", update_username, name="update_username"),
    path("update-email/", update_email, name="update_email"),
    path("settings/password/", change_password, name="change_password"),
]
