from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from django.views.decorators.http import require_http_methods
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.generic.base import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse



@login_required
def update_username(request):
    """
    Handle POST request to update the username of the logged-in user.

    Steps:
    - Validate the request is POST.
    - Get and strip the new username from POST data.
    - Check if username is empty -> return 400 error.
    - Check if username is already taken by another user -> return 200 with error message.
    - Update user's username and save.
    - Return a success message and JavaScript to update the username input value on the client side.
    - Return 405 Method Not Allowed for other HTTP methods.
    """
    if request.method == "POST":
        new_username = request.POST.get("username", "").strip()

        if not new_username:
            return HttpResponse(
                "<small class='text-red-500'>Username required</small>", status=400
            )

        if (
            User.objects.filter(username=new_username)
            .exclude(pk=request.user.pk)
            .exists()
        ):
            return HttpResponse(
                "<small class='text-red-500'>Username already taken</small>", status=200
            )

        request.user.username = new_username
        request.user.save()

        return HttpResponse(
            f"""
            <small class='text-green-500'>Username updated to {new_username}</small>
            <script>
                document.getElementById('id_username').value = '{new_username}';
            </script>
            """
        )

    return HttpResponse(status=405)  # Method Not Allowed


@login_required
def update_email(request):
    """
    Handle POST request to update the email address of the logged-in user.

    Steps:
    - Validate the request is POST.
    - Get and clean the new email from POST data.
    - Validate email format.
    - Check if email is already used by another user.
    - Update user's email and save.
    - Return success message and JavaScript to update email input value on client.
    - Return 405 for disallowed HTTP methods.
    """
    if request.method == "POST":
        new_email = request.POST.get("email", "").strip().lower()

        if not new_email:
            return HttpResponse(
                "<small class='text-red-500'>Email required</small>", status=400
            )

        try:
            validate_email(new_email)
        except ValidationError:
            return HttpResponse(
                "<small class='text-red-500'>Invalid email format</small>", status=200
            )

        if User.objects.filter(email=new_email).exclude(pk=request.user.pk).exists():
            return HttpResponse(
                "<small class='text-red-500'>Email already in use</small>", status=200
            )

        request.user.email = new_email
        request.user.save()

        return HttpResponse(
            f"""
            <small class='text-green-500'>Email updated to {new_email}</small>
            <script>
                document.getElementById('id_email').value = '{new_email}';
            </script>
            """
        )

    return HttpResponse(status=405)  # Method Not Allowed


@login_required
def change_password(request):
    """
    Handle the password change process for logged-in users.

    Workflow:
    - Accept POST requests with 'current_password' and 'new_password'.
    - Verify current password is correct.
    - Validate new password strength using Django's validators.
    - If validation passes, update password and keep user logged in.
    - Show success message and redirect to settings page.
    - On GET or validation failure, render the password change form with errors.
    """
    errors = {}
    if request.method == "POST":
        current = request.POST.get("current_password", "").strip()
        new = request.POST.get("new_password", "").strip()

        if not request.user.check_password(current):
            errors["current_password"] = "Incorrect current password."

        try:
            validate_password(new, user=request.user)
        except ValidationError as e:
            errors["new_password"] = "; ".join(e.messages)

        if not errors:
            request.user.set_password(new)
            request.user.save()
            update_session_auth_hash(request, request.user)  # Keeps user logged in
            messages.success(request, "Password changed successfully.")
            return redirect("settings")

    return render(request, "partials/change_password.html", {"errors": errors})


class SettingsView(LoginRequiredMixin, View):
    """
    Display the user settings page.

    Requires user authentication.
    Renders 'settings.html' with current user context.
    """

    def get(self, request):
        return render(request, "settings.html", {"user": request.user})
