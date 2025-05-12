from django.views.generic.base import View
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth.password_validation import validate_password
from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from .forms import MediaUploadForm
from .models import Media, Group, Member
from django.views.generic import ListView
from django.utils import timezone
from django.contrib import messages
from django.core.validators import validate_email
from django.contrib.auth import update_session_auth_hash




@require_http_methods(["GET"])
def index(request):

    if request.user.is_authenticated:
        return redirect("/dashboard")
    return render(request, "index.html")


class RegisterView(View):

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, "register.html")

    def post(self, request):
        if request.htmx and request.headers.get("Hx-Trigger-Name") == "username":
            username = request.POST.get("username", "").strip()
            if not username:
                return HttpResponse(
                    "<small id='username_availability' class='py-2 text-red-500'>Username required</small>"
                )
            elif User.objects.filter(username=username).exists():
                return HttpResponse(
                    "<small id='username_availability' class='py-2 text-red-500'>Username already taken</small>"
                )
            else:
                return HttpResponse(
                    "<small id='username_availability' class='py-2 text-green-500'>Username available</small>"
                )

        elif request.htmx and request.headers.get("Hx-Trigger-Name") == "email":
            email = request.POST.get("email", "").strip()
            validator = EmailValidator()
            try:
                validator(email)
                if User.objects.filter(email=email).exists():
                    return HttpResponse(
                        "<small id='email_availability' class='py-2 text-red-500'>Email already taken</small>"
                    )
                return HttpResponse(
                    "<small id='email_availability' class='py-2 text-green-500'>Email available</small>"
                )
            except ValidationError:
                return HttpResponse(
                    "<small id='email_availability' class='py-2 text-red-500'>Invalid email format</small>"
                )

        else:
            # Regular POST
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            password = request.POST.get("password", "")
            confirm_password = request.POST.get("confirm_password", "")

            errors = []

            # Email validation
            try:
                EmailValidator()(email)
            except ValidationError:
                errors.append("Invalid email format.")

            if not username or not email or not password or not confirm_password:
                errors.append("All fields are required.")

            if User.objects.filter(username=username).exists():
                errors.append("Username is already taken.")

            if User.objects.filter(email=email).exists():
                errors.append("Email is already taken.")

            if password != confirm_password:
                errors.append("Passwords do not match.")

            try:
                validate_password(password)
            except ValidationError as e:
                errors.extend(e.messages)

            if errors:
                return render(request, "register.html", {"errors": errors})

            User.objects.create_user(username=username, email=email, password=password)
            messages.success(
                request, "Account created successfully. You may now log in."
            )
            return redirect("/login")


@login_required
@require_http_methods(["POST"])
def Logout(request):

    logout(request)
    if request.htmx:
            response = HttpResponse()
            response["HX-Redirect"] = "/"
            return response

    return redirect("/")


class LoginView(View):

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return render(request, "login.html")

    def post(self, request):
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        errors = []

        if not username or not password:
            errors.append("Username and password are required.")
        else:
            user = authenticate(request, username=username, password=password)
            if user is None:
                errors.append("Invalid username or password.")

        if errors:
            response = render(request, "partials/login_errors.html", {"errors": errors})
            if request.htmx:
                response["HX-Retarget"] = ".login-errors"
                response["HX-Reswap"] = "innerHTML"
            return response

        login(request, user)

        if request.htmx:
            response = HttpResponse()
            response["HX-Redirect"] = "/"
            return response

        return redirect("/")


class DashboardView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, "dashboard.html", {"user": request.user})


class SettingsView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, "settings.html", {"user": request.user})


@login_required
def upload_media(request):
    if request.method == "POST":
        form = MediaUploadForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            media = form.save(commit=False)
            media.owner = request.user
            media.save()
            form.save_m2m()  # For groups many-to-many
            return redirect("media_list")  # Create this page or redirect elsewhere
    else:
        form = MediaUploadForm(user=request.user)
    return render(request, "partials/upload.html", {"form": form})


class MediaListView(LoginRequiredMixin, ListView):
    model = Media
    template_name = "files.html"
    context_object_name = "media_list"

    def get_queryset(self):
        return Media.objects.filter(owner=self.request.user)


class MediaView(LoginRequiredMixin, View):

    def post(self, request):
        media = Media.objects.get(pk=request.POST.get("pk"))
        if not media:
            response = HttpResponse("Media not found", status=404)
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response
        if media.owner != request.user:
            response =  HttpResponse("You do not have permission to delete this media", status=403)
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response
        media.delete()        
        response =  render(
            request,
            "partials/files_rows.html",
            {"media_list": Media.objects.filter(owner=self.request.user)},
        )
        response["HX-Retarget"] = ".tbody"
        response["HX-Reswap"] = "outerHTML"
        return response


class GroupListView(LoginRequiredMixin, ListView):
    model = Group
    template_name = "groups.html"
    context_object_name = "group_list"

    def get_queryset(self):
        return Group.objects.all().filter(
            members__user=self.request.user
        ).distinct()


class GroupView(LoginRequiredMixin, View):

    def post(self, request):
        group = Group.objects.get(pk=request.POST.get("pk"))
        if not group:
            response = HttpResponse("Group not found", status=404)
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response
        if group.owner != request.user:
            response = HttpResponse(
                "You do not have permission to delete this group", status=403
            )
            response["HX-Retarget"] = "#errors"
            response["HX-Reswap"] = "innerHTML"
            return response
        group.delete()
        response = render(
            request,
            "partials/files_rows.html",
            {"group_list": Group.objects.filter(members__user=self.request.user)},
        )
        response["HX-Retarget"] = ".tbody"
        response["HX-Reswap"] = "outerHTML"
        return response





@login_required
def update_username(request):
    if request.method == "POST":
        new_username = request.POST.get("username", "").strip()

        if not new_username:
            return HttpResponse(
                "<small class='text-red-500'>Username required</small>", status=400
            )

        # Check if username exists (excluding current user)
        if (
            User.objects.filter(username=new_username)
            .exclude(pk=request.user.pk)
            .exists()
        ):
            return HttpResponse(
                "<small class='text-red-500'>Username already taken</small>", status=200
            )

        # Update username if available
        request.user.username = new_username
        request.user.save()

        return HttpResponse(
            f"""
            <small class='text-green-500'>Username updated to {new_username}</small>
            <script>
                // Update the input value in case it was changed during processing
                document.getElementById('id_username').value = '{new_username}';
            </script>
            """
        )

    return HttpResponse(status=405)  # Method Not Allowed


@login_required
def update_email(request):
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

        # Update email if valid
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
    errors = {}
    if request.method == "POST":
        current = request.POST.get("current_password", "").strip()
        new = request.POST.get("new_password", "").strip()

        # 1) Check current password
        if not request.user.check_password(current):
            errors["current_password"] = "Incorrect current password."

        # 2) Validate new password strength
        try:
            validate_password(new, user=request.user)
        except ValidationError as e:
            errors["new_password"] = "; ".join(e.messages)

        # 3) If no errors, update password
        if not errors:
            request.user.set_password(new)
            request.user.save()
            # Keep the user logged in
            update_session_auth_hash(request, request.user)
            messages.success(request, "Password changed successfully.")
            return redirect("settings")  # or wherever you want

    return render(request, "partials/change_password.html", {"errors": errors})