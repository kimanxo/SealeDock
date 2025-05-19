from django.views.generic.base import View
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.contrib.auth.password_validation import validate_password
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse


class RegisterView(View):
    # Prevent authenticated users from accessing the registration page
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard")
        return super().dispatch(request, *args, **kwargs)

    # Show registration form
    def get(self, request):
        return render(request, "register.html")

    # Handle registration form submission
    def post(self, request):
        # HTMX request for checking username availability
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

        # HTMX request for checking email validity and availability
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
            # Regular POST request (registration submission)
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            password = request.POST.get("password", "")
            confirm_password = request.POST.get("confirm_password", "")

            errors = []

            # Validate email format
            try:
                EmailValidator()(email)
            except ValidationError:
                errors.append("Invalid email format.")

            # Ensure all fields are filled
            if not username or not email or not password or not confirm_password:
                errors.append("All fields are required.")

            # Check for duplicate username/email
            if User.objects.filter(username=username).exists():
                errors.append("Username is already taken.")

            if User.objects.filter(email=email).exists():
                errors.append("Email is already taken.")

            # Check password match
            if password != confirm_password:
                errors.append("Passwords do not match.")

            # Validate password strength
            try:
                validate_password(password)
            except ValidationError as e:
                errors.extend(e.messages)

            # Re-render form with errors if any
            if errors:
                return render(request, "register.html", {"errors": errors})

            # Create user if validation passes
            User.objects.create_user(username=username, email=email, password=password)
            messages.success(
                request, "Account created successfully. You may now log in."
            )
            return redirect("/login")


@login_required
@require_http_methods(["POST"])
def Logout(request):
    # Log the user out
    logout(request)

    # HTMX-specific redirect
    if request.htmx:
        response = HttpResponse()
        response["HX-Redirect"] = "/"
        return response

    return redirect("/")


class LoginView(View):
    # Prevent authenticated users from accessing login page
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard")
        return super().dispatch(request, *args, **kwargs)

    # Show login form
    def get(self, request):
        return render(request, "login.html")

    # Handle login submission
    def post(self, request):
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        errors = []

        # Ensure both fields are filled
        if not username or not password:
            errors.append("Username and password are required.")
        else:
            # Authenticate user
            user = authenticate(request, username=username, password=password)
            if user is None:
                errors.append("Invalid username or password.")

        # Handle login failure
        if errors:
            response = render(request, "partials/login_errors.html", {"errors": errors})
            if request.htmx:
                response["HX-Retarget"] = ".login-errors"
                response["HX-Reswap"] = "innerHTML"
            return response

        # Log the user in
        login(request, user)

        # HTMX-specific redirect
        if request.htmx:
            response = HttpResponse()
            response["HX-Redirect"] = "/"
            return response

        return redirect("/")
