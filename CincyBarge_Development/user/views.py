import base64

from django.contrib.auth import get_user_model, login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt

from .forms import CreateUserForm

# Create your views here.


def register(request):
    if request.method == "POST":
        form = UserCreationForm(CreateUserForm.POST)
        if form.is_valid():
            form.save()
            return redirect("user-login")
    else:
        form = CreateUserForm()
    context = {
        "form": form,
    }
    return render(request, "user/register.html", context)


def profile(request):
    return render(request, "user/profile.html")


def staff_page(request):
    staff_users = User.objects.filter(is_staff=True).order_by("date_joined")

    return render(request, "your_template_name.html", {"users": staff_users})


@csrf_exempt
def sso_login(request):
    """
    SSO Login endpoint - accepts POST requests from barge2rail-auth SSO
    Automatically creates/updates user and logs them in
    """
    if request.method == "POST":
        # Get SSO data
        email = request.POST.get("email")
        username = request.POST.get("username")
        first_name = request.POST.get("first_name", "")
        last_name = request.POST.get("last_name", "")
        is_staff = request.POST.get("is_staff") == "true"
        is_superuser = request.POST.get("is_superuser") == "true"
        sso_signature = request.POST.get("sso_signature")

        if not email or not sso_signature:
            return redirect("/admin/login/")

        # Get or create user - try by email first, then by username
        user = None
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            try:
                # If no user with this email, try by username
                user = User.objects.get(username=username or email)
            except User.DoesNotExist:
                pass

        if user:
            # Update existing user info from SSO
            user.username = username or email
            user.email = email
            user.first_name = first_name
            user.last_name = last_name
            user.is_staff = is_staff
            user.is_superuser = is_superuser
            user.save()
        else:
            # Create new user from SSO data
            user = User.objects.create(
                username=username or email,
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_staff=is_staff,
                is_superuser=is_superuser,
                is_active=True,
            )
            # No password needed - SSO only
            user.set_unusable_password()
            user.save()

        # Log the user in
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")

        # Redirect to dashboard
        return redirect("dashboard-index")

    # GET request - redirect to SSO
    return redirect("http://127.0.0.1:8000/login/")
