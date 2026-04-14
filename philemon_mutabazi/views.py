from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, PasswordChangeView
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.utils.decorators import method_decorator

from .forms import (
    ProfileUpdateForm,
    UserLoginForm,
    UserPasswordChangeForm,
    UserRegistrationForm,
    UserUpdateForm,
)


class RegisterView(View):
    template_name = "philemon_mutabazi/register.html"

    def get(self, request):
        if request.user.is_authenticated:
            return redirect("philemon_mutabazi:dashboard")
        form = UserRegistrationForm()
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        if request.user.is_authenticated:
            return redirect("philemon_mutabazi:dashboard")
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, f"Account created for {user.username}.")
            return redirect("philemon_mutabazi:login")
        return render(request, self.template_name, {"form": form})


class UserLoginView(LoginView):
    template_name = "philemon_mutabazi/login.html"
    authentication_form = UserLoginForm
    redirect_authenticated_user = True

    def get_success_url(self):
        return reverse_lazy("philemon_mutabazi:dashboard")


@login_required
def logout_view(request):
    if request.method == "POST":
        logout(request)
        messages.info(request, "You have been logged out successfully.")
        return redirect("philemon_mutabazi:login")
    return render(request, "philemon_mutabazi/logout_confirm.html")


@method_decorator(login_required, name="dispatch")
class DashboardView(View):
    template_name = "philemon_mutabazi/dashboard.html"

    def get(self, request):
        return render(request, self.template_name)


@method_decorator(login_required, name="dispatch")
class ProfileView(View):
    template_name = "philemon_mutabazi/profile.html"

    def get(self, request):
        user_form = UserUpdateForm(instance=request.user)
        profile_form = ProfileUpdateForm(instance=request.user.philemon_profile)
        context = {
            "user_form": user_form,
            "profile_form": profile_form,
        }
        return render(request, self.template_name, context)

    def post(self, request):
        user_form = UserUpdateForm(request.POST, instance=request.user)
        profile_form = ProfileUpdateForm(request.POST, instance=request.user.philemon_profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, "Your profile has been updated.")
            return redirect("philemon_mutabazi:profile")
        context = {
            "user_form": user_form,
            "profile_form": profile_form,
        }
        return render(request, self.template_name, context)


@method_decorator(login_required, name="dispatch")
class UserPasswordChangeView(PasswordChangeView):
    template_name = "philemon_mutabazi/password_change.html"
    form_class = UserPasswordChangeForm
    success_url = reverse_lazy("philemon_mutabazi:profile")

    def form_valid(self, form):
        messages.success(self.request, "Your password was changed successfully.")
        return super().form_valid(form)
