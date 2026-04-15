from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.views import (
    LoginView,
    PasswordChangeView,
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.utils.decorators import method_decorator

from django.contrib.auth.models import User

from .forms import (
    ProfileUpdateForm,
    UserLoginForm,
    UserPasswordChangeForm,
    UserPasswordResetForm,
    UserSetPasswordForm,
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


def user_is_privileged(user):
    return bool(
        user.is_authenticated
        and (
            user.is_staff
            or user.is_superuser
            or user.groups.filter(name="instructors").exists()
        )
    )


class PrivilegedAccessMixin(LoginRequiredMixin, UserPassesTestMixin):
    def test_func(self):
        return user_is_privileged(self.request.user)

    def handle_no_permission(self):
        if self.request.user.is_authenticated:
            messages.error(
                self.request,
                "You do not have permission to access that page.",
            )
            return redirect("philemon_mutabazi:dashboard")
        return super().handle_no_permission()


def can_access_profile(request_user, target_user):
    return bool(
        request_user.is_authenticated
        and request_user == target_user
    )


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
class ProfileRedirectView(View):
    def get(self, request):
        return redirect("philemon_mutabazi:profile_detail", username=request.user.username)


@method_decorator(login_required, name="dispatch")
class ProfileDetailView(View):
    template_name = "philemon_mutabazi/profile.html"

    def get_target_user(self, username):
        # Bind profile access to the currently authenticated user to prevent IDOR.
        target_user = get_object_or_404(User, username=username, pk=self.request.user.pk)
        if not can_access_profile(self.request.user, target_user):
            raise Http404
        return target_user

    def get(self, request, username):
        target_user = self.get_target_user(username)
        user_form = UserUpdateForm(instance=target_user)
        profile_form = ProfileUpdateForm(instance=target_user.philemon_profile)
        context = {
            "user_form": user_form,
            "profile_form": profile_form,
            "target_user": target_user,
            "can_edit": target_user == request.user,
        }
        return render(request, self.template_name, context)

    def post(self, request, username):
        target_user = self.get_target_user(username)
        user_form = UserUpdateForm(request.POST, instance=target_user)
        profile_form = ProfileUpdateForm(request.POST, instance=target_user.philemon_profile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, "Your profile has been updated.")
            return redirect("philemon_mutabazi:profile_detail", username=target_user.username)
        context = {
            "user_form": user_form,
            "profile_form": profile_form,
            "target_user": target_user,
            "can_edit": target_user == request.user,
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


class PrivilegedDashboardView(PrivilegedAccessMixin, View):
    template_name = "philemon_mutabazi/privileged_dashboard.html"

    def get(self, request):
        return render(request, self.template_name)


class UserPasswordResetView(PasswordResetView):
    """Secure password reset request view using Django's token system."""
    template_name = "philemon_mutabazi/password_reset_form.html"
    form_class = UserPasswordResetForm
    email_template_name = "philemon_mutabazi/password_reset_email.html"
    subject_template_name = "philemon_mutabazi/password_reset_subject.txt"
    success_url = reverse_lazy("philemon_mutabazi:password_reset_done")

    def get(self, request, *args, **kwargs):
        # Redirect authenticated users to their profile
        if request.user.is_authenticated:
            return redirect("philemon_mutabazi:profile")
        return super().get(request, *args, **kwargs)


class UserPasswordResetDoneView(PasswordResetDoneView):
    """Confirmation view after password reset request."""
    template_name = "philemon_mutabazi/password_reset_done.html"


class UserPasswordResetConfirmView(PasswordResetConfirmView):
    """View for setting a new password using reset token."""
    template_name = "philemon_mutabazi/password_reset_confirm.html"
    form_class = UserSetPasswordForm
    success_url = reverse_lazy("philemon_mutabazi:password_reset_complete")

    def form_valid(self, form):
        messages.success(
            self.request,
            "Your password has been reset successfully. You can now log in with your new password."
        )
        return super().form_valid(form)


class UserPasswordResetCompleteView(PasswordResetCompleteView):
    """Final success view after password reset."""
    template_name = "philemon_mutabazi/password_reset_complete.html"
