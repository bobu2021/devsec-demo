from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
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
from django.core.cache import cache
from django.http import Http404
from django.shortcuts import resolve_url
from django.shortcuts import get_object_or_404, redirect, render
from django.conf import settings
from django.urls import reverse_lazy
from django.utils.http import urlencode, url_has_allowed_host_and_scheme
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect

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
from .audit import hash_identifier, log_security_event


class SafeRedirectMixin:
    redirect_field_name = REDIRECT_FIELD_NAME

    def get_redirect_target(self):
        redirect_to = (
            self.request.POST.get(self.redirect_field_name)
            or self.request.GET.get(self.redirect_field_name)
            or ""
        )
        if redirect_to and url_has_allowed_host_and_scheme(
            redirect_to,
            allowed_hosts={self.request.get_host()},
            require_https=self.request.is_secure(),
        ):
            return redirect_to
        return ""

    def get_safe_redirect_url(self, fallback_url):
        return self.get_redirect_target() or resolve_url(fallback_url)

    def get_redirect_context(self):
        return {
            "next_url": self.get_redirect_target(),
            "redirect_field_name": self.redirect_field_name,
        }


def get_safe_redirect_target(request):
    redirect_to = (
        request.POST.get(REDIRECT_FIELD_NAME)
        or request.GET.get(REDIRECT_FIELD_NAME)
        or ""
    )
    if redirect_to and url_has_allowed_host_and_scheme(
        redirect_to,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return redirect_to
    return ""


def build_login_redirect_url(request):
    login_url = resolve_url("philemon_mutabazi:login")
    redirect_to = get_safe_redirect_target(request)
    if not redirect_to:
        return login_url
    return f"{login_url}?{urlencode({REDIRECT_FIELD_NAME: redirect_to})}"


@method_decorator(csrf_protect, name="dispatch")
class RegisterView(SafeRedirectMixin, View):
    template_name = "philemon_mutabazi/register.html"

    def get_context_data(self, form):
        context = {"form": form}
        context.update(self.get_redirect_context())
        return context

    def get(self, request):
        if request.user.is_authenticated:
            return redirect(self.get_safe_redirect_url("philemon_mutabazi:dashboard"))
        form = UserRegistrationForm()
        return render(request, self.template_name, self.get_context_data(form))

    def post(self, request):
        if request.user.is_authenticated:
            return redirect(self.get_safe_redirect_url("philemon_mutabazi:dashboard"))
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            log_security_event("auth.registration", request=request, user=user)
            messages.success(request, f"Account created for {user.username}.")
            return redirect(build_login_redirect_url(request))
        return render(request, self.template_name, self.get_context_data(form))


class UserLoginView(SafeRedirectMixin, LoginView):
    template_name = "philemon_mutabazi/login.html"
    authentication_form = UserLoginForm
    redirect_authenticated_user = True

    def _normalize_username(self):
        return (self.request.POST.get("username") or "").strip().lower()

    def _attempt_key(self, username):
        return f"login_attempts:{username}"

    def _lock_key(self, username):
        return f"login_lock:{username}"

    def _is_locked(self, username):
        if not username:
            return False
        return bool(cache.get(self._lock_key(username)))

    def _record_failed_attempt(self, username):
        if not username:
            return

        attempt_key = self._attempt_key(username)
        lock_key = self._lock_key(username)
        attempts = cache.get(attempt_key, 0) + 1
        cache.set(attempt_key, attempts, timeout=settings.LOGIN_LOCKOUT_SECONDS)

        if attempts >= settings.LOGIN_MAX_ATTEMPTS:
            cache.set(lock_key, True, timeout=settings.LOGIN_LOCKOUT_SECONDS)

    def _reset_login_protection(self, username):
        if not username:
            return
        cache.delete(self._attempt_key(username))
        cache.delete(self._lock_key(username))

    def post(self, request, *args, **kwargs):
        username = self._normalize_username()
        if self._is_locked(username):
            form = self.get_form()
            form.add_error(
                None,
                "Too many failed login attempts. Please wait and try again.",
            )
            return self.form_invalid(form)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        self._record_failed_attempt(self._normalize_username())
        return super().form_invalid(form)

    def form_valid(self, form):
        self._reset_login_protection(self._normalize_username())
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(self.get_redirect_context())
        return context

    def get_success_url(self):
        return self.get_safe_redirect_url("philemon_mutabazi:dashboard")


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


@csrf_protect
@login_required
def logout_view(request):
    if request.method == "POST":
        logout(request)
        messages.info(request, "You have been logged out successfully.")
        redirect_to = get_safe_redirect_target(request)
        if redirect_to:
            return redirect(redirect_to)
        return redirect("philemon_mutabazi:login")
    return render(
        request,
        "philemon_mutabazi/logout_confirm.html",
        {
            "next_url": get_safe_redirect_target(request),
            "redirect_field_name": REDIRECT_FIELD_NAME,
        },
    )


@method_decorator(login_required, name="dispatch")
class DashboardView(View):
    template_name = "philemon_mutabazi/dashboard.html"

    def get(self, request):
        return render(request, self.template_name)


@method_decorator(login_required, name="dispatch")
class ProfileRedirectView(View):
    def get(self, request):
        return redirect("philemon_mutabazi:profile_detail", username=request.user.username)


@method_decorator([login_required, csrf_protect], name="dispatch")
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
        log_security_event("auth.password_changed", request=self.request, user=self.request.user)
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

    def form_valid(self, form):
        log_security_event(
            "auth.password_reset_requested",
            request=self.request,
            email_hash=hash_identifier(form.cleaned_data.get("email")),
        )
        return super().form_valid(form)


class UserPasswordResetDoneView(PasswordResetDoneView):
    """Confirmation view after password reset request."""
    template_name = "philemon_mutabazi/password_reset_done.html"


class UserPasswordResetConfirmView(PasswordResetConfirmView):
    """View for setting a new password using reset token."""
    template_name = "philemon_mutabazi/password_reset_confirm.html"
    form_class = UserSetPasswordForm
    success_url = reverse_lazy("philemon_mutabazi:password_reset_complete")

    def form_valid(self, form):
        log_security_event("auth.password_reset_completed", request=self.request, user=form.user)
        messages.success(
            self.request,
            "Your password has been reset successfully. You can now log in with your new password."
        )
        return super().form_valid(form)


class UserPasswordResetCompleteView(PasswordResetCompleteView):
    """Final success view after password reset."""
    template_name = "philemon_mutabazi/password_reset_complete.html"
