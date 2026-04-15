from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
    UserCreationForm,
)
from django.contrib.auth.models import User

from .models import Profile


class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not email:
            return email
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email


class UserLoginForm(AuthenticationForm):
    pass


class UserPasswordChangeForm(PasswordChangeForm):
    pass


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username", "email")

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if not email:
            return email
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise forms.ValidationError("A user with this email already exists.")
        return email


class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ("bio", "date_of_birth")


class UserPasswordResetForm(PasswordResetForm):
    """Custom password reset form with secure messaging."""
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(attrs={'autocomplete': 'email'})
    )

    def clean_email(self):
        """Validate email without disclosing account existence."""
        email = self.cleaned_data.get("email")
        if not email:
            return email
        # Note: We intentionally do not check if the email exists here
        # to prevent user enumeration attacks. The email will be silently
        # ignored if no account exists.
        return email


class UserSetPasswordForm(SetPasswordForm):
    """Custom set password form with secure validation."""
    pass

