import os

from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
    UserCreationForm,
)
from django.contrib.auth.models import User
from django.utils.html import strip_tags

from .models import Profile

MAX_AVATAR_SIZE = 2 * 1024 * 1024
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024
ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_DOCUMENT_EXTENSIONS = {".pdf"}


def _file_extension(upload):
    return os.path.splitext(upload.name)[1].lower()


def _read_file_header(upload, length=16):
    position = upload.tell()
    upload.seek(0)
    header = upload.read(length)
    upload.seek(position)
    return header


def validate_avatar_upload(upload):
    if not upload:
        return upload

    extension = _file_extension(upload)
    if extension not in ALLOWED_AVATAR_EXTENSIONS:
        raise forms.ValidationError("Avatar uploads must be a JPG or PNG image.")

    if upload.size > MAX_AVATAR_SIZE:
        raise forms.ValidationError("Avatar uploads must be 2 MB or smaller.")

    header = _read_file_header(upload)
    is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
    is_jpeg = header.startswith(b"\xff\xd8\xff")
    if not (is_png or is_jpeg):
        raise forms.ValidationError("Avatar content does not match an allowed image format.")

    return upload


def validate_document_upload(upload):
    if not upload:
        return upload

    extension = _file_extension(upload)
    if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
        raise forms.ValidationError("Document uploads must be a PDF file.")

    if upload.size > MAX_DOCUMENT_SIZE:
        raise forms.ValidationError("Document uploads must be 5 MB or smaller.")

    header = _read_file_header(upload)
    if not header.startswith(b"%PDF-"):
        raise forms.ValidationError("Document content does not match an allowed PDF file.")

    return upload


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
        fields = ("bio", "date_of_birth", "avatar", "document")

    def clean_bio(self):
        bio = self.cleaned_data.get("bio", "")
        if not bio:
            return bio
        return strip_tags(bio)

    def clean_avatar(self):
        return validate_avatar_upload(self.cleaned_data.get("avatar"))

    def clean_document(self):
        return validate_document_upload(self.cleaned_data.get("document"))


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

