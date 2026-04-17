import os
import uuid

from django.contrib.auth.models import User
from django.db import models


def profile_upload_path(prefix, filename):
    extension = os.path.splitext(filename)[1].lower()
    return f"private_uploads/{prefix}/{uuid.uuid4().hex}{extension}"


def avatar_upload_path(instance, filename):
    return profile_upload_path("avatars", filename)


def document_upload_path(instance, filename):
    return profile_upload_path("documents", filename)


class Profile(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="philemon_profile",
    )
    bio = models.TextField(blank=True, max_length=500)
    date_of_birth = models.DateField(blank=True, null=True)
    avatar = models.FileField(blank=True, upload_to=avatar_upload_path)
    document = models.FileField(blank=True, upload_to=document_upload_path)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile of {self.user.username}"
