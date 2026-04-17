from django.contrib import admin

from .models import Profile


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "date_of_birth", "updated_at")
    list_filter = ("updated_at",)
    search_fields = ("user__username", "user__email")
