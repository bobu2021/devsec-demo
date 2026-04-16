from django.contrib.auth.models import Group, Permission, User
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import m2m_changed, post_save, pre_save
from django.dispatch import receiver

from .audit import log_security_event
from .models import Profile


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if hasattr(instance, "philemon_profile"):
        instance.philemon_profile.save()


@receiver(user_logged_in)
def audit_login_success(sender, request, user, **kwargs):
    log_security_event("auth.login_succeeded", request=request, user=user)


@receiver(user_login_failed)
def audit_login_failure(sender, credentials, request, **kwargs):
    log_security_event(
        "auth.login_failed",
        request=request,
        username=(credentials or {}).get("username"),
    )


@receiver(user_logged_out)
def audit_logout(sender, request, user, **kwargs):
    if user is not None:
        log_security_event("auth.logout", request=request, user=user)


@receiver(pre_save, sender=User)
def capture_user_privilege_state(sender, instance, **kwargs):
    if not instance.pk:
        instance._audit_previous_flags = None
        return

    previous = sender.objects.filter(pk=instance.pk).values("is_staff", "is_superuser").first()
    instance._audit_previous_flags = previous


@receiver(post_save, sender=User)
def audit_privilege_flag_changes(sender, instance, created, **kwargs):
    if created:
        return

    previous = getattr(instance, "_audit_previous_flags", None)
    if not previous:
        return

    changes = {}
    if previous["is_staff"] != instance.is_staff:
        changes["is_staff"] = instance.is_staff
    if previous["is_superuser"] != instance.is_superuser:
        changes["is_superuser"] = instance.is_superuser

    if changes:
        log_security_event("auth.privilege_flags_changed", user=instance, changes=changes)


@receiver(m2m_changed, sender=User.groups.through)
def audit_group_changes(sender, instance, action, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    group_names = []
    if pk_set:
        group_names = list(Group.objects.filter(pk__in=pk_set).values_list("name", flat=True))

    log_security_event(
        "auth.group_membership_changed",
        user=instance,
        action=action,
        groups=group_names,
    )


@receiver(m2m_changed, sender=User.user_permissions.through)
def audit_permission_changes(sender, instance, action, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    permissions = []
    if pk_set:
        permissions = list(
            Permission.objects.filter(pk__in=pk_set).values_list("codename", flat=True)
        )

    log_security_event(
        "auth.user_permissions_changed",
        user=instance,
        action=action,
        permissions=permissions,
    )
