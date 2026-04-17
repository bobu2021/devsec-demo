import hashlib
import json
import logging


audit_logger = logging.getLogger("philemon_mutabazi.audit")


def hash_identifier(value):
    if not value:
        return None
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()[:16]


def get_client_ip(request):
    if not request:
        return None
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_security_event(event, *, request=None, user=None, **details):
    payload = {
        "event": event,
        "user_id": getattr(user, "pk", None),
        "username": getattr(user, "get_username", lambda: None)(),
        "ip_address": get_client_ip(request),
        "path": getattr(request, "path", None),
    }
    payload.update({key: value for key, value in details.items() if value is not None})
    audit_logger.info(json.dumps(payload, sort_keys=True))
