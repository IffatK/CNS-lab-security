"""Security event logging. Callers must never pass passwords, keys, tokens or plaintext."""
import re

from flask import has_request_context, request

from extensions import db
from models.security import SecurityEvent, SecurityNotification

_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _clean(s, n):
    return _CTRL.sub(" ", str(s))[:n]


def log_event(event_type, severity="info", user=None, detail="", username=None):
    actor = user
    if actor is None and username:
        from models.user import User
        actor = User.query.filter_by(username=_clean(username, 64).lower()).first()
    ev = SecurityEvent(
        event_type=event_type, severity=severity,
        user_id=getattr(actor, "id", None),
        username=_clean(username or getattr(actor, "username", "") or "", 64) or None,
        ip=request.remote_addr if has_request_context() else None,
        detail=_clean(detail, 500))
    db.session.add(ev)
    normalized = str(event_type or "").lower()
    if ev.user_id and (severity in ("warning", "critical") or normalized in {
        "password_changed", "session_revoked", "sessions_revoked", "protection_enabled", "protection_disabled"
    }):
        titles = {
            "login_failed": "Failed sign-in attempt", "login_throttled": "Sign-in temporarily throttled",
            "crypto_failure": "Message integrity verification failed", "file_integrity_failure": "File integrity check failed",
            "password_changed": "Password changed", "session_revoked": "Session revoked",
            "sessions_revoked": "Other sessions revoked", "malware_scan_infected": "Malware detected",
            "malware_scan_failed": "Malware scan failed", "attacker_modified_message": "Lab relay modified a message",
            "attacker_dropped_message": "Lab relay dropped a message", "session_created": "New browser session",
        }
        db.session.add(SecurityNotification(user_id=ev.user_id, event=ev,
                                            title=titles.get(normalized, normalized.replace("_", " ").capitalize())))
    db.session.commit()
    return ev
