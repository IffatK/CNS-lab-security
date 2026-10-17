"""DB-backed throttling for logins and message sending (survives restarts)."""
from datetime import timedelta

from flask import current_app
from sqlalchemy import func

from extensions import db
from models.base import utcnow
from models.message import Message
from models.security import LoginAttempt


def _failures(cutoff, **flt):
    last_ok = db.session.query(func.max(LoginAttempt.created_at)).filter_by(success=True, **flt).scalar()
    if last_ok and last_ok > cutoff:
        cutoff = last_ok  # a success resets the counter (rows are kept as evidence)
    return LoginAttempt.query.filter_by(**flt).filter(LoginAttempt.success.is_(False),
                                                      LoginAttempt.created_at > cutoff)


def login_lock_remaining(username, ip) -> int:
    """Seconds until login allowed again; 0 if not locked."""
    cfg = current_app.config
    window = cfg["LOGIN_WINDOW_SECONDS"]
    now = utcnow()
    cutoff = now - timedelta(seconds=window)
    username = (username or "").lower()[:64]
    worst = 0
    for flt, limit in (({"username": username, "ip": ip}, cfg["LOGIN_MAX_FAILS_USER_IP"]),
                       ({"ip": ip}, cfg["LOGIN_MAX_FAILS_IP"])):
        rows = _failures(cutoff, **flt).order_by(LoginAttempt.created_at.asc()).all()
        if len(rows) >= limit:
            oldest_counted = rows[-limit].created_at
            worst = max(worst, int((oldest_counted + timedelta(seconds=window) - now).total_seconds()) + 1)
    return max(worst, 0)


def record_login_attempt(username, ip, success):
    db.session.add(LoginAttempt(username=(username or "").lower()[:64], ip=ip or "unknown", success=success))
    db.session.commit()


def send_throttled(user_id) -> bool:
    cfg = current_app.config
    cutoff = utcnow() - timedelta(seconds=cfg["SEND_WINDOW_SECONDS"])
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    n = Message.query.filter(Message.sender_id == user_id, Message.created_at > cutoff_iso).count()
    return n >= cfg["SEND_MAX_PER_WINDOW"]
