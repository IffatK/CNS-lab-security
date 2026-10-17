import hashlib

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models import LoginAttempt, UserSession
from models.base import utcnow
from services.security_log import log_event

bp = Blueprint("account", __name__)


def _current_sid_hash():
    sid = session.get("sid", "")
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()


@bp.get("/account")
@login_required
def page():
    sessions = UserSession.query.filter_by(user_id=current_user.id).order_by(UserSession.last_seen_at.desc()).limit(30).all()
    attempts = LoginAttempt.query.filter_by(username=current_user.username).order_by(LoginAttempt.id.desc()).limit(20).all()
    return render_template("account_security.html", sessions=sessions, attempts=attempts,
                           current_sid_hash=_current_sid_hash())


@bp.post("/account/sessions/<int:session_id>/revoke")
@login_required
def revoke(session_id):
    row = UserSession.query.filter_by(id=session_id, user_id=current_user.id, revoked_at=None).first_or_404()
    row.revoked_at = utcnow()
    db.session.commit()
    log_event("session_revoked", "warning", user=current_user, detail=f"session_id={row.id} revoked")
    if row.sid_hash == _current_sid_hash():
        logout_user()
        session.clear()
        flash("This session was revoked.", "ok")
        return redirect(url_for("auth.login"))
    flash("Session revoked. It will be rejected on its next request.", "ok")
    return redirect(url_for("account.page"))


@bp.post("/account/sessions/revoke-others")
@login_required
def revoke_others():
    rows = UserSession.query.filter_by(user_id=current_user.id, revoked_at=None).all()
    now = utcnow()
    count = 0
    for row in rows:
        if row.sid_hash != _current_sid_hash():
            row.revoked_at = now
            count += 1
    db.session.commit()
    log_event("sessions_revoked", "warning", user=current_user, detail=f"other_sessions={count}")
    flash(f"Revoked {count} other session(s).", "ok")
    return redirect(url_for("account.page"))


@bp.post("/account/password")
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")
    if not check_password_hash(current_user.password_hash, current):
        flash("Current password was not accepted.", "warning")
        return redirect(url_for("account.page"))
    if (len(new) < 12 or len(new) > 128 or not any(c.isalpha() for c in new)
            or not any(not c.isalnum() for c in new) or current_user.username in new.lower()):
        flash("Use 12–128 characters with letters and non-letters; do not include your username.", "warning")
        return redirect(url_for("account.page"))
    if new != confirm:
        flash("New password confirmation did not match.", "warning")
        return redirect(url_for("account.page"))
    user = current_user._get_current_object()
    user.password_hash = generate_password_hash(new)
    user.session_epoch += 1
    UserSession.query.filter_by(user_id=user.id, revoked_at=None).update({"revoked_at": utcnow()})
    db.session.commit()
    log_event("password_changed", "warning", user=user, detail="Password changed; all browser sessions revoked")
    logout_user()
    session.clear()
    flash("Password changed. Sign in again with your new password.", "ok")
    return redirect(url_for("auth.login"))
