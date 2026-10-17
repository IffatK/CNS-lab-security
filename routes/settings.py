from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from extensions import db
from models import LabSettings
from services.security_log import log_event

bp = Blueprint("settings", __name__)

def get_settings(user):
    row = LabSettings.query.filter_by(user_id=user.id).first()
    if row is None:
        row = LabSettings(user_id=user.id, protection_enabled=False)
        db.session.add(row); db.session.commit()
    return row

@bp.route("/settings", methods=["GET", "POST"])
@login_required
def page():
    row = get_settings(current_user)
    if request.method == "POST":
        enabled = request.form.get("protection_enabled") == "on"
        changed = row.protection_enabled != enabled
        row.protection_enabled = enabled
        db.session.commit()
        if changed:
            log_event("protection_enabled" if enabled else "protection_disabled",
                      "info" if enabled else "warning", user=current_user,
                      detail="ElGamal + AES-GCM transport protection " + ("enabled" if enabled else "disabled"))
        flash("Transport protection " + ("enabled." if enabled else "disabled. Unprotected lab messages will be visible in the attacker console."), "ok" if enabled else "warning")
        return redirect(url_for("settings.page"))
    return render_template("settings.html", protection_enabled=row.protection_enabled,
                           client_ip=request.remote_addr)
