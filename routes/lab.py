from flask import Blueprint, jsonify, render_template
from flask_login import current_user, login_required

from models import SecurityEvent
from services import lab
from services.security_log import log_event

bp = Blueprint("lab", __name__)


@bp.get("/lab")
@login_required
def lab_page():
    events = SecurityEvent.query.filter_by(event_type="lab_test", user_id=current_user.id) \
        .order_by(SecurityEvent.id.desc()).limit(20).all()
    return render_template("lab.html", tests=list(lab.TESTS), events=events)


@bp.post("/lab/run/<name>")
@login_required
def run(name):
    names = list(lab.TESTS) if name == "all" else [name]
    if any(n not in lab.TESTS for n in names):
        return jsonify(error="unknown test"), 404
    results = [lab.run(n, current_user) for n in names]
    for r in results:
        sev = "info" if r["passed"] in (True, None) else "critical"
        log_event("lab_test", sev, user=current_user,
                  detail=f"{r['name']}: {'PASS' if r['passed'] else 'N/A' if r['passed'] is None else 'FAIL'} - {r['observed']}")
    return jsonify(results=results)
