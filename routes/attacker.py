from functools import wraps
from datetime import datetime, timedelta, timezone
import json
import uuid
from flask import Blueprint, abort, jsonify, render_template, request, Response
from flask_login import current_user, login_required
from sqlalchemy import desc, update
from models import LabCapture, LabSettings, LoginAttempt, Message, SecurityEvent, User, InterceptedMessage
from services.security_log import log_event
from services import messaging
from services.messaging import verify_signature_status
from extensions import db
from services.crypto import encrypt_unprotected
from sqlalchemy.exc import IntegrityError

bp = Blueprint("attacker", __name__)
RELAY_ACTIONS = frozenset(("drop", "forward_original", "forward_edited"))


def _timestamp(value, *, timespec="seconds"):
    """Format ORM timestamps consistently across old SQLite and current rows."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:19].replace("T", " ")
    return value.isoformat(sep=" ", timespec=timespec)


def lab_operator_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped

@bp.get("/attacker")
@lab_operator_required
def page():
    return render_template("attacker.html")

@bp.get("/api/attacker/events")
@lab_operator_required
def events():
    visible_event_types = (
        "attacker_simulation_started", "attacker_simulation_completed", "attacker_forwarded_original",
        "attacker_modified_message", "attacker_dropped_message", "attacker_action_blocked",
        "attacker_action_rejected", "message_intercepted", "plaintext_transport_blocked",
    )
    evs = SecurityEvent.query.filter(SecurityEvent.event_type.in_(visible_event_types)).order_by(desc(SecurityEvent.id)).limit(80).all()
    attempts = LoginAttempt.query.order_by(desc(LoginAttempt.id)).limit(30).all()
    captures = LabCapture.query.filter_by(protection="plaintext").order_by(desc(LabCapture.id)).limit(50).all()
    pending = InterceptedMessage.query.filter_by(status="pending").order_by(desc(InterceptedMessage.id)).limit(50).all()
    def capture_row(c):
        stored = db.session.get(Message, c.message_id) if c.message_id else None
        size = (len(c.visible_content.encode("utf-8")) if c.visible_content is not None else
                len(stored.ciphertext) if stored else None)
        return {"id": c.id, "time": _timestamp(c.created_at),
                "username": c.username, "source": c.source_ip, "recipient": c.recipient,
                "protection": c.protection, "content": c.visible_content,
                "wire_preview": c.wire_preview, "message_id": c.message_id, "size_bytes": size,
                "verification": verify_signature_status(stored) if stored else "pending",
                "status": c.status}
    return jsonify(
        events=[{"id":e.id,"time":_timestamp(e.created_at),
                 "type":e.event_type,"severity":e.severity,"username":e.username or "unknown",
                 "source":e.ip or "unknown","detail":e.detail or ""} for e in evs],
        attempts=[{"time":_timestamp(a.created_at),
                   "username":a.username,"source":a.ip,"result":"SUCCESS" if a.success else "FAILED"} for a in attempts],
        captures=[capture_row(c) for c in captures],
        pending=[{"id":m.id,"time":_timestamp(m.created_at),
                  "sender":m.sender_username,"recipient":m.recipient_username,"body":m.original_body,
                  "source":m.source_ip,"status":m.status} for m in pending],
        messages=[{"id":m.id,"time":m.created_at,"sender":m.sender.username,"recipient":m.recipient.username,
                   "protection":m.protection}
                  for m in Message.query.filter(Message.protection.in_(("plaintext_relay", "plaintext_relay_tampered")))
                  .order_by(desc(Message.id)).limit(100).all()],
        stats={"pending":InterceptedMessage.query.filter_by(status="pending").count(),"users":User.query.count(),
               "messages":Message.query.filter(Message.protection.in_(("plaintext_relay", "plaintext_relay_tampered"))).count(),
               "events":SecurityEvent.query.filter(SecurityEvent.event_type.in_(visible_event_types)).count(),"failed_logins":LoginAttempt.query.filter_by(success=False).count(),
               "critical":SecurityEvent.query.filter_by(severity="critical").count(),
               "captures":LabCapture.query.filter_by(protection="plaintext").count(),
               "plaintext":LabCapture.query.filter_by(protection="plaintext").count(),
               "forwarded":InterceptedMessage.query.filter(InterceptedMessage.status.in_(("forwarded", "tampered"))).count(),
               "dropped":InterceptedMessage.query.filter_by(status="dropped").count(),
               "simulations":SecurityEvent.query.filter_by(event_type="attacker_simulation_completed").count(),
               "simulations_blocked":SecurityEvent.query.filter_by(event_type="attacker_simulation_completed").filter(SecurityEvent.detail.contains("outcome=blocked")).count(),
               "attack_attempts":SecurityEvent.query.filter_by(event_type="attacker_simulation_started").count(),
               "simulation_successes":SecurityEvent.query.filter_by(event_type="attacker_simulation_completed").filter(SecurityEvent.detail.contains("status=completed")).count(),
               "blocked_attacks":SecurityEvent.query.filter_by(event_type="attacker_simulation_completed").filter(SecurityEvent.detail.contains("outcome=blocked")).count()}
    )


@bp.get("/api/attacker/diagnostics")
@lab_operator_required
def diagnostics():
    """Live attacker-lab analytics derived from persisted lab records/events."""
    days = request.args.get("days", 7, type=int)
    days = days if days in (7, 30, 90) else 7
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    first_day = today - timedelta(days=days - 1)
    labels = [(first_day + timedelta(days=i)).isoformat() for i in range(days)]
    actions = SecurityEvent.query.filter(
        SecurityEvent.created_at >= datetime.combine(first_day, datetime.min.time()),
        SecurityEvent.event_type.in_(("attacker_forwarded_original", "attacker_modified_message",
                                      "attacker_dropped_message", "attacker_action_blocked",
                                      "attacker_action_rejected", "attacker_simulation_started"))
    ).all()
    sim_events = SecurityEvent.query.filter(
        SecurityEvent.created_at >= datetime.combine(first_day, datetime.min.time()),
        SecurityEvent.event_type.in_(("attacker_simulation_started", "attacker_simulation_completed"))
    ).order_by(SecurityEvent.id).all()
    attempts_by_day = {label: 0 for label in labels}
    blocked_by_day = {label: 0 for label in labels}
    action_types = {name: {"successful": 0, "blocked": 0} for name in ("forward", "tamper", "drop")}
    for event in actions:
        label = event.created_at.date().isoformat()
        if label not in attempts_by_day:
            continue
        attempts_by_day[label] += 1
        is_blocked = event.event_type in ("attacker_action_blocked", "attacker_action_rejected")
        if is_blocked:
            blocked_by_day[label] += 1
        detail = (event.detail or "").lower()
        kind = ("tamper" if event.event_type == "attacker_modified_message" or "tamper" in detail or "edit" in detail
                else "drop" if event.event_type == "attacker_dropped_message" or "drop" in detail
                else "forward")
        action_types[kind]["blocked" if is_blocked else "successful"] += 1

    simulation_types = {}
    for event in sim_events:
        label = event.created_at.date().isoformat()
        detail = event.detail or ""
        fields = dict(part.split("=", 1) for part in detail.split() if "=" in part)
        kind = fields.get("type", "unknown")
        if event.event_type == "attacker_simulation_started":
            if label in attempts_by_day:
                attempts_by_day[label] += 1
            continue
        outcome = fields.get("outcome", "unknown")
        if outcome == "blocked" and label in blocked_by_day:
            blocked_by_day[label] += 1
        bucket = simulation_types.setdefault(kind, {"successful": 0, "blocked": 0, "failed": 0})
        bucket["blocked" if outcome == "blocked" else "failed" if fields.get("status") != "completed" else "successful"] += 1

    all_messages = Message.query.filter(Message.protection.in_(
        ("plaintext_relay", "plaintext_relay_tampered"))).order_by(Message.id.desc()).all()
    messages = all_messages[:100]
    integrity = [{"id": m.id, "time": _timestamp(m.created_at),
                  "sender": m.sender.username, "recipient": m.recipient.username,
                  "protection": m.protection, "verification": verify_signature_status(m)} for m in messages]
    states = {m.id: verify_signature_status(m) for m in all_messages}
    signature_results = {"verified": sum(s == "verified" for s in states.values()),
                         "unprotected": sum(s == "unprotected" for s in states.values()),
                         "failed": sum(s not in ("verified", "unprotected") for s in states.values())}
    intercepted = InterceptedMessage.query
    tampered_items = intercepted.filter_by(status="tampered").all()
    tampered_message_ids = {item.delivered_message_id for item in tampered_items if item.delivered_message_id}
    rejected = sum(state not in ("verified", "unprotected") and message_id not in tampered_message_ids
                   for message_id, state in states.items())
    outcomes = {"delivered": sum(s in ("verified", "unprotected") for s in states),
                "pending": intercepted.filter_by(status="pending").count(),
                "dropped": intercepted.filter_by(status="dropped").count(),
                "rejected": rejected,
                "tampered": len(tampered_items)}
    settings = LabSettings.query.all()
    policy = {"enabled_accounts": sum(bool(row.protection_enabled) for row in settings),
              "configured_accounts": User.query.count(),
              "enforcement": "Sender-side protection bypasses the readable relay. Unprotected sender messages enter the relay even if the receiver has enabled protection; protected receivers are warned and tampered signed messages are rejected."}
    return jsonify(days=days,
                   timeline=[{"label": day, "attempts": attempts_by_day[day], "blocked": blocked_by_day[day]} for day in labels],
                   attack_types=action_types, outcomes=outcomes, integrity=integrity,
                   signature_results=signature_results,
                   simulation_types=simulation_types,
                   protection=policy)

@bp.post("/api/attacker/relay/<int:item_id>")
@lab_operator_required
def relay_message(item_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Malformed relay request for intercepted message {item_id}")
        return jsonify(error="JSON object body required."), 400
    action = data.get("action")
    if not isinstance(action, str) or action not in RELAY_ACTIONS:
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Invalid relay action for intercepted message {item_id}")
        return jsonify(error="action must be forward_original, forward_edited, or drop"), 400
    if action == "drop":
        body = None
    elif action == "forward_original":
        body = None
    elif action == "forward_edited":
        body = data.get("body")
        if not isinstance(body, str) or not body.strip() or len(body) > 2000:
            log_event("attacker_action_rejected", "warning", user=current_user,
                      detail=f"Invalid edited-forward request for intercepted message {item_id}")
            return jsonify(error="Edited message must contain 1–2000 characters."), 400

    candidate = db.session.get(InterceptedMessage, item_id)
    if candidate is None or candidate.status != "pending":
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Relay action {action} rejected: intercepted message {item_id} is not pending")
        return jsonify(error="This intercepted message is no longer pending."), 409
    original_envelope = candidate.get_envelope()
    if action != "drop" and original_envelope is None:
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Relay action {action} rejected: legacy message {item_id} has no signed envelope")
        return jsonify(error="This legacy interception has no sender-signed envelope. Drop it and ask the sender to resend."), 409

    # Compare-and-swap makes relay actions one-shot even when two requests race.
    # Keep this write transaction open while re-checking policy and completing
    # delivery, so a concurrent setting update cannot slip between the policy
    # check and the tamper action.
    claimed = db.session.execute(
        update(InterceptedMessage)
        .where(InterceptedMessage.id == item_id, InterceptedMessage.status == "pending")
        .values(status="processing")
    ).rowcount
    if not claimed:
        db.session.rollback()
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Relay action {action} lost a race for intercepted message {item_id}")
        return jsonify(error="This intercepted message is no longer pending."), 409
    # The sender's setting was checked when the message entered this queue.
    # A receiver preference cannot retroactively hide plaintext already
    # exposed by an unprotected sender; it changes how edits are reported.
    item = db.session.get(InterceptedMessage, item_id)
    if item is None:
        db.session.rollback()
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Relay action {action} failed: intercepted message {item_id} disappeared")
        return jsonify(error="Intercepted message not found."), 404

    if action == "drop":
        item.status = "dropped"
        db.session.commit()
        log_event("attacker_dropped_message", "warning", username=item.sender_username,
                  detail=f"Attacker dropped intercepted message {item.id}")
        return jsonify(status="dropped", message="Message dropped; recipient will not receive it.")
    edited = item.original_body if action == "forward_original" else body
    try:
        if edited == item.original_body:
            envelope = original_envelope
            protection = "plaintext_relay"
        elif item.recipient_protected:
            # Protected receivers verify the sender's signature and withhold
            # any altered content. The relay IP is included in their report.
            envelope = messaging.envelope_for_edit(original_envelope, edited)
            protection = "plaintext_relay_tampered"
        else:
            # In the both-unprotected exercise, no integrity guarantee exists:
            # the relay can substitute readable content without a tamper alert.
            envelope = encrypt_unprotected(messaging.keys().master_key, original_envelope.sender_id,
                                           original_envelope.recipient_id, edited)
            protection = "plaintext_relay"
        delivered = Message.from_envelope(envelope)
        delivered.protection = protection
        delivered.relay_ip = request.remote_addr or "unknown"
        delivered.relay_report = bool(item.recipient_protected)
        db.session.add(delivered)
        db.session.flush()
    except Exception as exc:
        db.session.rollback()
        item = db.session.get(InterceptedMessage, item_id)
        if item is not None and item.status == "processing":
            item.status = "pending"
            db.session.commit()
        log_event("attacker_action_rejected", "warning", user=current_user,
                  detail=f"Relay action {action} failed for intercepted message {item_id}: {type(exc).__name__}")
        return jsonify(error=getattr(exc, "message", "Could not deliver edited message.")), getattr(exc, "status", 400)
    item.edited_body = edited
    item.status = "tampered" if edited != item.original_body else "forwarded"
    item.delivered_message_id = delivered.id
    capture = LabCapture(username=item.sender_username, source_ip=item.source_ip,
                         recipient=item.recipient_username, protection="plaintext",
                         visible_content=edited, wire_preview=("Attacker modified a sender-signed envelope; verification must fail" if edited != item.original_body else "Attacker forwarded the original sender-signed envelope unchanged"),
                         message_id=delivered.id, status=("tampered and forwarded" if edited != item.original_body else "forwarded unchanged"))
    log_event("message_delivered", "info", username=item.sender_username,
              detail=f"msg={delivered.id} recipient={item.recipient_username} mode=plaintext_relay")
    db.session.add(capture)
    db.session.commit()
    event_type = "attacker_forwarded_original" if action == "forward_original" else "attacker_modified_message"
    log_event(event_type, "warning" if action == "forward_original" else "critical", username=item.sender_username,
              detail=f"Attacker {action.replace('_', ' ')} for intercepted message {item.id}; delivered message {delivered.id}; plaintext relay")
    return jsonify(status="forwarded", message_id=delivered.id, relay_ip=delivered.relay_ip,
                   protection="unprotected", message=("Original message delivered through the plaintext lab relay." if action == "forward_original" else "Edited message delivered through the plaintext lab relay."), changed=(edited != item.original_body))


SIMULATIONS = {
    "interception", "tampering", "replay", "unauthorized_access",
    "dropping", "delivery_manipulation", "signature_verification",
    "protection_comparison",
}


@bp.post("/api/attacker/simulations/<kind>")
@lab_operator_required
def run_simulation(kind):
    """Run a bounded, app-local exercise and persist safe evidence as audit events."""
    if kind not in SIMULATIONS:
        return jsonify(error="Unknown simulation type."), 404
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify(error="JSON object body required."), 400
    run_id = str(uuid.uuid4())
    selected_id = data.get("message_id")
    queue_id = data.get("queue_id")
    if selected_id is not None and (isinstance(selected_id, bool) or not isinstance(selected_id, int) or selected_id <= 0):
        return jsonify(error="message_id must be a positive integer."), 400
    if selected_id is not None and not Message.query.filter(
            Message.id == selected_id,
            Message.protection.in_(("plaintext_relay", "plaintext_relay_tampered"))).first():
        return jsonify(error="Message unavailable to the attacker relay."), 404
    if queue_id is not None and (isinstance(queue_id, bool) or not isinstance(queue_id, int) or queue_id <= 0):
        return jsonify(error="queue_id must be a positive integer."), 400
    log_event("attacker_simulation_started", "info", user=current_user,
              detail=f"run_id={run_id} type={kind} selected={selected_id or 'synthetic'}")
    result = {"run_id": run_id, "type": kind, "status": "completed", "outcome": "observed", "evidence": {}}
    try:
        if kind == "interception":
            q = InterceptedMessage.query.filter_by(status="pending").order_by(InterceptedMessage.id.desc()).limit(50).all()
            result.update(outcome="observed", explanation="The relay can read metadata for messages held in its app-local queue. Plaintext is visible only for messages submitted through the unprotected lab path.",
                          evidence={"pending_count": len(q), "message_ids": [x.id for x in q],
                                    "protection": "metadata only; no protected plaintext exposed"})
        elif kind == "tampering":
            from services.lab import run as run_lab
            check = run_lab("tamper_ciphertext", current_user)
            result.update(outcome="blocked" if check["passed"] else "failed", explanation=check["observed"], evidence={"check": check["name"], "passed": check["passed"]})
        elif kind == "replay":
            message = (Message.query.filter_by(id=selected_id).filter(Message.protection.in_(
                ("plaintext_relay", "plaintext_relay_tampered"))).first() if selected_id else
                Message.query.filter(Message.protection.in_(
                    ("plaintext_relay", "plaintext_relay_tampered"))).order_by(desc(Message.id)).first())
            if message is None:
                result.update(status="failed", outcome="no_data", explanation="Send a lab message before testing replay protection.")
            else:
                from models.message import Message as MessageModel
                duplicate = MessageModel.from_envelope(message.to_envelope())
                try:
                    with db.session.begin_nested():
                        db.session.add(duplicate)
                        db.session.flush()
                    result.update(outcome="allowed", explanation="Duplicate envelope inserted unexpectedly; uniqueness protection did not reject it.", evidence={"message_id": message.id})
                except IntegrityError:
                    result.update(outcome="blocked", explanation="The database rejected a duplicate message identifier/nonce. No duplicate was stored.", evidence={"message_id": message.id, "duplicate_stored": False})
        elif kind == "unauthorized_access":
            message = (Message.query.filter_by(id=selected_id).filter(Message.protection.in_(
                ("plaintext_relay", "plaintext_relay_tampered"))).first() if selected_id else
                Message.query.filter(Message.protection.in_(
                    ("plaintext_relay", "plaintext_relay_tampered"))).order_by(desc(Message.id)).first())
            if message is None:
                result.update(status="failed", outcome="no_data", explanation="Send a lab message before testing access control.")
            else:
                outsider = User.query.filter(User.id.notin_((message.sender_id, message.recipient_id))).order_by(User.id).first()
                if outsider is None:
                    result.update(status="failed", outcome="no_test_account", explanation="A separate test account is required.")
                else:
                    try:
                        messaging.get_authorized_message(message.id, outsider)
                        result.update(outcome="allowed", explanation="Unexpectedly, a nonparticipant could access the message.")
                    except Exception as exc:
                        from werkzeug.exceptions import NotFound
                        if isinstance(exc, NotFound):
                            result.update(outcome="blocked", explanation="A separate lab account was denied access; message contents were not read.", evidence={"message_id": message.id, "test_account": outsider.username})
                        else:
                            raise
        elif kind == "dropping":
            item = db.session.get(InterceptedMessage, queue_id) if queue_id else None
            if item is None or item.status != "pending":
                result.update(status="failed", outcome="no_pending_message", explanation="Select a currently pending relay item from the queue selector to test drop behavior.")
            else:
                claimed = db.session.execute(
                    update(InterceptedMessage)
                    .where(InterceptedMessage.id == item.id, InterceptedMessage.status == "pending")
                    .values(status="dropped")
                ).rowcount
                if not claimed:
                    db.session.rollback()
                    result.update(status="failed", outcome="already_processed", explanation="The selected queue item was processed by another request; no state was changed by this run.")
                    item = None
            if item is not None and result["status"] == "completed":
                db.session.commit()
                log_event("attacker_dropped_message", "warning", user=current_user,
                          detail=f"run_id={run_id} dropped intercepted message {item.id}")
                result.update(outcome="dropped", explanation="The queued message was marked dropped and is excluded from the receiver inbox.", evidence={"intercept_id": item.id, "delivered_message_id": item.delivered_message_id})
        elif kind == "delivery_manipulation":
            forged_action = "force_delivered"
            accepted = forged_action in RELAY_ACTIONS
            result.update(outcome="blocked" if not accepted else "allowed",
                          explanation="The real relay action validator rejects arbitrary client-supplied delivery states. Delivery changes only through its guarded Forward/Drop operations.",
                          evidence={"attempted_action": forged_action, "accepted_by_relay_validator": accepted,
                                   "allowed_actions": sorted(RELAY_ACTIONS)})
        elif kind == "signature_verification":
            from services.lab import run as run_lab
            check = run_lab("tamper_signature", current_user)
            result.update(outcome="blocked" if check["passed"] else "failed", explanation=check["observed"], evidence={"check": check["name"], "passed": check["passed"]})
        elif kind == "protection_comparison":
            enabled = LabSettings.query.filter_by(protection_enabled=True).count()
            configured = LabSettings.query.count()
            off_allowed, off_reason = messaging.plaintext_relay_policy(False, False)
            on_allowed, on_reason = messaging.plaintext_relay_policy(True, True)
            result.update(outcome="observed", explanation="The comparison executed the server's shared plaintext relay policy against both fixture configurations. Protected messages continue through the authenticated protected transport path.", evidence={"accounts_with_protection": enabled, "accounts_with_settings": configured, "policy_source": "services.messaging.plaintext_relay_policy", "protection_disabled": {"relay_allowed": off_allowed, "reason": off_reason}, "protection_enabled": {"relay_allowed": on_allowed, "reason": on_reason}})
    except Exception as exc:
        db.session.rollback()
        result.update(status="failed", outcome="error", explanation=f"Simulation failed ({type(exc).__name__}).")
    # Store a safe compact summary; no secrets, tokens, or message plaintext.
    log_event("attacker_simulation_completed", "info" if result["status"] == "completed" else "warning",
              user=current_user,
              detail=f"run_id={run_id} type={kind} status={result['status']} outcome={result['outcome']} evidence={json.dumps(result['evidence'], sort_keys=True)[:300]}")
    return jsonify(result), (200 if result["status"] == "completed" else 400)


@bp.get("/api/attacker/reports/<run_id>")
@lab_operator_required
def simulation_report(run_id):
    try:
        run_id = str(uuid.UUID(run_id))
    except (ValueError, AttributeError):
        return jsonify(error="Invalid run identifier."), 400
    rows = SecurityEvent.query.filter(SecurityEvent.detail.contains(f"run_id={run_id}")).order_by(SecurityEvent.id).all()
    if not rows:
        return jsonify(error="Run not found."), 404
    report = {"run_id": run_id, "generated_at": datetime.now(timezone.utc).isoformat(),
              "events": [{"timestamp": row.created_at.isoformat() if row.created_at else None,
                          "event": row.event_type, "severity": row.severity,
                          "detail": row.detail} for row in rows]}
    return Response(json.dumps(report, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=lab-run-{run_id}.json"})

@bp.post("/api/attacker/tamper-demo")
@lab_operator_required
def tamper_demo():
    from services.lab import run as run_lab
    check = run_lab("tamper_ciphertext", current_user)
    result = "PASS" if check.get("passed") else "FAIL"
    detail = check.get("observed", "Synthetic tamper test did not return a result.")
    log_event("tamper_test_" + result.lower(), "info" if result == "PASS" else "critical", detail=detail)
    return jsonify(result=result, title="Synthetic cryptographic tamper test", detail=detail), 200
