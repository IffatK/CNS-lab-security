import csv
import io
import json
import os
import re
import time
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from extensions import db
from models import SecurityFinding, SecurityScan
from models.base import utcnow
from services.analysis_scanner import (SEVERITY_ORDER, UnsafeTarget, normalize_target,
    request_cancel, safe_scan_file, submit_scan)
from services.scanner import file_type_matches
from services.security_log import log_event

bp = Blueprint("security_center", __name__)
FILE_TYPES = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip", ".7z"}


def _owned(scan_id):
    return SecurityScan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()


def _payload(scan):
    summary = json.loads(scan.summary_json or "{}")
    return {"id": scan.id, "scan_type": scan.scan_type, "target": scan.target, "status": scan.status,
            "progress": scan.progress, "risk_score": scan.risk_score, "risk_level": scan.risk_level,
            "error": scan.error, "summary": summary,
            "report_url": url_for("security_center.json_report", scan_id=scan.id),
            "detail_url": url_for("security_center.detail", scan_id=scan.id)}


def _json_request():
    return request.accept_mimetypes.best == "application/json" or request.headers.get("X-Requested-With") == "XMLHttpRequest"


def _error(message, status=400):
    if _json_request():
        return jsonify(error=message), status
    from flask import flash
    flash(message, "warning")
    return redirect(url_for("security_center.page"))


def _create(scan_type, target, *, config=None, authorized=False, consent=False):
    active = SecurityScan.query.filter_by(user_id=current_user.id).filter(SecurityScan.status.in_(("queued", "running"))).count()
    if active >= 2:
        return None, (jsonify(error="You already have two scans queued or running."), 429)
    scan_config = dict(config or {})
    app_host = urllib.parse.urlsplit("//" + request.host).hostname
    if app_host:
        blocked = set(scan_config.get("blocked_hosts", []))
        blocked.add(app_host.lower().rstrip("."))
        scan_config["blocked_hosts"] = sorted(blocked)
    row = SecurityScan(user_id=current_user.id, scan_type=scan_type, target=target[:2048], status="queued",
                       authorized=authorized, consent_reputation=consent,
                       config_json=json.dumps(scan_config, ensure_ascii=True))
    db.session.add(row)
    db.session.commit()
    log_event("security_scan_queued", "info", user=current_user,
              detail=f"scan_id={row.id} scan_type={scan_type} authorized={bool(authorized)}")
    if not submit_scan(current_app._get_current_object(), row.id, (config or {}).get("temp_path")):
        row.status, row.error, row.completed_at = "failed", "Scanner queue is full; retry later.", utcnow()
        db.session.commit()
        return None, (jsonify(error=row.error), 503)
    return row, None


@bp.get("/security-center")
@login_required
def page():
    rows = SecurityScan.query.filter_by(user_id=current_user.id).order_by(SecurityScan.id.desc()).limit(100).all()
    counts = {key: sum(row.status == key for row in rows) for key in ("completed", "partial", "failed", "queued", "running", "cancelled")}
    by_severity = {severity: SecurityFinding.query.join(SecurityScan).filter(
        SecurityScan.user_id == current_user.id, SecurityFinding.severity == severity).count() for severity in SEVERITY_ORDER}
    by_category = dict(db.session.query(SecurityFinding.category, db.func.count(SecurityFinding.id))
                       .join(SecurityScan).filter(SecurityScan.user_id == current_user.id)
                       .group_by(SecurityFinding.category).all())
    # Trend rows are counts from persisted scans, grouped by UTC calendar date.
    cutoff = utcnow() - timedelta(days=13)
    recent = SecurityScan.query.filter_by(user_id=current_user.id).filter(SecurityScan.created_at >= cutoff).all()
    trend = {}
    for scan in recent:
        day = scan.created_at.date().isoformat()
        bucket = trend.setdefault(day, {"scans": 0, "high_risk": 0})
        bucket["scans"] += 1
        bucket["high_risk"] += scan.risk_level in ("critical", "high")
    scans_for_charts = SecurityScan.query.filter_by(user_id=current_user.id).all()
    file_outcomes = {name: sum(s.scan_type == "file" and s.status == name for s in scans_for_charts)
                     for name in ("completed", "partial", "failed", "cancelled")}
    reputation_outcomes = {}
    header_checks = {"present": 0, "missing": 0}
    for scan in scans_for_charts:
        summary = json.loads(scan.summary_json or "{}")
        reputation = summary.get("reputation")
        if scan.scan_type == "url" and reputation:
            label = reputation.get("status", "unknown")
            reputation_outcomes[label] = reputation_outcomes.get(label, 0) + 1
        for check in summary.get("checks", []):
            if check.get("check") in ("Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options",
                                       "Referrer-Policy", "Permissions-Policy", "Framing protection"):
                key = "present" if check.get("status") in ("present", "verified") else "missing"
                header_checks[key] += 1
    scan_modes = {row.id: json.loads(row.config_json or "{}").get("scan_mode", "comprehensive") for row in rows if row.scan_type == "website"}
    return render_template("security_center.html", rows=rows, scan_modes=scan_modes, counts=counts, by_severity=by_severity,
                           by_category=by_category, trend=sorted(trend.items()),
                           trend_max=max([1] + [values["scans"] for _, values in trend.items()]),
                           file_outcomes=file_outcomes, reputation_outcomes=reputation_outcomes,
                           header_checks=header_checks,
                           google_configured=bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")),
                           virustotal_configured=bool(os.environ.get("VIRUSTOTAL_API_KEY")),
                           max_mb=current_app.config["MAX_SCAN_BYTES"] // (1024 * 1024))


@bp.post("/security-center/scan/file")
@login_required
def scan_file():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        return _error("Choose a file to scan.")
    filename = secure_filename(upload.filename)[:255]
    suffix = Path(filename).suffix.lower()
    if not filename or suffix not in FILE_TYPES:
        return _error("Unsupported file type. Choose a supported document, image, text file, or archive.")
    try:
        path, size, digest, mime = safe_scan_file(upload, filename, current_app.config["MAX_SCAN_BYTES"],
                                                   Path(current_app.config["INSTANCE_DIR"]) / "scanner-tmp")
    except ValueError as exc:
        return _error(str(exc), 413)
    if not file_type_matches(path, suffix):
        Path(path).unlink(missing_ok=True)
        return _error("File contents do not match the filename type; no scan was claimed.")
    config = {"sha256": digest, "size_bytes": size, "mime_type": mime,
              "scanner_timeout_seconds": min(int(current_app.config["CLAMSCAN_TIMEOUT"]),
                                              int(current_app.config.get("SECURITY_SCAN_TIMEOUT_SECONDS", 30))),
              "share_file_hash": request.form.get("share_file_hash") == "on", "temp_path": path}
    row, error = _create("file", filename, config=config)
    if error:
        Path(path).unlink(missing_ok=True)
        return error
    return (jsonify(_payload(row)), 202) if _json_request() else redirect(url_for("security_center.detail", scan_id=row.id))


@bp.post("/security-center/scan/url")
@login_required
def scan_url():
    try:
        target, _, _, _ = normalize_target(request.form.get("url", ""))
    except UnsafeTarget as exc:
        return _error(str(exc))
    row, error = _create("url", target, consent=request.form.get("share_reputation") == "on")
    if error:
        return error
    return (jsonify(_payload(row)), 202) if _json_request() else redirect(url_for("security_center.detail", scan_id=row.id))


@bp.post("/security-center/scan/website")
@login_required
def scan_website():
    if request.form.get("authorized") != "on":
        return _error("Confirm that you own this website or have permission to assess it.")
    try:
        target, _, _, _ = normalize_target(request.form.get("url", ""))
    except UnsafeTarget as exc:
        return _error(str(exc))
    scan_mode = request.form.get("scan_mode", "comprehensive")
    if scan_mode not in ("quick", "comprehensive"):
        return _error("Choose Quick Scan or Comprehensive Scan.")
    row, error = _create("website", target, config={"scan_mode": scan_mode}, authorized=True)
    if error:
        return error
    return (jsonify(_payload(row)), 202) if _json_request() else redirect(url_for("security_center.detail", scan_id=row.id))


@bp.get("/security-center/api/scans/<int:scan_id>")
@login_required
def scan_status(scan_id):
    return jsonify(_payload(_owned(scan_id)))


@bp.post("/security-center/api/scans/<int:scan_id>/cancel")
@login_required
def cancel_scan(scan_id):
    row = _owned(scan_id)
    if row.status not in ("queued", "running"):
        return jsonify(error="This scan is already finished.", status=row.status), 409
    row.cancel_requested = True
    db.session.commit()
    request_cancel(row.id)
    log_event("security_scan_cancel_requested", "warning", user=current_user, detail=f"scan_id={row.id}")
    return jsonify(status="cancelling")


@bp.get("/security-center/<int:scan_id>")
@login_required
def detail(scan_id):
    row = _owned(scan_id)
    severity_order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    findings = sorted(row.findings, key=lambda f: (severity_order.get(f.severity, 99), f.id))
    finding_guidance = {finding.id: {"remediation": json.loads(finding.remediation_steps_json or "[]"),
                                    "verification": json.loads(finding.verification_steps_json or "[]")}
                        for finding in findings}
    return render_template("security_scan_detail.html", scan=row,
                           summary=json.loads(row.summary_json or "{}"), findings=findings,
                           finding_guidance=finding_guidance)


@bp.get("/security-center/<int:scan_id>/report.json")
@login_required
def json_report(scan_id):
    row = _owned(scan_id)
    report = _report_data(row)
    log_event("security_scan_report_exported", "info", user=current_user,
              detail=f"scan_id={row.id} format=json")
    response = jsonify(report)
    response.headers["Content-Disposition"] = f'attachment; filename="cns-scan-{row.id}.json"'
    response.headers["Cache-Control"] = "no-store"
    return response


def _report_data(row):
    summary = json.loads(row.summary_json or "{}")
    severity_order = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    findings = sorted(row.findings, key=lambda f: (severity_order.get(f.severity, 99), f.id))
    return {"product": "CNS Security Lab", "report_id": f"CNS-SCAN-{row.id:08d}",
            "scan_id": row.id, "scan_type": row.scan_type, "target": row.target,
            "created_at_utc": row.created_at.isoformat() + "Z",
            "started_at_utc": row.started_at.isoformat() + "Z" if row.started_at else None,
            "completed_at_utc": row.completed_at.isoformat() + "Z" if row.completed_at else None,
            "duration_ms": row.duration_ms, "status": row.status, "risk": {"score": row.risk_score, "level": row.risk_level,
            "method": summary.get("risk_method", "No score available for an incomplete scan.")},
            "authorization_confirmed": row.authorized, "configuration": json.loads(row.config_json or "{}") | {"temp_path": None},
            "summary": summary, "scan_error": row.error,
            "findings": [{"id": f"F-{row.id:06d}-{finding.id:06d}", "title": finding.title,
                "severity": finding.severity, "confidence": finding.confidence, "category": finding.category,
                "affected": finding.affected, "evidence": finding.evidence, "explanation": finding.explanation,
                "impact": finding.impact, "remediation": finding.remediation, "source": finding.source,
                "remediation_steps": json.loads(finding.remediation_steps_json or "[]"),
                "verification_steps": json.loads(finding.verification_steps_json or "[]"),
                "verification": finding.verification, "timestamp_utc": finding.created_at.isoformat() + "Z"}
                for finding in findings]}


@bp.get("/security-center/<int:scan_id>/report.csv")
@login_required
def csv_report(scan_id):
    row = _owned(scan_id)
    report = _report_data(row)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["finding_id", "title", "severity", "confidence", "category", "affected", "evidence",
                     "explanation", "impact", "remediation", "remediation_steps", "verification_steps", "source", "verification"])
    for finding in report["findings"]:
        def csv_value(value):
            value = str(value if value is not None else "")
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value
        writer.writerow([finding["id"], finding["title"], finding["severity"], finding["confidence"],
            *[csv_value(finding[key]) for key in ("category", "affected", "evidence", "explanation", "impact", "remediation")],
            csv_value("; ".join(finding["remediation_steps"])), csv_value("; ".join(finding["verification_steps"])),
            csv_value(finding["source"]), csv_value(finding["verification"])])
    log_event("security_scan_report_exported", "info", user=current_user,
              detail=f"scan_id={row.id} format=csv")
    response = current_app.response_class("\ufeff" + output.getvalue(), mimetype="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = f'attachment; filename="cns-scan-{row.id}.csv"'
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/security-center/<int:scan_id>/report.pdf")
@login_required
def pdf_report(scan_id):
    row = _owned(scan_id)
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    except ImportError:
        abort(503, description="PDF reports require reportlab. Install project dependencies and retry.")
    data = _report_data(row)
    output = io.BytesIO()
    crimson, cream, charcoal, beige = colors.HexColor("#B52A32"), colors.HexColor("#F7F0E7"), colors.HexColor("#292322"), colors.HexColor("#E8C9AC")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CNSCover", parent=styles["Title"], textColor=crimson, fontName="Helvetica-Bold", fontSize=26, leading=31, alignment=TA_CENTER, spaceAfter=16))
    styles.add(ParagraphStyle(name="CNSHead", parent=styles["Heading2"], textColor=crimson, fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="CNSBody", parent=styles["BodyText"], textColor=charcoal, leading=14, spaceAfter=6, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CNSSmall", parent=styles["BodyText"], textColor=charcoal, fontSize=8, leading=10, wordWrap="CJK"))
    safe = lambda value: escape(str(value if value is not None else ""))
    story = [Spacer(1, 1.1*inch), Paragraph("CNS SECURITY LAB", styles["CNSCover"]),
             Paragraph("Malware &amp; Website Security Analysis Report", styles["Heading1"]), Spacer(1, .25*inch)]
    cover = [["Report ID", data["report_id"]], ["Scan type", row.scan_type.title()], ["Target", row.target],
             ["Created (UTC)", data["created_at_utc"]], ["Status", row.status.upper()],
             ["Risk", f"{row.risk_level.upper()} · score {row.risk_score if row.risk_score is not None else 'unavailable'}"]]
    table = Table([[Paragraph(safe(a), styles["CNSBody"]), Paragraph(safe(b), styles["CNSBody"])] for a,b in cover], colWidths=[1.5*inch, 4.8*inch])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),cream),("TEXTCOLOR",(0,0),(0,-1),crimson),("GRID",(0,0),(-1,-1),.5,beige),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8)]))
    story.extend([table, Spacer(1,.3*inch), Paragraph("Assessment is limited to the checks and evidence listed in this report. No scan can establish that a file or website is completely safe.", styles["CNSBody"]), PageBreak()])
    story.append(Paragraph("Executive summary", styles["CNSHead"]))
    story.append(Paragraph(safe(f"This {row.scan_type} scan finished with status {row.status} and a {row.risk_level} risk classification. The rating is based on the highest-severity finding; confidence is recorded separately."), styles["CNSBody"]))
    story.append(Paragraph("Risk scoring method", styles["CNSHead"]))
    story.append(Paragraph(safe(data["risk"]["method"]), styles["CNSBody"]))
    story.append(Paragraph("Scope and authorization", styles["CNSHead"]))
    story.append(Paragraph(safe(f"Target: {row.target}. Website authorization confirmed: {'yes' if row.authorized else 'not applicable'}. The scanner made bounded, non-destructive requests and did not crawl arbitrary domains."), styles["CNSBody"]))
    story.append(Paragraph("Scanners and limitations", styles["CNSHead"]))
    summary = data["summary"]
    story.append(Paragraph(safe("Engines: " + ", ".join(summary.get("engines", []))), styles["CNSBody"]))
    for limitation in summary.get("limitations", []):
        story.append(Paragraph("• " + safe(limitation), styles["CNSBody"]))
    if row.error:
        story.append(Paragraph("Scan errors", styles["CNSHead"]))
        story.append(Paragraph(safe(row.error), styles["CNSBody"]))
    story.append(Paragraph("Finding summary", styles["CNSHead"]))
    counts = summary.get("severity_counts", {})
    story.append(Paragraph(safe(" · ".join(f"{s.title()}: {counts.get(s,0)}" for s in SEVERITY_ORDER)), styles["CNSBody"]))
    if row.scan_type == "file":
        story.append(Paragraph("File analysis", styles["CNSHead"]))
        story.append(Paragraph(safe(f"SHA-256: {json.loads(row.config_json or '{}').get('sha256','')}. Size: {json.loads(row.config_json or '{}').get('size_bytes','')} bytes. MIME: {json.loads(row.config_json or '{}').get('mime_type','unknown')}."), styles["CNSSmall"]))
    for key, title in (("scan_mode", "Scan mode"), ("checks_run", "Checks executed"),
                       ("checks_not_assessed", "Checks not assessed"), ("probe_paths", "Same-host scope"),
                       ("reputation", "Reputation results"), ("redirect_chain", "Redirect chain"),
                       ("checks", "Executed website checks"), ("http_status", "HTTP response status")):
        if summary.get(key):
            story.append(Paragraph(title, styles["CNSHead"]))
            value = summary[key]
            if isinstance(value, list):
                for entry in value:
                    story.append(Paragraph(safe(json.dumps(entry, sort_keys=True)), styles["CNSSmall"]))
            elif isinstance(value, dict):
                story.append(Paragraph(safe(json.dumps(value, sort_keys=True)), styles["CNSSmall"]))
            else:
                story.append(Paragraph(safe(value), styles["CNSSmall"]))
    story.append(Paragraph("Detailed findings", styles["CNSHead"]))
    if not row.findings:
        story.append(Paragraph("No findings were stored. This is not a guarantee that the target is safe.", styles["CNSBody"]))
    for finding in row.findings:
        title = f"F-{row.id:06d}-{finding.id:06d} · {finding.title} · {finding.severity.upper()} ({finding.confidence} confidence)"
        block = [Paragraph(safe(title), styles["Heading3"])]
        for label, value in (("Affected",finding.affected),("Evidence",finding.evidence),("Why it matters",finding.explanation),
                             ("Potential impact",finding.impact),("Remediation",finding.remediation),
                             ("Source / verification",f"{finding.source} / {finding.verification}")):
            block.append(Paragraph(f"<b>{safe(label)}:</b> {safe(value)}", styles["CNSSmall"]))
        for label, items in (("Prioritized remediation steps", json.loads(finding.remediation_steps_json or "[]")),
                             ("Verification steps", json.loads(finding.verification_steps_json or "[]"))):
            block.append(Paragraph(f"<b>{safe(label)}:</b> {safe(' · '.join(items))}", styles["CNSSmall"]))
        block.append(Spacer(1,8))
        story.append(KeepTogether(block))
    story.extend([Spacer(1,12), Paragraph("Final assessment and disclaimer", styles["CNSHead"]),
                  Paragraph("This report records observed evidence from a bounded scan. Potential findings are not proof of exploitability; absence of findings does not prove security. Use only on assets you own or are authorized to assess.", styles["CNSBody"])])
    def page_decor(canvas, doc):
        canvas.saveState(); w,h=letter
        canvas.setFillColor(crimson); canvas.rect(0,h-9,w,9,fill=1,stroke=0)
        canvas.setFont("Helvetica",8); canvas.setFillColor(charcoal)
        canvas.drawString(.65*inch,.45*inch,"CNS Security Lab · Confidential scan report")
        canvas.drawRightString(w-.65*inch,.45*inch,f"Page {doc.page}")
        canvas.restoreState()
    SimpleDocTemplate(output, pagesize=letter, rightMargin=.65*inch,leftMargin=.65*inch,topMargin=.75*inch,bottomMargin=.7*inch,
                      title=f"CNS Scan Report {row.id}", author="CNS Security Lab").build(story,onFirstPage=page_decor,onLaterPages=page_decor)
    log_event("security_scan_report_exported", "info", user=current_user,
              detail=f"scan_id={row.id} format=pdf")
    output.seek(0)
    return send_file(output, mimetype="application/pdf", as_attachment=True,
                     download_name=f"cns-scan-{row.id}.pdf", max_age=0)

