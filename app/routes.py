import os
import uuid
from flask import (Blueprint, render_template, request, redirect, url_for,
                    flash, current_app, jsonify, send_from_directory)
from werkzeug.utils import secure_filename

from .models import db, Case, Evidence, CustodyLog
from .modules.hashing import hash_file_multi

bp = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@bp.route("/")
def index():
    from .models import Evidence, Alert

    cases = Case.query.order_by(Case.created_at.desc()).all()

    total_evidence = Evidence.query.count()
    total_packets = db.session.query(db.func.sum(Evidence.packet_count)).scalar() or 0
    all_alerts = Alert.query.all()
    alert_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in all_alerts:
        if a.severity in alert_counts:
            alert_counts[a.severity] += 1

    stats = {
        "total_cases": len(cases),
        "total_evidence": total_evidence,
        "total_packets": total_packets,
        "total_alerts": len(all_alerts),
        "critical_alerts": alert_counts["critical"],
        "high_alerts": alert_counts["high"],
    }

    return render_template("index.html", cases=cases, stats=stats)

@bp.route("/case/new", methods=["GET", "POST"])
def new_case():
    if request.method == "POST":
        case = Case(
            name=request.form["name"],
            description=request.form.get("description", ""),
            investigator=request.form.get("investigator", ""),
            suspect=request.form.get("suspect", ""),
            affected_party=request.form.get("affected_party", ""),
        )
        db.session.add(case)
        db.session.commit()
        flash(f"Case '{case.name}' created.", "success")
        return redirect(url_for("main.view_case", case_id=case.id))
    return render_template("new_case.html")


@bp.route("/case/<int:case_id>")
def view_case(case_id):
    case = Case.query.get_or_404(case_id)
    return render_template("case.html", case=case)

@bp.route("/case/<int:case_id>/edit", methods=["GET", "POST"])
def edit_case(case_id):
    case = Case.query.get_or_404(case_id)

    if request.method == "POST":
        case.name = request.form["name"]
        case.description = request.form.get("description", "")
        case.investigator = request.form.get("investigator", "")
        case.suspect = request.form.get("suspect", "")
        case.affected_party = request.form.get("affected_party", "")
        case.status = request.form.get("status", "open")
        db.session.commit()
        flash(f"Case '{case.name}' updated.", "success")
        return redirect(url_for("main.view_case", case_id=case.id))

    return render_template("edit_case.html", case=case)


@bp.route("/case/<int:case_id>/delete", methods=["POST"])
def delete_case(case_id):
    case = Case.query.get_or_404(case_id)
    name = case.name
    db.session.delete(case)
    db.session.commit()
    flash(f"Case '{name}' and all its evidence permanently deleted.", "success")
    return redirect(url_for("main.index"))


@bp.route("/evidence/<int:evidence_id>/delete", methods=["POST"])
def delete_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    case_id = evidence.case_id
    filename = evidence.original_filename

    if os.path.exists(evidence.stored_path):
        try:
            os.remove(evidence.stored_path)
        except OSError:
            pass
    for ef in evidence.extracted_files:
        if os.path.exists(ef.stored_path):
            try:
                os.remove(ef.stored_path)
            except OSError:
                pass

    db.session.delete(evidence)
    db.session.commit()
    flash(f"Evidence '{filename}' permanently deleted.", "success")
    return redirect(url_for("main.view_case", case_id=case_id))
@bp.route("/case/<int:case_id>/upload", methods=["POST"])
def upload_evidence(case_id):
    case = Case.query.get_or_404(case_id)

    if "pcap_file" not in request.files:
        flash("No file part in request.", "error")
        return redirect(url_for("main.view_case", case_id=case.id))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("main.view_case", case_id=case.id))

    if not allowed_file(file.filename):
        flash("Only .pcap, .pcapng, .cap files are accepted.", "error")
        return redirect(url_for("main.view_case", case_id=case.id))

    original_name = secure_filename(file.filename)
    stored_name = f"{uuid.uuid4().hex}_{original_name}"
    stored_path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored_name)
    file.save(stored_path)

    hashes = hash_file_multi(stored_path)
    file_size = os.path.getsize(stored_path)

    evidence = Evidence(
        case_id=case.id,
        original_filename=original_name,
        stored_path=stored_path,
        file_size=file_size,
        sha256=hashes["sha256"],
        md5=hashes["md5"],
        uploaded_by=request.form.get("investigator", case.investigator or "unknown"),
        analysis_status="pending",
    )
    db.session.add(evidence)
    db.session.commit()

    CustodyLog.append(
        evidence_id=evidence.id,
        action="uploaded",
        actor=evidence.uploaded_by,
        details=f"Uploaded '{original_name}' ({file_size} bytes), SHA-256={hashes['sha256']}",
    )

    flash(f"Evidence uploaded and hashed (SHA-256: {hashes['sha256'][:16]}...).", "success")
    return redirect(url_for("main.view_evidence", evidence_id=evidence.id))


@bp.route("/evidence/<int:evidence_id>")
def view_evidence(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)

    CustodyLog.append(
        evidence_id=evidence.id,
        action="viewed",
        actor=request.args.get("actor", "unknown"),
        details="Evidence detail page accessed.",
    )

    return render_template("evidence.html", evidence=evidence)


@bp.route("/evidence/<int:evidence_id>/custody")
def view_custody_log(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    is_valid, broken_at = CustodyLog.verify_chain(evidence.id)
    return render_template(
        "custody_log.html",
        evidence=evidence,
        logs=evidence.custody_logs,
        is_valid=is_valid,
        broken_at=broken_at,
    )


@bp.route("/evidence/<int:evidence_id>/analyze", methods=["POST"])
def analyze_evidence(evidence_id):
    from .modules.pcap_analyzer import analyze_pcap

    evidence = Evidence.query.get_or_404(evidence_id)

    if not os.path.exists(evidence.stored_path):
        flash("Evidence file missing from disk — cannot analyze.", "error")
        return redirect(url_for("main.view_evidence", evidence_id=evidence.id))

    try:
        analyzer = analyze_pcap(evidence)
        CustodyLog.append(
            evidence_id=evidence.id,
            action="analyzed",
            actor=request.form.get("actor", "unknown"),
            details=(f"Parsed {analyzer.packet_count} packets into "
                     f"{len(analyzer.sessions)} sessions."),
        )
        flash(f"Analysis complete: {analyzer.packet_count} packets, "
              f"{len(analyzer.sessions)} sessions found.", "success")
    except Exception as exc:
        CustodyLog.append(
            evidence_id=evidence.id,
            action="analysis_failed",
            actor=request.form.get("actor", "unknown"),
            details=str(exc),
        )
        flash(f"Analysis failed: {exc}", "error")

    return redirect(url_for("main.view_evidence", evidence_id=evidence.id))


@bp.route("/evidence/<int:evidence_id>/detect", methods=["POST"])
def detect_patterns(evidence_id):
    from .modules.pattern_detector import run_all_detectors

    evidence = Evidence.query.get_or_404(evidence_id)

    if evidence.analysis_status != "completed":
        flash("Run analysis first before detecting patterns.", "error")
        return redirect(url_for("main.view_evidence", evidence_id=evidence.id))

    alerts = run_all_detectors(evidence.id)

    CustodyLog.append(
        evidence_id=evidence.id,
        action="pattern_detection_run",
        actor=request.form.get("actor", "unknown"),
        details=f"Detected {len(alerts)} suspicious pattern(s).",
    )

    if alerts:
        flash(f"⚠️ {len(alerts)} suspicious pattern(s) detected.", "error")
    else:
        flash("No suspicious patterns detected.", "success")

    return redirect(url_for("main.view_evidence", evidence_id=evidence.id))


@bp.route("/evidence/<int:evidence_id>/timeline")
def view_timeline(evidence_id):
    evidence = Evidence.query.get_or_404(evidence_id)
    sessions = sorted(
        [s for s in evidence.sessions if s.start_time is not None],
        key=lambda s: s.start_time
    )
    return render_template("timeline.html", evidence=evidence, sessions=sessions)


@bp.route("/evidence/<int:evidence_id>/extract", methods=["POST"])
def extract_files(evidence_id):
    from .modules.file_extractor import extract_and_persist

    evidence = Evidence.query.get_or_404(evidence_id)

    if evidence.analysis_status != "completed":
        flash("Run analysis first before extracting files.", "error")
        return redirect(url_for("main.view_evidence", evidence_id=evidence.id))

    try:
        created = extract_and_persist(evidence, current_app.config["EXTRACTED_FOLDER"])
        CustodyLog.append(
            evidence_id=evidence.id,
            action="files_extracted",
            actor=request.form.get("actor", "unknown"),
            details=f"Extracted {len(created)} file(s) from traffic.",
        )
        if created:
            flash(f"Extracted {len(created)} file(s).", "success")
        else:
            flash("No files found in traffic (HTTP only supported currently).", "success")
    except Exception as exc:
        flash(f"File extraction failed: {exc}", "error")

    return redirect(url_for("main.view_evidence", evidence_id=evidence.id))


@bp.route("/extracted/<int:file_id>/vt_check", methods=["POST"])
def vt_check_file(file_id):
    from .modules.vt_check import check_extracted_file, VTNotConfigured, VTLookupError
    from .models import ExtractedFile

    ef = ExtractedFile.query.get_or_404(file_id)
    api_key = current_app.config.get("VT_API_KEY", "")

    try:
        check_extracted_file(ef, api_key)
        db.session.commit()
        CustodyLog.append(
            evidence_id=ef.evidence_id,
            action="vt_checked",
            actor=request.form.get("actor", "unknown"),
            details=(f"VirusTotal check for {ef.filename}: "
                     f"{ef.vt_malicious_count}/{ef.vt_total_engines} engines flagged it."
                     if ef.vt_total_engines else
                     f"VirusTotal has no record of {ef.filename}."),
        )
        flash(f"VirusTotal check complete for {ef.filename}.", "success")
    except VTNotConfigured:
        flash("VirusTotal is not configured. Set the VT_API_KEY environment "
              "variable with a free API key from virustotal.com to enable this.", "error")
    except VTLookupError as exc:
        flash(f"VirusTotal check failed: {exc}", "error")

    return redirect(url_for("main.view_evidence", evidence_id=ef.evidence_id))


@bp.route("/evidence/<int:evidence_id>/ioc")
def export_iocs(evidence_id):
    from .modules.ioc_export import extract_iocs, format_iocs_as_text
    from flask import Response

    evidence = Evidence.query.get_or_404(evidence_id)
    iocs = extract_iocs(evidence.id)
    text = format_iocs_as_text(evidence, iocs)

    CustodyLog.append(
        evidence_id=evidence.id,
        action="ioc_exported",
        actor=request.args.get("actor", "unknown"),
        details=(f"Exported {len(iocs['alerted_ips'])} IP(s), "
                 f"{len(iocs['domains'])} domain(s)."),
    )

    return Response(
        text, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=ioc_evidence_{evidence.id}.txt"}
    )


@bp.route("/evidence/<int:evidence_id>/report")
def generate_report(evidence_id):
    from .modules.report_generator import generate_report, report_path_for

    evidence = Evidence.query.get_or_404(evidence_id)
    output_path = report_path_for(evidence, current_app.config["REPORTS_FOLDER"])
    generate_report(evidence, output_path)

    CustodyLog.append(
        evidence_id=evidence.id,
        action="report_generated",
        actor=request.args.get("actor", "unknown"),
        details="PDF report generated.",
    )

    return send_from_directory(
        current_app.config["REPORTS_FOLDER"],
        os.path.basename(output_path),
        as_attachment=True,
        download_name=f"forensic_report_{evidence.original_filename}.pdf",
    )


@bp.route("/evidence/<int:evidence_id>/verify")
def verify_integrity(evidence_id):
    """Recompute the file hash right now and compare to what was recorded at upload."""
    evidence = Evidence.query.get_or_404(evidence_id)
    from .modules.hashing import hash_file

    if not os.path.exists(evidence.stored_path):
        return jsonify({"valid": False, "error": "Evidence file missing from disk."}), 404

    current_hash = hash_file(evidence.stored_path, "sha256")
    valid = evidence.verify_integrity(current_hash)

    CustodyLog.append(
        evidence_id=evidence.id,
        action="integrity_check",
        actor=request.args.get("actor", "unknown"),
        details=f"Recomputed SHA-256={current_hash}, match={valid}",
    )

    return jsonify({
        "valid": valid,
        "recorded_sha256": evidence.sha256,
        "current_sha256": current_hash,
    })