"""IOC (Indicators of Compromise) extraction."""
import re

from ..models import Session, Alert, Evidence

DNS_NOTE_RE = re.compile(r"DNS query:\s*(\S+)")
HTTP_NOTE_RE = re.compile(r"HTTP \w+ (\S+)")


def extract_iocs(evidence_id):
    alerted_ips = set()
    for alert in Alert.query.filter_by(evidence_id=evidence_id).all():
        if alert.dst_ip:
            alerted_ips.add(alert.dst_ip)

    domains = set()
    for sess in Session.query.filter_by(evidence_id=evidence_id).all():
        if not sess.summary:
            continue
        for note in sess.summary.split(";"):
            note = note.strip()
            m = DNS_NOTE_RE.search(note)
            if m:
                domains.add(m.group(1))
                continue
            m = HTTP_NOTE_RE.search(note)
            if m:
                target = m.group(1)
                host = target.split("/")[0]
                if "." in host:
                    domains.add(host)

    evidence = Evidence.query.get(evidence_id)
    file_hashes = [evidence.sha256] if evidence else []

    return {
        "alerted_ips": sorted(alerted_ips),
        "domains": sorted(domains),
        "file_hashes": file_hashes,
    }


def format_iocs_as_text(evidence, iocs: dict) -> str:
    lines = [
        f"IOC Export — {evidence.original_filename}",
        f"Case ID: {evidence.case_id}  Evidence ID: {evidence.id}",
        f"Evidence SHA-256: {evidence.sha256}",
        "=" * 60,
        "",
        f"Suspicious IPs ({len(iocs['alerted_ips'])}):",
    ]
    if iocs["alerted_ips"]:
        lines.extend(f"  {ip}" for ip in iocs["alerted_ips"])
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append(f"Domains observed ({len(iocs['domains'])}):")
    if iocs["domains"]:
        lines.extend(f"  {d}" for d in iocs["domains"])
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("File hashes (SHA-256):")
    lines.extend(f"  {h}" for h in iocs["file_hashes"])

    return "\n".join(lines) + "\n"