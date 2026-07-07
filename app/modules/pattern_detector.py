"""
Suspicious pattern detection.

Three detectors:

1. Beaconing: a host repeatedly contacting the same external destination
   (ip, port) at roughly regular intervals — classic C2 malware behavior.
2. Large transfer / possible exfiltration: any single session moving an
   unusually large amount of data, especially outbound to a non-private IP.
3. Port scan: one host touching many distinct ports on the same target
   within a short window — classic reconnaissance behavior.
"""
import statistics
from ipaddress import ip_address

from ..models import db, Session, Alert, utcnow

BEACON_MIN_OCCURRENCES = 3
BEACON_MAX_INTERVAL_STDDEV_RATIO = 0.3
LARGE_TRANSFER_BYTES = 50_000

PORT_SCAN_MIN_DISTINCT_PORTS = 5
PORT_SCAN_WINDOW_SECONDS = 60


def _is_private(ip_str: str) -> bool:
    try:
        return ip_address(ip_str).is_private
    except ValueError:
        return False


def detect_beaconing(evidence_id):
    sessions = Session.query.filter_by(evidence_id=evidence_id).all()

    groups = {}
    for s in sessions:
        if s.start_time is None:
            continue
        key = (s.src_ip, s.dst_ip, s.dst_port)
        groups.setdefault(key, []).append(s)

    alerts = []
    for (src_ip, dst_ip, dst_port), group in groups.items():
        if len(group) < BEACON_MIN_OCCURRENCES:
            continue

        times = sorted(s.start_time for s in group)
        intervals = [
            (times[i + 1] - times[i]).total_seconds()
            for i in range(len(times) - 1)
        ]
        if not intervals or any(i <= 0 for i in intervals):
            continue

        mean_interval = statistics.mean(intervals)
        stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        ratio = (stddev / mean_interval) if mean_interval else 1

        if ratio <= BEACON_MAX_INTERVAL_STDDEV_RATIO:
            alerts.append(Alert(
                evidence_id=evidence_id,
                alert_type="beaconing",
                severity="high",
                title=f"Possible beaconing: {src_ip} -> {dst_ip}:{dst_port}",
                description=(
                    f"{src_ip} contacted {dst_ip}:{dst_port} {len(group)} times "
                    f"at ~{mean_interval:.1f}s intervals (stddev {stddev:.1f}s). "
                    "Regular, repeated contact to the same destination is a "
                    "classic sign of malware command-and-control (C2) beaconing."
                ),
                src_ip=src_ip, dst_ip=dst_ip,
                detected_at=utcnow(),
                evidence_timestamp=times[0],
            ))

    return alerts


def detect_large_transfers(evidence_id):
    sessions = Session.query.filter_by(evidence_id=evidence_id).all()

    alerts = []
    for s in sessions:
        if s.byte_count is None or s.byte_count < LARGE_TRANSFER_BYTES:
            continue

        dst_is_external = not _is_private(s.dst_ip)
        severity = "critical" if dst_is_external else "medium"

        alerts.append(Alert(
            evidence_id=evidence_id,
            alert_type="large_transfer",
            severity=severity,
            title=f"Large data transfer: {s.src_ip} -> {s.dst_ip}:{s.dst_port} ({s.byte_count} bytes)",
            description=(
                f"Session {s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port} "
                f"moved {s.byte_count} bytes over {s.protocol}"
                f"{'/' + s.app_protocol if s.app_protocol else ''}. "
                + ("Destination is an external/public IP, which raises the "
                   "possibility of data exfiltration."
                   if dst_is_external else
                   "Destination is on the local network, but the volume is still worth reviewing.")
            ),
            src_ip=s.src_ip, dst_ip=s.dst_ip,
            detected_at=utcnow(),
            evidence_timestamp=s.start_time,
        ))

    return alerts


def detect_port_scans(evidence_id):
    sessions = Session.query.filter_by(evidence_id=evidence_id).all()

    groups = {}
    for s in sessions:
        if s.start_time is None or s.dst_port is None:
            continue
        key = (s.src_ip, s.dst_ip)
        groups.setdefault(key, []).append((s.dst_port, s.start_time))

    alerts = []
    for (src_ip, dst_ip), touches in groups.items():
        touches.sort(key=lambda t: t[1])

        for i in range(len(touches)):
            window_start = touches[i][1]
            window_ports = set()
            for port, ts in touches[i:]:
                if (ts - window_start).total_seconds() > PORT_SCAN_WINDOW_SECONDS:
                    break
                window_ports.add(port)

            if len(window_ports) >= PORT_SCAN_MIN_DISTINCT_PORTS:
                alerts.append(Alert(
                    evidence_id=evidence_id,
                    alert_type="port_scan",
                    severity="high",
                    title=f"Possible port scan: {src_ip} -> {dst_ip}",
                    description=(
                        f"{src_ip} touched {len(window_ports)} distinct ports on "
                        f"{dst_ip} within {PORT_SCAN_WINDOW_SECONDS} seconds "
                        f"(ports: {sorted(window_ports)[:15]}"
                        f"{'...' if len(window_ports) > 15 else ''}). "
                        "Rapid connections across many ports on one host is a "
                        "classic sign of network reconnaissance/port scanning."
                    ),
                    src_ip=src_ip, dst_ip=dst_ip,
                    detected_at=utcnow(),
                    evidence_timestamp=window_start,
                ))
                break

    return alerts


def run_all_detectors(evidence_id):
    Alert.query.filter_by(evidence_id=evidence_id).delete()

    new_alerts = []
    new_alerts.extend(detect_beaconing(evidence_id))
    new_alerts.extend(detect_large_transfers(evidence_id))
    new_alerts.extend(detect_port_scans(evidence_id))

    for alert in new_alerts:
        db.session.add(alert)
    db.session.commit()

    return new_alerts