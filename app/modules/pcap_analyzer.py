"""
Core PCAP analysis engine.
 
Reads a packet capture and produces per-session (5-tuple flow) summaries
and best-effort application-layer classification, using scapy's streaming
PcapReader so large captures don't get loaded fully into memory.
"""
import re
from datetime import datetime, timezone
 
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
 
from ..models import db, Session, Evidence, ExtractedFile, Alert
 
PORT_APP_MAP = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "TLS", 445: "SMB", 587: "SMTP",
    3389: "RDP", 8080: "HTTP", 8443: "TLS",
}
 
HTTP_METHOD_RE = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT) (\S+) HTTP/")
HTTP_HOST_RE = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)
 
 
def _pkt_time_to_dt(pkt_time) -> datetime:
    return datetime.fromtimestamp(float(pkt_time), tz=timezone.utc).replace(tzinfo=None)
 
 
def _classify_app_protocol(src_port, dst_port):
    return PORT_APP_MAP.get(dst_port) or PORT_APP_MAP.get(src_port) or None
 
 
def _flow_key(ip_a, port_a, ip_b, port_b, proto):
    endpoint_a = (ip_a, port_a)
    endpoint_b = (ip_b, port_b)
    if endpoint_a <= endpoint_b:
        return (endpoint_a, endpoint_b, proto)
    return (endpoint_b, endpoint_a, proto)
 
 
class PcapAnalyzer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.sessions = {}
        self.packet_count = 0
        self.capture_start = None
        self.capture_end = None
 
    def run(self):
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                self.packet_count += 1
                self._process_packet(pkt)
        return self
 
    def _process_packet(self, pkt):
        ts = getattr(pkt, "time", None)
        if ts is not None:
            dt = _pkt_time_to_dt(ts)
            if self.capture_start is None or dt < self.capture_start:
                self.capture_start = dt
            if self.capture_end is None or dt > self.capture_end:
                self.capture_end = dt
        else:
            dt = None
 
        ip_layer = None
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        if ip_layer is None:
            return
 
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        length = len(pkt)
 
        if pkt.haslayer(TCP):
            layer = pkt[TCP]
            proto = "TCP"
            src_port, dst_port = int(layer.sport), int(layer.dport)
        elif pkt.haslayer(UDP):
            layer = pkt[UDP]
            proto = "UDP"
            src_port, dst_port = int(layer.sport), int(layer.dport)
        else:
            proto = ip_layer.name if hasattr(ip_layer, "name") else "IP"
            src_port, dst_port = 0, 0
 
        key = _flow_key(src_ip, src_port, dst_ip, dst_port, proto)
        sess = self.sessions.get(key)
        if sess is None:
            sess = {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": proto,
                "packet_count": 0, "byte_count": 0,
                "start_time": dt, "end_time": dt,
                "app_protocol": _classify_app_protocol(src_port, dst_port),
                "notes": [],
            }
            self.sessions[key] = sess
 
        sess["packet_count"] += 1
        sess["byte_count"] += length
        if dt is not None:
            if sess["start_time"] is None or dt < sess["start_time"]:
                sess["start_time"] = dt
            if sess["end_time"] is None or dt > sess["end_time"]:
                sess["end_time"] = dt
 
        self._inspect_payload(pkt, sess, dst_port, src_port)
 
    def _inspect_payload(self, pkt, sess, dst_port, src_port):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
                note = f"DNS query: {qname}"
                if note not in sess["notes"]:
                    sess["notes"].append(note)
            except Exception:
                pass
 
        if pkt.haslayer(Raw) and (dst_port == 80 or src_port == 80 or
                                   dst_port == 8080 or src_port == 8080):
            payload = bytes(pkt[Raw].load)
            m = HTTP_METHOD_RE.match(payload)
            if m:
                method, path = m.group(1).decode(), m.group(2).decode(errors="replace")
                host_m = HTTP_HOST_RE.search(payload)
                host = host_m.group(1).decode(errors="replace").strip() if host_m else ""
                note = f"HTTP {method} {host}{path}" if host else f"HTTP {method} {path}"
                if note not in sess["notes"]:
                    sess["notes"].append(note)
 
    def persist(self, evidence: Evidence):
        """Write extracted sessions to the DB and update Evidence summary fields.
 
        Clears any previously-persisted sessions for this evidence first, so
        re-running analysis doesn't duplicate every session row. Extracted
        files and alerts can reference a session via session_id, so those
        references are nulled out first — otherwise deleting a
        still-referenced session row leaves a dangling foreign key.
        """
        old_session_ids = [
            s.id for s in Session.query.filter_by(evidence_id=evidence.id).all()
        ]
        if old_session_ids:
            ExtractedFile.query.filter(
                ExtractedFile.session_id.in_(old_session_ids)
            ).update({ExtractedFile.session_id: None}, synchronize_session=False)
            Alert.query.filter(
                Alert.session_id.in_(old_session_ids)
            ).update({Alert.session_id: None}, synchronize_session=False)
 
        Session.query.filter_by(evidence_id=evidence.id).delete()
 
        for sess in self.sessions.values():
            summary = "; ".join(sess["notes"][:5]) if sess["notes"] else None
            db.session.add(Session(
                evidence_id=evidence.id,
                src_ip=sess["src_ip"], dst_ip=sess["dst_ip"],
                src_port=sess["src_port"], dst_port=sess["dst_port"],
                protocol=sess["protocol"],
                packet_count=sess["packet_count"], byte_count=sess["byte_count"],
                start_time=sess["start_time"], end_time=sess["end_time"],
                app_protocol=sess["app_protocol"], summary=summary,
            ))
 
        evidence.packet_count = self.packet_count
        evidence.capture_start = self.capture_start
        evidence.capture_end = self.capture_end
 
 
def analyze_pcap(evidence: Evidence):
    evidence.analysis_status = "processing"
    db.session.commit()
    try:
        analyzer = PcapAnalyzer(evidence.stored_path).run()
        analyzer.persist(evidence)
        evidence.analysis_status = "completed"
        db.session.commit()
        return analyzer
    except Exception as exc:
        evidence.analysis_status = "failed"
        evidence.analysis_error = str(exc)
        db.session.commit()
        raise
 
