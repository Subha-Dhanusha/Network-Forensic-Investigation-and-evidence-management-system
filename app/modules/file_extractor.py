"""
File extraction ("carving") from network traffic.

MVP scope: HTTP only. Reassembles each TCP flow's payload bytes in packet
order (no retransmission/out-of-order handling), then:
  - Client -> server payloads starting with an HTTP method line are treated
    as requests (used to recover the request path, for naming the file).
  - Server -> client payloads starting with "HTTP/1." are treated as
    responses; the body (everything after the blank line separating
    headers from body) is carved out as a candidate extracted file.
"""
import os
import re
import hashlib

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from ..models import db, ExtractedFile, Session

HTTP_METHOD_RE = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD) (\S+) HTTP/")
CONTENT_DISPOSITION_RE = re.compile(rb'filename="?([^"\r\n;]+)"?', re.IGNORECASE)


def _flow_dir_key(src_ip, src_port, dst_ip, dst_port):
    return (src_ip, src_port, dst_ip, dst_port)


def _guess_filename(request_path: str, headers: bytes, index: int) -> str:
    m = CONTENT_DISPOSITION_RE.search(headers)
    if m:
        return m.group(1).decode(errors="replace")
    if request_path:
        base = os.path.basename(request_path.split("?")[0])
        if base:
            return base
    return f"extracted_file_{index}"


class FileExtractor:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.flows = {}
        self.request_paths = {}

    def run(self):
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                self._process_packet(pkt)
        return self

    def _process_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        payload = bytes(pkt[Raw].load)

        key = _flow_dir_key(ip_layer.src, int(tcp_layer.sport),
                             ip_layer.dst, int(tcp_layer.dport))
        self.flows.setdefault(key, bytearray()).extend(payload)

        m = HTTP_METHOD_RE.match(payload)
        if m:
            self.request_paths[key] = m.group(2).decode(errors="replace")

    def extract_http_files(self):
        results = []
        idx = 0
        for key, buf in self.flows.items():
            src_ip, src_port, dst_ip, dst_port = key
            data = bytes(buf)

            if not data.startswith(b"HTTP/1."):
                continue

            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                continue

            headers = data[:header_end]
            body = data[header_end + 4:]
            if not body:
                continue

            reverse_key = (dst_ip, dst_port, src_ip, src_port)
            request_path = self.request_paths.get(reverse_key, "")

            idx += 1
            filename = _guess_filename(request_path, headers, idx)

            results.append({
                "data": body,
                "filename": filename,
                "direction": "inbound",
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
            })

        return results


def extract_and_persist(evidence, extracted_folder: str):
    extractor = FileExtractor(evidence.stored_path).run()
    carved = extractor.extract_http_files()

    created = []
    for i, item in enumerate(carved):
        sha256 = hashlib.sha256(item["data"]).hexdigest()
        safe_name = f"{evidence.id}_{i}_{item['filename']}".replace("/", "_").replace("\\", "_")
        out_path = os.path.join(extracted_folder, safe_name)
        with open(out_path, "wb") as f:
            f.write(item["data"])

        session = Session.query.filter_by(
            evidence_id=evidence.id, src_ip=item["dst_ip"], dst_ip=item["src_ip"],
            src_port=item["dst_port"], dst_port=item["src_port"],
        ).first() or Session.query.filter_by(
            evidence_id=evidence.id, src_ip=item["src_ip"], dst_ip=item["dst_ip"],
            src_port=item["src_port"], dst_port=item["dst_port"],
        ).first()

        ef = ExtractedFile(
            evidence_id=evidence.id,
            session_id=session.id if session else None,
            filename=item["filename"],
            stored_path=out_path,
            file_size=len(item["data"]),
            sha256=sha256,
            source_protocol="HTTP",
            direction=item["direction"],
        )
        db.session.add(ef)
        created.append(ef)

    db.session.commit()
    return created