"""
Database models for the Network Forensic Investigation & Evidence Management System.
"""
import hashlib
import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


def utcnow():
    """Naive UTC datetime (no tzinfo) — keeps hash-chain strings consistent
    before and after SQLite round-trip."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    investigator = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=utcnow)
    status = db.Column(db.String(50), default="open")
    suspect = db.Column(db.Text)
    affected_party = db.Column(db.Text)
    evidence_items = db.relationship("Evidence", backref="case", lazy=True,
                                      cascade="all, delete-orphan")


class Evidence(db.Model):
    __tablename__ = "evidence"

    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=False)

    original_filename = db.Column(db.String(500), nullable=False)
    stored_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)

    sha256 = db.Column(db.String(64), nullable=False)
    md5 = db.Column(db.String(32))

    uploaded_at = db.Column(db.DateTime, default=utcnow)
    uploaded_by = db.Column(db.String(200))

    analysis_status = db.Column(db.String(50), default="pending")
    analysis_error = db.Column(db.Text)

    packet_count = db.Column(db.Integer)
    capture_start = db.Column(db.DateTime)
    capture_end = db.Column(db.DateTime)

    sessions = db.relationship("Session", backref="evidence", lazy=True,
                                cascade="all, delete-orphan")
    extracted_files = db.relationship("ExtractedFile", backref="evidence", lazy=True,
                                       cascade="all, delete-orphan")
    alerts = db.relationship("Alert", backref="evidence", lazy=True,
                              cascade="all, delete-orphan")
    custody_logs = db.relationship("CustodyLog", backref="evidence", lazy=True,
                                    cascade="all, delete-orphan",
                                    order_by="CustodyLog.id")

    def verify_integrity(self, current_sha256: str) -> bool:
        return current_sha256 == self.sha256


class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)

    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))

    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.Integer, default=0)

    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)

    app_protocol = db.Column(db.String(50))
    summary = db.Column(db.Text)


class ExtractedFile(db.Model):
    __tablename__ = "extracted_files"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey("sessions.id"))

    filename = db.Column(db.String(500))
    stored_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)
    sha256 = db.Column(db.String(64))

    source_protocol = db.Column(db.String(50))
    direction = db.Column(db.String(20))

    extracted_at = db.Column(db.DateTime, default=utcnow)

    vt_checked = db.Column(db.Boolean, default=False)
    vt_malicious_count = db.Column(db.Integer)
    vt_total_engines = db.Column(db.Integer)
    vt_report_url = db.Column(db.String(500))
    vt_checked_at = db.Column(db.DateTime)


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey("sessions.id"))

    alert_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    title = db.Column(db.String(300))
    description = db.Column(db.Text)

    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))

    detected_at = db.Column(db.DateTime, default=utcnow)
    evidence_timestamp = db.Column(db.DateTime)


class CustodyLog(db.Model):
    """Tamper-evident chain-of-custody log (hash-chained entries)."""
    __tablename__ = "custody_logs"

    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False)

    action = db.Column(db.String(100), nullable=False)
    actor = db.Column(db.String(200))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=utcnow)

    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)

    @staticmethod
    def compute_hash(evidence_id, action, actor, details, timestamp, prev_hash):
        payload = json.dumps({
            "evidence_id": evidence_id,
            "action": action,
            "actor": actor,
            "details": details,
            "timestamp": timestamp.isoformat(),
            "prev_hash": prev_hash,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def append(cls, evidence_id, action, actor="system", details=""):
        last = (cls.query
                .filter_by(evidence_id=evidence_id)
                .order_by(cls.id.desc())
                .first())
        prev_hash = last.entry_hash if last else "0" * 64
        ts = utcnow()
        entry_hash = cls.compute_hash(evidence_id, action, actor, details, ts, prev_hash)

        entry = cls(
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            details=details,
            timestamp=ts,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    @classmethod
    def verify_chain(cls, evidence_id):
        entries = (cls.query
                   .filter_by(evidence_id=evidence_id)
                   .order_by(cls.id.asc())
                   .all())
        expected_prev = "0" * 64
        for entry in entries:
            recomputed = cls.compute_hash(
                entry.evidence_id, entry.action, entry.actor,
                entry.details, entry.timestamp, expected_prev
            )
            if entry.prev_hash != expected_prev or entry.entry_hash != recomputed:
                return False, entry.id
            expected_prev = entry.entry_hash
        return True, None


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)  # nullable for now — tighten after backfill
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="investigator")  # "admin" or "investigator"
    investigator_id = db.Column(db.String(20), unique=True, nullable=True)   # e.g. INV-00001, admins have None
    is_active_user = db.Column(db.Boolean, default=True, nullable=False, server_default="1")
    created_at = db.Column(db.DateTime, default=utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"