from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verifications = db.relationship('Verification', backref='user', lazy=True)
    dmarc_records = db.relationship('DMARCRecord', backref='user', lazy=True)
    blacklist_monitors = db.relationship('BlacklistMonitor', backref='user', lazy=True)

class Verification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    total_emails = db.Column(db.Integer, default=0)
    valid_emails = db.Column(db.Integer, default=0)
    invalid_format = db.Column(db.Integer, default=0)
    disposable = db.Column(db.Integer, default=0)
    role_based = db.Column(db.Integer, default=0)
    dns_error = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='Pending')
    
    # New fields for advanced verification
    catch_all_scores = db.relationship('CatchAllScore', backref='verification', lazy=True)

class DMARCRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    policy = db.Column(db.String(50))  # none, quarantine, reject
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime)
    is_valid = db.Column(db.Boolean, default=False)
    spf_record = db.Column(db.String(255))
    dkim_record = db.Column(db.String(255))
    reports = db.relationship('DMARCReport', backref='dmarc_record', lazy=True)

class DMARCReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dmarc_record_id = db.Column(db.Integer, db.ForeignKey('dmarc_record.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    authentication_results = db.Column(db.String(255))
    disposition = db.Column(db.String(50))
    dkim_result = db.Column(db.String(50))
    spf_result = db.Column(db.String(50))
    is_suspicious = db.Column(db.Boolean, default=False)

class BlacklistMonitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    ip_version = db.Column(db.Integer)  # 4 or 6
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime)
    status = db.Column(db.String(20))  # clean, listed, warning
    blacklist_entries = db.relationship('BlacklistEntry', backref='monitor', lazy=True)

class BlacklistEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey('blacklist_monitor.id'), nullable=False)
    blacklist_name = db.Column(db.String(255))
    listed_on = db.Column(db.DateTime, default=datetime.utcnow)
    delisted_on = db.Column(db.DateTime)
    reason = db.Column(db.Text)
    status = db.Column(db.String(20))  # active, resolved

class CatchAllScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verification_id = db.Column(db.Integer, db.ForeignKey('verification.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer)  # 1-10
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    factors = db.Column(db.Text)  # JSON string of scoring factors
