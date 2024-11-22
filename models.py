from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json
from extensions import db

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    verifications = db.relationship('Verification', backref='user', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    credits = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Verification(db.Model):
    __tablename__ = 'verifications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    total_emails = db.Column(db.Integer, default=0)
    valid_emails = db.Column(db.Integer, default=0)
    invalid_emails = db.Column(db.Integer, default=0)
    results = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')
    error_message = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'filename': self.filename,
            'date': self.date.isoformat() if self.date else None,
            'total_emails': self.total_emails,
            'valid_emails': self.valid_emails,
            'invalid_emails': self.invalid_emails,
            'status': self.status,
            'error_message': self.error_message,
            'results': json.loads(self.results) if self.results else None
        }

    # Relationships
    catch_all_scores = db.relationship('CatchAllScore', backref='verification', lazy=True)

class DMARCRecord(db.Model):
    __tablename__ = 'dmarc_records'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    policy = db.Column(db.String(50))  # none, quarantine, reject
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime)
    is_valid = db.Column(db.Boolean, default=False)
    spf_record = db.Column(db.String(255))
    dkim_record = db.Column(db.String(255))
    reports = db.relationship('DMARCReport', backref='dmarc_record', lazy=True)

class DMARCReport(db.Model):
    __tablename__ = 'dmarc_reports'
    id = db.Column(db.Integer, primary_key=True)
    dmarc_record_id = db.Column(db.Integer, db.ForeignKey('dmarc_records.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(45))
    authentication_results = db.Column(db.String(255))
    disposition = db.Column(db.String(50))
    dkim_result = db.Column(db.String(50))
    spf_result = db.Column(db.String(50))
    is_suspicious = db.Column(db.Boolean, default=False)

class BlacklistMonitor(db.Model):
    __tablename__ = 'blacklist_monitors'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    ip_version = db.Column(db.Integer)  # 4 or 6
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_checked = db.Column(db.DateTime)
    status = db.Column(db.String(20))  # active, inactive
    blacklist_entries = db.relationship('BlacklistEntry', backref='monitor', lazy=True)

class BlacklistEntry(db.Model):
    __tablename__ = 'blacklist_entries'
    id = db.Column(db.Integer, primary_key=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey('blacklist_monitors.id'), nullable=False)
    blacklist_name = db.Column(db.String(255))
    listed_on = db.Column(db.DateTime, default=datetime.utcnow)
    delisted_on = db.Column(db.DateTime)
    reason = db.Column(db.Text)
    status = db.Column(db.String(20))  # active, resolved

class CatchAllScore(db.Model):
    __tablename__ = 'catch_all_scores'
    id = db.Column(db.Integer, primary_key=True)
    verification_id = db.Column(db.Integer, db.ForeignKey('verifications.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    score = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    factors = db.Column(db.Text)

class AppSumoCode(db.Model):
    __tablename__ = 'appsumo_codes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(255), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    redeemed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='active')  # active, redeemed, expired
