from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import pandas as pd
import json
import logging
import shutil
from email_validator import validate_email, EmailNotValidError
import dns.resolver
from dns.exception import DNSException as DNSError
import click
from flask_migrate import Migrate
import xlsxwriter
import uuid
import secrets
import traceback
import re

# Initialize app and database
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emailverifier.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create required directories
os.makedirs('logs', exist_ok=True)

# Enhanced validation constants
HONEYPOT_PATTERNS = {
    'spam', 'trap', 'honeypot', 'honey-pot', 'honey_pot', 'spamtrap',
    'spam-trap', 'spam_trap', 'spambox', 'spam-box', 'spam_box'
}

INDUSTRY_DOMAINS = {
    'edu': {'edu', 'ac.uk', 'edu.au', 'edu.in'},  # Educational
    'gov': {'gov', 'mil', 'gov.uk', 'gov.au'},    # Government
    'business': {'com', 'co', 'ltd', 'inc', 'plc', 'gmbh', 'corp'}, # Business
    'nonprofit': {'org', 'ngo', 'net'}  # Non-profit
}

COMMON_TYPOS = {
    'gmail.con': 'gmail.com',
    'gmail.co': 'gmail.com',
    'gmial.com': 'gmail.com',
    'gmal.com': 'gmail.com',
    'gamil.com': 'gmail.com',
    'yahoo.con': 'yahoo.com',
    'yaho.com': 'yahoo.com',
    'hotmail.con': 'hotmail.com',
    'hotmal.com': 'hotmail.com',
    'outloo.com': 'outlook.com',
    'outlok.com': 'outlook.com'
}

DISPOSABLE_DOMAINS = {
    # Existing disposable domains...
    'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'mailinator.com',
    'yopmail.com', '10minutemail.com', 'trashmail.com', 'sharklasers.com',
    'getairmail.com', 'maildrop.cc', 'harakirimail.com', 'mailnesia.com',
    'tempmailaddress.com', 'tempail.com', 'throwawaymail.com', 'fakeinbox.com',
    'tempinbox.com', 'emailondeck.com', 'discard.email', 'tempr.email',
    'temp-mail.io', 'spamgourmet.com', 'mytemp.email',
    # Additional disposable domains
    'throwawaymail.com', 'tempinbox.com', 'mailnesia.com', 'maildrop.cc',
    'dispostable.com', 'mailcatch.com', 'tempmailaddress.com', 'tempmail.net',
    'jetable.org', 'spamgourmet.com', 'meltmail.com', 'harakirimail.com',
    'mailexpire.com', 'spambox.us', 'mytrashmail.com', 'gettempmail.com',
    'tempmail.de', 'wegwerfemail.de', 'einrot.com', 'trashmail.net',
    'anonymbox.com', 'fakemail.fr', 'throwawaymail.com', 'fakeinbox.com',
    'tempinbox.com', 'emailondeck.com', 'discard.email', 'tempr.email',
    'temp-mail.io', 'spamgourmet.com', 'mytemp.email',
    # Common disposable domain patterns
    'temp', 'disposable', 'throwaway', 'tmpmail', 'spam', 'fake', 'trash',
    'dumpmail', 'tempmail', 'yopmail', 'mailinator', 'guerrilla'
}

BUSINESS_EMAIL_PATTERNS = {
    'sales', 'info', 'support', 'contact', 'admin', 'billing', 'help',
    'service', 'enquiry', 'inquiry', 'marketing', 'hr', 'jobs', 'careers',
    'recruitment', 'noreply', 'no-reply', 'newsletter', 'webmaster'
}

# Allowed file extensions
ALLOWED_EXTENSIONS = {'csv', 'txt', 'xls', 'xlsx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_excel_report(results, stats, filepath):
    workbook = xlsxwriter.Workbook(filepath)
    worksheet = workbook.add_worksheet()

    # Add header formats
    header_format = workbook.add_format({
        'bold': True,
        'bg_color': '#f0f0f0',
        'border': 1
    })

    # Write statistics
    worksheet.write('A1', 'Email Verification Report', header_format)
    worksheet.write('A3', 'Total Emails', header_format)
    worksheet.write('B3', stats['total'])
    worksheet.write('A4', 'Valid Ratio', header_format)
    worksheet.write('B4', f"{stats['valid'] / stats['total']:.2%}")

    # Write category statistics
    row = 6
    worksheet.write(row, 0, 'Category', header_format)
    worksheet.write(row, 1, 'Count', header_format)
    row += 1

    categories = {
        'Valid Emails': stats['valid'],
        'Invalid Format': stats['invalid_format'],
        'Disposable': stats['disposable'],
        'DNS Errors': stats['dns_error'],
        'Role-based': stats['role_based']
    }

    for category, count in categories.items():
        worksheet.write(row, 0, category)
        worksheet.write(row, 1, count)
        row += 1

    # Add some space
    row += 2

    # Write detailed results
    worksheet.write(row, 0, 'Email', header_format)
    worksheet.write(row, 1, 'Status', header_format)
    worksheet.write(row, 2, 'Reply Score', header_format)
    worksheet.write(row, 3, 'Real Person Score', header_format)
    worksheet.write(row, 4, 'Engagement Score', header_format)
    worksheet.write(row, 5, 'Risk Score', header_format)
    worksheet.write(row, 6, 'Details', header_format)
    row += 1

    for result in results:
        worksheet.write(row, 0, result['email'])
        worksheet.write(row, 1, 'Valid' if result.get('valid', False) else 'Invalid')
        worksheet.write(row, 2, result.get('reply_score', 'N/A'))
        worksheet.write(row, 3, result.get('real_person_score', 'N/A'))
        worksheet.write(row, 4, result.get('engagement_score', 'N/A'))
        worksheet.write(row, 5, result.get('risk_score', 'N/A'))
        
        # Compile details
        details = []
        if result.get('invalid_format'):
            details.append('Invalid Format')
        if result.get('disposable'):
            details.append('Disposable Email')
        if result.get('dns_error'):
            details.append('DNS Error')
        if result.get('role_based'):
            details.append('Role-based Email')
        if result.get('reason'):
            details.append(result['reason'])
        
        worksheet.write(row, 6, ', '.join(details) if details else 'No issues')
        row += 1

    # Adjust column widths
    worksheet.set_column('A:A', 40)  # Email column
    worksheet.set_column('B:F', 15)  # Status and score columns
    worksheet.set_column('G:G', 50)  # Details column

    workbook.close()

def calculate_ai_scores(email):
    """Calculate AI-based scores for email quality and engagement potential."""
    scores = {
        'reply_score': 0,
        'real_person_score': 0,
        'engagement_score': 0,
        'risk_score': 0
    }
    
    # Basic email pattern analysis
    if '@' in email and '.' in email.split('@')[1]:
        domain = email.split('@')[1].lower()
        local_part = email.split('@')[0].lower()
        
        # Reply score factors
        if len(local_part) > 3:
            scores['reply_score'] += 3
        if any(char.isdigit() for char in local_part):
            scores['reply_score'] += 1
        if not any(char in local_part for char in '._-'):
            scores['reply_score'] += 2
            
        # Real person score factors
        if len(local_part) > 2:
            scores['real_person_score'] += 2
        if not local_part.startswith(('info', 'admin', 'support', 'sales', 'contact')):
            scores['real_person_score'] += 3
        if not any(char.isdigit() for char in local_part[-2:]):
            scores['real_person_score'] += 1
            
        # Engagement score factors
        if domain in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']:
            scores['engagement_score'] += 3
        if len(local_part) < 20:
            scores['engagement_score'] += 2
        if not any(char * 2 in local_part for char in '._-'):
            scores['engagement_score'] += 1
            
        # Risk score factors (lower is better)
        if len(local_part) > 25:
            scores['risk_score'] += 2
        if sum(c.isdigit() for c in local_part) > 4:
            scores['risk_score'] += 2
        if any(char * 3 in local_part for char in local_part):
            scores['risk_score'] += 1
    
    # Normalize scores to 0-10 range
    max_scores = {'reply_score': 6, 'real_person_score': 6, 'engagement_score': 6, 'risk_score': 5}
    for key in scores:
        scores[key] = round((scores[key] / max_scores[key]) * 10, 1)
        
    # Invert risk score (lower risk is better)
    scores['risk_score'] = round(10 - scores['risk_score'], 1)
    
    return scores

def verify_email(email):
    """Verify a single email address with comprehensive checks."""
    result = {
        'valid': False,
        'invalid_format': False,
        'disposable': False,
        'dns_error': False,
        'role_based': False,
        'reason': None
    }
    
    try:
        # Basic format validation
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            result['invalid_format'] = True
            result['reason'] = 'Invalid email format'
            return result

        # Parse email for detailed validation
        local_part, domain = email.split('@')
        
        # Check for common disposable email domains
        disposable_domains = ['tempmail.com', 'throwawaymail.com']  # Add more as needed
        if domain.lower() in disposable_domains:
            result['disposable'] = True
            result['reason'] = 'Disposable email domain'
            return result
            
        # Check for role-based emails
        role_based_prefixes = ['admin', 'info', 'support', 'sales', 'contact', 'help']
        if any(local_part.lower().startswith(prefix) for prefix in role_based_prefixes):
            result['role_based'] = True
            result['reason'] = 'Role-based email'
            
        # DNS validation
        try:
            dns.resolver.resolve(domain, 'MX')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result['dns_error'] = True
            result['reason'] = 'Invalid domain or no MX records'
            return result
            
        # If we got here and no major issues found, mark as valid
        if not result['role_based']:
            result['valid'] = True
            
    except Exception as e:
        result['invalid_format'] = True
        result['reason'] = str(e)
        
    return result

def read_emails_from_file(filepath):
    """Read emails from various file formats."""
    _, ext = os.path.splitext(filepath)
    emails = []
    
    try:
        if ext.lower() == '.csv':
            df = pd.read_csv(filepath, header=None)
            # Try to find column with email addresses
            for col in df.columns:
                col_data = df[col].astype(str)
                if col_data.str.contains('@').any():
                    emails.extend(col_data[col_data.str.contains('@')].tolist())
                    
        elif ext.lower() == '.xlsx' or ext.lower() == '.xls':
            df = pd.read_excel(filepath, header=None)
            # Try to find column with email addresses
            for col in df.columns:
                col_data = df[col].astype(str)
                if col_data.str.contains('@').any():
                    emails.extend(col_data[col_data.str.contains('@')].tolist())
                    
        elif ext.lower() == '.txt':
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if '@' in line:
                        emails.append(line)
                        
        # Remove duplicates and clean emails
        emails = list(set(emails))
        emails = [email.strip() for email in emails if '@' in email]
        
    except Exception as e:
        raise Exception(f"Error reading file: {str(e)}")
        
    if not emails:
        raise Exception("No valid email addresses found in file")
        
    return emails

@app.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if file and allowed_file(file.filename):
            try:
                # Create a new verification record
                verification = Verification(
                    user_id=current_user.id,
                    filename=secure_filename(file.filename),
                    date=datetime.utcnow(),
                    total_emails=0,
                    valid_emails=0,
                    invalid_format=0,
                    disposable=0,
                    dns_error=0,
                    role_based=0,
                    status='In Progress'
                )
                db.session.add(verification)
                db.session.commit()

                # Save and process the file
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    # First read all emails from file
                    emails = read_emails_from_file(filepath)
                    verification.total_emails = len(emails)
                    db.session.commit()

                    # Process each email
                    results = []
                    total_score = 0
                    total_valid = 0

                    for email in emails:
                        try:
                            # Verify email
                            result = verify_email(email)
                            result['email'] = email
                            
                            # Calculate AI scores
                            ai_scores = calculate_ai_scores(email)
                            result.update(ai_scores)
                            
                            # Update verification counters
                            if result.get('valid', False):
                                verification.valid_emails += 1
                                total_valid += 1
                                total_score += result.get('reply_score', 0)
                            if result.get('invalid_format', False):
                                verification.invalid_format += 1
                            if result.get('disposable', False):
                                verification.disposable += 1
                            if result.get('dns_error', False):
                                verification.dns_error += 1
                            if result.get('role_based', False):
                                verification.role_based += 1
                            
                            db.session.commit()
                            results.append(result)
                        except Exception as e:
                            logger.error(f"Error verifying email {email}: {str(e)}")
                            results.append({
                                'email': email,
                                'valid': False,
                                'invalid_format': True,
                                'disposable': False,
                                'dns_error': False,
                                'role_based': False,
                                'reason': str(e),
                                'reply_score': 0,
                                'real_person_score': 0,
                                'engagement_score': 0,
                                'risk_score': 0
                            })

                    # Calculate average score for valid emails
                    avg_score = round(total_score / total_valid if total_valid > 0 else 0, 2)

                    # Update verification status
                    verification.status = 'Completed'
                    db.session.commit()

                    # Create Excel report
                    report_filename = f'verification_report_{verification.id}.xlsx'
                    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
                    create_excel_report(results, {
                        'total': len(emails),
                        'valid': verification.valid_emails,
                        'invalid_format': verification.invalid_format,
                        'disposable': verification.disposable,
                        'dns_error': verification.dns_error,
                        'role_based': verification.role_based,
                        'avg_score': avg_score
                    }, report_path)

                    # Clean up the uploaded file
                    if os.path.exists(filepath):
                        os.remove(filepath)

                    return jsonify({
                        'verification_id': verification.id,
                        'stats': {
                            'total': len(emails),
                            'valid': verification.valid_emails,
                            'invalid_format': verification.invalid_format,
                            'disposable': verification.disposable,
                            'dns_error': verification.dns_error,
                            'role_based': verification.role_based,
                            'avg_score': avg_score
                        }
                    })

                except Exception as e:
                    logger.error(f"Error during verification: {str(e)}")
                    verification.status = 'Failed'
                    db.session.commit()
                    return jsonify({'error': str(e)}), 500

            except Exception as e:
                logger.error(f"Error during verification: {str(e)}")
                return jsonify({'error': str(e)}), 500

        else:
            return jsonify({'error': 'Invalid file type. Please upload a CSV, TXT, or Excel file.'}), 400

    return render_template('verify_new.html')

@app.route('/download/<int:verification_id>')
@login_required
def download(verification_id):
    verification = Verification.query.get_or_404(verification_id)
    
    # Check if the verification belongs to the current user
    if verification.user_id != current_user.id:
        abort(403)
    
    # Generate the report filename
    report_filename = f'verification_report_{verification.id}.xlsx'
    report_path = os.path.join(app.config['UPLOAD_FOLDER'], report_filename)
    
    try:
        return send_file(
            report_path,
            as_attachment=True,
            download_name=report_filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        flash('Error downloading report. Please try again.', 'error')
        return redirect(url_for('verify'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
