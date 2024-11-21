"""
Enhanced email validation module for PureMail
"""
import re
from typing import Dict, List, Union

class EmailValidatorEnhanced:
    def __init__(self):
        self.common_typos = {
            'gmail.com': ['gmai.com', 'gamil.com', 'gnail.com', 'gmal.com'],
            'yahoo.com': ['yaho.com', 'yahooo.com', 'yaho.com', 'yahho.com'],
            'hotmail.com': ['hotmai.com', 'hotmal.com', 'hotmial.com', 'hotmil.com'],
            'outlook.com': ['outlok.com', 'outloo.com', 'outluk.com', 'outlock.com']
        }
        
        self.business_patterns = [
            r'^[a-zA-Z0-9_.+-]+@(?!gmail|yahoo|hotmail|outlook|aol|protonmail|icloud)[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        ]
        
        self.suspicious_patterns = [
            r'^test.*@',
            r'^admin@',
            r'^info@',
            r'^no-?reply@',
            r'^[a-z]{1,2}@',
            r'^postmaster@',
            r'^.*\+.*@'  # Catch email aliases
        ]
        
        self.disposable_patterns = [
            r'@tempmail\.',
            r'@guerrillamail\.',
            r'@10minutemail\.',
            r'@mailinator\.',
            r'@throwawaymail\.',
            r'@yopmail\.',
            r'@temp-mail\.'
        ]
        
        self.high_risk_tlds = [
            '.xyz', '.top', '.work', '.click', '.loan', '.download'
        ]
        
        self.spam_keywords = [
            'spam', 'temp', 'fake', 'disposable', 'trash'
        ]

    def analyze_pattern(self, email: str) -> Dict[str, Union[bool, str, List[str]]]:
        """Analyze email patterns for business, typos, and suspicious characteristics."""
        analysis = {
            'is_business': False,
            'possible_typo': None,
            'is_suspicious': False,
            'suggestions': []
        }
        
        # Check for business email
        for pattern in self.business_patterns:
            if re.match(pattern, email.lower()):
                analysis['is_business'] = True
                break
        
        # Check for typos
        domain = email.split('@')[-1].lower()
        for correct_domain, typos in self.common_typos.items():
            if domain in typos:
                analysis['possible_typo'] = correct_domain
                analysis['suggestions'].append(f"Did you mean @{correct_domain}?")
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, email.lower()):
                analysis['is_suspicious'] = True
                analysis['suggestions'].append("This email follows a suspicious pattern")
                break
        
        return analysis

    def security_check(self, email: str) -> Dict[str, Union[bool, int, List[str]]]:
        """Perform security checks on the email."""
        results = {
            'is_disposable': False,
            'is_high_risk_tld': False,
            'spam_score': 0,
            'security_warnings': []
        }
        
        # Check for disposable email patterns
        for pattern in self.disposable_patterns:
            if re.search(pattern, email.lower()):
                results['is_disposable'] = True
                results['security_warnings'].append("Detected disposable email pattern")
                results['spam_score'] += 3
                break
        
        # Check TLD risk
        for tld in self.high_risk_tlds:
            if email.lower().endswith(tld):
                results['is_high_risk_tld'] = True
                results['security_warnings'].append(f"High-risk TLD detected: {tld}")
                results['spam_score'] += 2
                break
        
        # Check for spam keywords
        for keyword in self.spam_keywords:
            if keyword in email.lower():
                results['spam_score'] += 1
                results['security_warnings'].append(f"Suspicious keyword detected: {keyword}")
        
        return results

    def validate_email(self, email: str) -> Dict[str, Union[Dict, bool]]:
        """Complete email validation including pattern analysis and security checks."""
        try:
            # Basic format validation
            email = str(email).strip()
            if not email:
                return {
                    'valid': False,
                    'error': 'Empty email address'
                }
            
            # Pattern analysis
            pattern_analysis = self.analyze_pattern(email)
            
            # Security checks
            security_check = self.security_check(email)
            
            # Combine results
            return {
                'valid': True,
                'pattern_analysis': pattern_analysis,
                'security_check': security_check
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
