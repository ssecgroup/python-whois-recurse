"""
WHOIS response parser with field extraction
"""

import re
from typing import Dict, List, Optional
from datetime import datetime

class WHOISParser:
    """Extract structured data from raw WHOIS text"""
    
    # Common field patterns
    FIELD_PATTERNS = {
        'registrar': [
            r'Registrar: (.+)',
            r'Registrar Name: (.+)',
            r'Sponsoring Registrar: (.+)'
        ],
        'creation_date': [
            r'Creation Date: (.+)',
            r'Created Date: (.+)',
            r'Created on: (.+)',
            r'Domain Created: (.+)'
        ],
        'expiry_date': [
            r'Registry Expiry Date: (.+)',
            r'Expiry Date: (.+)',
            r'Expires: (.+)',
            r'Expiration Date: (.+)'
        ],
        'updated_date': [
            r'Updated Date: (.+)',
            r'Last Updated: (.+)',
            r'Last Update: (.+)'
        ],
        'nameservers': [
            r'Name Server: (.+)',
            r'Nameserver: (.+)',
            r'nserver: (.+)'
        ],
        'status': [
            r'Domain Status: (.+)',
            r'Status: (.+)'
        ]
    }
    
    # Contact type patterns
    CONTACT_PATTERNS = {
        'registrant': ['Registrant', 'Owner'],
        'admin': ['Admin', 'Administrative'],
        'tech': ['Tech', 'Technical'],
        'billing': ['Billing']
    }
    
    def parse_full(self, domain: str, text: str, thin_server: str = None) -> Dict:
        """Complete parsing of WHOIS data"""
        
        result = {
            'domain': domain,
            'thin_server': thin_server,
            'registrar_server': self.extract_registrar_whois(text),
            'query_time': datetime.utcnow().isoformat(),
            'raw_length': len(text)
        }
        
        # Extract standard fields
        for field, patterns in self.FIELD_PATTERNS.items():
            value = self._extract_field(text, patterns)
            if value:
                result[field] = value
        
        # Extract contact emails
        for contact_type in self.CONTACT_PATTERNS:
            for name in self.CONTACT_PATTERNS[contact_type]:
                email = self.extract_contact_email(text, name)
                if email:
                    result[f'{contact_type}_email'] = email
                    break
        
        # Extract all emails
        result['all_emails'] = self.extract_all_emails(text)
        
        # Check for privacy protection
        result['privacy_protected'] = any(
            pattern in text.lower() 
            for pattern in ['identity-protection', 'domainsbyproxy', 'whoisguard']
        )
        
        return result
    
    def extract_registrar_whois(self, text: str) -> Optional[str]:
        """Find registrar WHOIS server"""
        patterns = [
            r'Registrar WHOIS Server: (.+)',
            r'Registrar Whois: (.+)',
            r'WHOIS Server: (.+)'
        ]
        return self._extract_field(text, patterns)
    
    def extract_contact_email(self, text: str, contact_type: str) -> Optional[str]:
        """Extract email for specific contact"""
        patterns = [
            rf'{contact_type} Email: (.+)',
            rf'{contact_type} E-mail: (.+)',
            rf'{contact_type} EMAIL: (.+)'
        ]
        email = self._extract_field(text, patterns)
        
        # Validate and clean
        if email and self._is_valid_email(email):
            return email.strip()
        return None
    
    def extract_all_emails(self, text: str) -> List[str]:
        """Find all email addresses in WHOIS output"""
        # Basic email regex
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(pattern, text)
        
        # Filter out abuse/noreply/placeholders
        filtered = []
        for email in emails:
            email_lower = email.lower()
            if not any(x in email_lower for x in [
                'abuse', 'whois', 'example', 'hostmaster', 
                'noc@', 'admin@', 'postmaster', 'spam'
            ]):
                if not email_lower.startswith('@'):
                    filtered.append(email)
        
        return list(set(filtered))  # Deduplicate
    
    def _extract_field(self, text: str, patterns: List[str]) -> Optional[str]:
        """Extract first matching field"""
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation"""
        if not email or len(email) > 254:
            return False
        if '@' not in email or '.' not in email.split('@')[1]:
            return False
        return True
    
    def parse_dates(self, date_str: str) -> Optional[datetime]:
        """Parse various date formats"""
        # Add more date formats as needed
        formats = [
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%d %H:%M:%S',
            '%Y.%m.%d',
            '%d-%b-%Y',
            '%Y-%m-%d'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        return None