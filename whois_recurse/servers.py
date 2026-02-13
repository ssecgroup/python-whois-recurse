"""
WHOIS server mappings for all TLDs
Updated from IANA regularly
"""

INITIAL_SERVERS = {
    # Generic TLDs
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'io': 'whois.nic.io',
    'ai': 'whois.nic.ai',
    'app': 'whois.nic.google',
    'dev': 'whois.nic.google',
    'cloud': 'whois.nic.cloud',
    'co': 'whois.nic.co',
    'me': 'whois.nic.me',
    'tv': 'whois.nic.tv',
    
    # Country TLDs
    'in': 'whois.registry.in',
    'uk': 'whois.nic.uk',
    'de': 'whois.denic.de',
    'eu': 'whois.eu',
    'ca': 'whois.cira.ca',
    'jp': 'whois.jprs.jp',
    'au': 'whois.auda.org.au',
    'fr': 'whois.nic.fr',
    'br': 'whois.registro.br',
    
    # Specialized
    'edu': 'whois.educause.edu',
    'gov': 'whois.dotgov.gov',
    'mil': 'whois.nic.mil',
}

REFERRAL_PATTERNS = [
    r'Registrar WHOIS Server: (.+)',
    r'Registrar Whois: (.+)',
    r'WHOIS Server: (.+)',
    r'Whois Server: (.+)'
]

# TLDs that support RDAP (for future enhancement)
RDAP_SUPPORT = [
    'com', 'net', 'org', 'io', 'co', 'app', 'dev'
]

def get_server_for_tld(tld: str) -> str:
    """Get WHOIS server for TLD, with IANA fallback"""
    return INITIAL_SERVERS.get(tld, f'whois.nic.{tld}')