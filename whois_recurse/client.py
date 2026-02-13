"""
Core WHOIS client with recursive referral following
"""

import socket
import re
from typing import Dict, Optional, List, Union
from datetime import datetime
from .servers import INITIAL_SERVERS, REFERRAL_PATTERNS
from .parser import WHOISParser
from .exceptions import *

class WHOISClient:
    """
    Pure Python WHOIS client with automatic referral following
    
    Features:
    - Zero dependencies
    - Follows registrar WHOIS referrals automatically
    - Extracts structured contact data
    - Handles 1500+ TLDs via IANA fallback
    - GDPR-aware (returns proxy emails when protected)
    """
    
    def __init__(self, timeout: int = 10, follow_referrals: bool = True):
        self.timeout = timeout
        self.follow_referrals = follow_referrals
        self.parser = WHOISParser()
        self._cache = {}  # Optional: Add Redis/Memcached support
        
    def lookup(self, domain: str, raw: bool = False) -> Dict:
        """
        Perform full recursive WHOIS lookup
        
        Args:
            domain: Domain name (e.g., 'example.com')
            raw: Return raw WHOIS text if True
            
        Returns:
            Dict with parsed WHOIS data
        """
        domain = domain.lower().strip()
        tld = self._extract_tld(domain)
        
        # Get initial WHOIS server
        initial_server = self._get_whois_server(tld)
        
        try:
            # Step 1: Query thin registry
            thin_data = self._query(initial_server, domain)
            
            # Step 2: Follow to registrar WHOIS
            if self.follow_referrals:
                registrar_server = self.parser.extract_registrar_whois(thin_data)
                if registrar_server:
                    thick_data = self._query(registrar_server, domain)
                else:
                    thick_data = thin_data
            else:
                thick_data = thin_data
            
            if raw:
                return {'raw': thick_data}
            
            # Step 3: Parse everything
            return self.parser.parse_full(domain, thick_data, initial_server)
            
        except socket.timeout:
            raise QueryTimeoutError(f"WHOIS query timed out for {domain}")
        except ConnectionRefusedError:
            raise ServerNotFoundError(f"Cannot connect to WHOIS server for {tld}")
        except Exception as e:
            raise WHOISError(f"WHOIS lookup failed: {e}")
    
    def _query(self, server: str, domain: str) -> str:
        """Raw TCP socket query to WHOIS port 43"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect to WHOIS port
            sock.connect((server, 43))
            
            # Send query (CRLF required by RFC)
            sock.send(f"{domain}\r\n".encode())
            
            # Read response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                
                # Check for rate limiting
                if b"limited" in data.lower() or b"try again" in data.lower():
                    raise RateLimitError(f"Rate limited by {server}")
                    
            sock.close()
            
            return response.decode('utf-8', errors='ignore')
            
        except socket.gaierror:
            raise ServerNotFoundError(f"Unknown WHOIS server: {server}")
    
    def _get_whois_server(self, tld: str) -> str:
        """Get WHOIS server for TLD (cached)"""
        # Check predefined list first
        if tld in INITIAL_SERVERS:
            return INITIAL_SERVERS[tld]
        
        # Fallback: Query IANA for unknown TLDs
        try:
            iana_data = self._query('whois.iana.org', tld)
            match = re.search(r'whois:\s*(.+)', iana_data, re.IGNORECASE)
            if match:
                server = match.group(1).strip()
                return server
        except:
            pass
        
        # Default fallback
        return f"whois.nic.{tld}"
    
    def _extract_tld(self, domain: str) -> str:
        """Extract TLD from domain"""
        parts = domain.split('.')
        if len(parts) > 2 and parts[-2] in ['co', 'org', 'com']:
            return '.'.join(parts[-2:])  # co.uk, org.uk etc
        return parts[-1]
    
    def bulk_lookup(self, domains: List[str], concurrency: int = 5) -> List[Dict]:
        """
        Lookup multiple domains (threaded)
        
        Args:
            domains: List of domain names
            concurrency: Number of concurrent lookups
            
        Returns:
            List of WHOIS results
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(self.lookup, domain): domain 
                      for domain in domains}
            
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'domain': domain,
                        'error': str(e)
                    })
        
        return results
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass