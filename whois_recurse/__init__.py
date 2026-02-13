"""
python-whois-recurse - Pure Python recursive WHOIS client
No dependencies, follows referrals, extracts all contact data
"""

from .client import WHOISClient
from .exceptions import (
    WHOISError,
    ServerNotFoundError,
    QueryTimeoutError,
    RateLimitError
)

__version__ = '0.1.0'
__author__ = 'Your Name'
__license__ = 'MIT'

__all__ = [
    'WHOISClient',
    'WHOISError',
    'ServerNotFoundError',
    'QueryTimeoutError',
    'RateLimitError'
]