# python-whois-recurse 🔍

**Pure Python WHOIS client with automatic referral following. Zero dependencies, no APIs, no paid services.**

[![PyPI version](https://img.shields.io/pypi/v/whois-recurse)](https://pypi.org/project/whois-recurse/)
[![Python versions](https://img.shields.io/pypi/pyversions/whois-recurse)](https://pypi.org/project/whois-recurse/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/yourusername/python-whois-recurse/workflows/Tests/badge.svg)](https://github.com/yourusername/python-whois-recurse/actions)

## ✨ Features

- **🔄 Recursive Lookups** - Automatically follows registrar WHOIS referrals
- **📦 Zero Dependencies** - Pure Python, only uses standard library
- **🌐 1500+ TLDs** - Full IANA TLD list with intelligent fallback
- **📧 Email Extraction** - Finds registrant, admin, tech contacts
- **🛡️ GDPR-Aware** - Detects privacy protection services
- **⚡ Bulk Lookups** - Threaded concurrent queries
- **🎯 No Rate Limits** - Direct socket connections, no API quotas

## 🚀 Quick Start

```bash
pip install whois-recurse