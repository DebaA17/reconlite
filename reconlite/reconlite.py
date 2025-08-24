#!/usr/bin/env python3
"""
ReconLite - Advanced Cyber Reconnaissance Tool
A comprehensive Python-based reconnaissance tool for DNS and domain information gathering.
Perfect for ethical hacking, Red Team operations, and vulnerability assessments.

🌐 Web Version: https://recon.debasisbiswas.me
💻 CLI Version: Command-line tool for advanced users

Features:
- DNS Enumeration using subfinder
- WHOIS Lookup
- IP Address Resolution & Intelligence
- Security Records Analysis (SPF, DMARC, DKIM)
- JSON Export for further analysis
- Command-line Interface

Author: DEBASIS (hello@debasisbiswas.me)
Website: https://debasisbiswas.me
Version: 1.0

⚖️ LEGAL DISCLAIMER:
This tool is intended for educational purposes and authorized security testing only.
Users are responsible for ensuring they have proper authorization before scanning any
domains or networks. Unauthorized scanning may violate laws and regulations.
The author is not responsible for any misuse of this tool.
"""

import subprocess
import json
import socket
import sys
import argparse
import re
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

# Version and tool information
__version__ = "1.0.0"
__author__ = "DEBASIS"
__email__ = "hello@debasisbiswas.me"
__website__ = "https://debasisbiswas.me"
__github__ = "https://github.com/DebaA17/reconlite"

# Import required libraries
try:
    import whois as python_whois
    from ipwhois import IPWhois
    import dns.resolver
    import dns.reversename
    import requests
except ImportError as e:
    print(f"❌ Missing required library: {e}")
    print("Please install required dependencies:")
    print("pip install -r requirements.txt")
    sys.exit(1)

class ReconLite:
    """Main reconnaissance tool class"""
    
    def __init__(self):
        self.results = {
            'target': '',
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'whois_info': {},
            'ip_info': {},
            'ip_intelligence': {},
            'security_records': {},
            'subdomain_enum': [],
            'port_scan': {},
            'technology_stack': {}
        }
        self.timeout = 30
    
    def banner(self):
        """Display tool banner"""
        print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🔍 RECONLITE TOOL                                 ║
║                                                                              ║
║   Advanced DNS & Domain Intelligence Gathering Tool                         ║
║   Perfect for Ethical Hacking, Red Team Ops & Vulnerability Assessment      ║
║                                                                              ║
║   Features: DNS Enum | WHOIS | IP Intel | Security Records | JSON Export    ║
║   Tech Stack: subfinder | python-whois | ipwhois | dnspython                ║
║                                                                              ║
║   🌐 Web Version: recon.debasisbiswas.me                                     ║
║   Made by: DEBASIS (hello@debasisbiswas.me)                                 ║
║   ⚖️  For Educational Purposes Only - Not for Illegal Activities            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """)
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        dependencies = {
            'dnsrecon': 'dnsrecon --help'
        }
        # ...existing code...


def main():
    parser = argparse.ArgumentParser(description="ReconLite - Advanced Cyber Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    args = parser.parse_args()

    tool = ReconLite()
    tool.banner()
    tool.results['target'] = args.target
    # You can add more CLI logic here, e.g., call methods to perform recon
    print(f"ReconLite initialized for target: {args.target}")

if __name__ == "__main__":
    main()
