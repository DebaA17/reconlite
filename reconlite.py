#!/usr/bin/env python3
"""
ReconLite - Advanced Cyber Reconnaissance Tool
A comprehensive Python-based reconnaissance tool for DNS and domain information gathering.
Perfect for ethical hacking, Red Team operations, and vulnerability assessments.

Features:
- DNS Enumeration using dnsrecon
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
║   Tech Stack: dnsrecon | python-whois | ipwhois | dnspython                 ║
║                                                                              ║
║   Made by: DEBASIS (hello@debasisbiswas.me)                                 ║
║   ⚖️  For Educational Purposes Only - Not for Illegal Activities            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """)
    
    def check_dependencies(self):
        """Check if required tools are installed"""
        dependencies = {
            'dnsrecon': 'dnsrecon --help',
            'dig': 'dig -v',
            'nslookup': 'nslookup -version',
            'nmap': 'nmap --version',
            'subfinder': 'subfinder -version'
        }
        
        available = {}
        missing = []
        
        for tool, command in dependencies.items():
            try:
                result = subprocess.run(command.split(), capture_output=True, timeout=5)
                available[tool] = result.returncode == 0
                if result.returncode != 0:
                    missing.append(tool)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                available[tool] = False
                missing.append(tool)
        
        if missing:
            print(f"⚠️  Warning: Missing tools: {', '.join(missing)}")
            print("Some features may not work properly.")
            print("On Kali Linux/Ubuntu, install with:")
            print("sudo apt update && sudo apt install dnsrecon dnsutils nmap")
            print("For subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        
        return available
    
    def run_dnsrecon(self, domain: str) -> Dict[str, Any]:
        """Run dnsrecon for comprehensive DNS enumeration"""
        print(f"🔍 Running DNS reconnaissance on {domain}...")
        
        dns_data = {
            'standard_records': {},
            'zone_transfer': {},
            'subdomain_enum': [],
            'raw_output': '',
            'mx_enum': [],
            'srv_enum': []
        }
        
        try:
            # Standard DNS enumeration
            print("  → Standard DNS enumeration...")
            cmd = ['dnsrecon', '-d', domain, '-t', 'std']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                dns_data['raw_output'] = result.stdout
                # Parse output for structured data
                self._parse_dnsrecon_output(result.stdout, dns_data)
            else:
                dns_data['error'] = f"dnsrecon failed: {result.stderr}"
            
            # Zone transfer attempt
            print("  → Attempting zone transfer...")
            try:
                zt_cmd = ['dnsrecon', '-d', domain, '-t', 'axfr']
                zt_result = subprocess.run(zt_cmd, capture_output=True, text=True, timeout=30)
                dns_data['zone_transfer'] = {
                    'attempted': True,
                    'successful': 'Zone Transfer successful' in zt_result.stdout,
                    'output': zt_result.stdout
                }
            except subprocess.TimeoutExpired:
                dns_data['zone_transfer'] = {'attempted': True, 'successful': False, 'error': 'Timeout'}
            
            # Subdomain brute force
            print("  → Subdomain enumeration...")
            try:
                # Dictionary to track unique subdomains
                unique_subdomains = {}
                
                # Try common subdomain list first
                common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn', 'blog']
                for sub in common_subs:
                    try:
                        full_domain = f"{sub}.{domain}"
                        answers = dns.resolver.resolve(full_domain, 'A')
                        
                        # Collect all IPs for this subdomain
                        ips = [str(answer) for answer in answers]
                        
                        if full_domain not in unique_subdomains:
                            unique_subdomains[full_domain] = {
                                'subdomain': full_domain,
                                'ips': ips,
                                'method': 'common_list'
                            }
                        else:
                            # Add any new IPs to existing subdomain
                            for ip in ips:
                                if ip not in unique_subdomains[full_domain]['ips']:
                                    unique_subdomains[full_domain]['ips'].append(ip)
                    except:
                        continue
                
                # Try dnsrecon brute force if wordlist exists
                wordlist_paths = [
                    '/usr/share/dnsrecon/subdomains-top1mil-5000.txt',
                    '/usr/share/wordlists/dnsmap.txt',
                    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
                ]
                
                for wordlist in wordlist_paths:
                    if os.path.exists(wordlist):
                        sub_cmd = ['dnsrecon', '-d', domain, '-t', 'brt', '-D', wordlist]
                        sub_result = subprocess.run(sub_cmd, capture_output=True, text=True, timeout=60)
                        
                        # Parse subdomain results
                        for line in sub_result.stdout.split('\n'):
                            if '[A]' in line or '[AAAA]' in line:
                                match = re.search(r'(\S+\.' + re.escape(domain) + r')\s+\d+\s+IN\s+[A]+\s+(\S+)', line)
                                if match:
                                    subdomain = match.group(1)
                                    ip = match.group(2)
                                    
                                    if subdomain not in unique_subdomains:
                                        unique_subdomains[subdomain] = {
                                            'subdomain': subdomain,
                                            'ips': [ip],
                                            'method': 'dnsrecon_brute'
                                        }
                                    else:
                                        if ip not in unique_subdomains[subdomain]['ips']:
                                            unique_subdomains[subdomain]['ips'].append(ip)
                        break
                
                # Convert to list format for consistency
                dns_data['subdomain_enum'] = list(unique_subdomains.values())
                        
            except subprocess.TimeoutExpired:
                dns_data['subdomain_enum'].append({'error': 'Subdomain enumeration timeout'})
        
        except Exception as e:
            dns_data['error'] = str(e)
        
        return dns_data
    
    def _parse_dnsrecon_output(self, output: str, dns_data: Dict[str, Any]):
        """Parse dnsrecon output for structured data"""
        lines = output.split('\n')
        for line in lines:
            # Parse MX records
            if '[MX]' in line:
                match = re.search(r'\[MX\]\s+(\S+)\s+(\d+)\s+(\S+)', line)
                if match:
                    dns_data['mx_enum'].append({
                        'domain': match.group(1),
                        'priority': int(match.group(2)),
                        'exchange': match.group(3)
                    })
            
            # Parse SRV records
            if '[SRV]' in line:
                match = re.search(r'\[SRV\]\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)', line)
                if match:
                    dns_data['srv_enum'].append({
                        'service': match.group(1),
                        'priority': int(match.group(2)),
                        'weight': int(match.group(3)),
                        'port': int(match.group(4)),
                        'target': match.group(5)
                    })
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records using dnspython"""
        print(f"📡 Gathering DNS records for {domain}...")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = []
                
                for answer in answers:
                    if record_type == 'MX':
                        records[record_type].append({
                            'priority': answer.preference,
                            'exchange': str(answer.exchange).rstrip('.')
                        })
                    elif record_type == 'SOA':
                        records[record_type].append({
                            'mname': str(answer.mname).rstrip('.'),
                            'rname': str(answer.rname).rstrip('.'),
                            'serial': answer.serial,
                            'refresh': answer.refresh,
                            'retry': answer.retry,
                            'expire': answer.expire,
                            'minimum': answer.minimum
                        })
                    else:
                        records[record_type].append(str(answer).rstrip('.'))
                        
            except dns.resolver.NXDOMAIN:
                records[record_type] = {'error': 'Domain not found'}
            except dns.resolver.NoAnswer:
                records[record_type] = {'error': 'No answer'}
            except Exception as e:
                records[record_type] = {'error': str(e)}
        
        return records
    
    def analyze_security_records(self, domain: str, dns_records: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze DNS records for security configurations"""
        print("🔒 Analyzing security records (DMARC, SPF, DKIM)...")
        
        security_info = {
            'spf': {'present': False, 'record': '', 'mechanisms': [], 'valid': False},
            'dmarc': {'present': False, 'record': '', 'policy': '', 'subdomain_policy': ''},
            'dkim': {'present': False, 'selectors_found': [], 'records': []},
            'dnssec': {'enabled': False, 'algorithms': []},
            'caa': {'present': False, 'records': []},
            'security_score': 0
        }
        
        # Analyze TXT records for SPF
        if 'TXT' in dns_records and isinstance(dns_records['TXT'], list):
            for txt_record in dns_records['TXT']:
                txt_str = str(txt_record).strip('"')
                
                # SPF Analysis
                if txt_str.startswith('v=spf1'):
                    security_info['spf']['present'] = True
                    security_info['spf']['record'] = txt_str
                    security_info['spf']['valid'] = self._validate_spf(txt_str)
                    
                    # Parse SPF mechanisms
                    mechanisms = []
                    for part in txt_str.split():
                        if part.startswith(('ip4:', 'ip6:', 'include:', 'a:', 'mx:', 'exists:', 'redirect=')):
                            mechanisms.append(part)
                    security_info['spf']['mechanisms'] = mechanisms
        
        # Check for DMARC record
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for answer in dmarc_answers:
                txt_str = str(answer).strip('"')
                if txt_str.startswith('v=DMARC1'):
                    security_info['dmarc']['present'] = True
                    security_info['dmarc']['record'] = txt_str
                    
                    # Extract policies
                    policy_match = re.search(r'p=(\w+)', txt_str)
                    if policy_match:
                        security_info['dmarc']['policy'] = policy_match.group(1)
                    
                    sp_match = re.search(r'sp=(\w+)', txt_str)
                    if sp_match:
                        security_info['dmarc']['subdomain_policy'] = sp_match.group(1)
                    break
        except dns.resolver.NXDOMAIN:
            pass  # No DMARC record found
        except dns.resolver.NoAnswer:
            pass  # No DMARC record found
        except Exception as e:
            # Debug: print the error but continue
            pass
        
        # Common DKIM selectors to check (expanded list with Zoho-specific selectors)
        dkim_selectors = [
            'default', 'google', 'k1', 'k2', 'mail', 'selector1', 'selector2', 'dkim', 's1', 's2',
            'zoho', 'zohomail', 'zohomailgroup1', 'zohomailgroup2', 'zoho1', 'zoho2',
            'mx', 'mx1', 'mx2', 'smtp', 'outbound', 'email', 'mailserver'
        ]
        for selector in dkim_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_answers = dns.resolver.resolve(dkim_domain, 'TXT')
                for answer in dkim_answers:
                    answer_str = str(answer).strip('"')
                    if 'k=' in answer_str or 'p=' in answer_str or 'v=DKIM1' in answer_str:
                        security_info['dkim']['present'] = True
                        security_info['dkim']['selectors_found'].append(selector)
                        security_info['dkim']['records'].append({
                            'selector': selector,
                            'record': answer_str
                        })
            except:
                continue
        
        # Check for CAA records
        try:
            caa_answers = dns.resolver.resolve(domain, 'CAA')
            security_info['caa']['present'] = True
            for answer in caa_answers:
                security_info['caa']['records'].append(str(answer))
        except:
            pass
        
        # Check for DNSSEC using DNSKEY records
        try:
            dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY')
            if dnskey_answers:
                security_info['dnssec']['enabled'] = True
                for answer in dnskey_answers:
                    # Extract algorithm info from DNSKEY record
                    dnskey_parts = str(answer).split()
                    if len(dnskey_parts) >= 4:
                        algorithm = dnskey_parts[2]
                        security_info['dnssec']['algorithms'].append(algorithm)
        except dns.resolver.NXDOMAIN:
            pass  # No DNSKEY records found
        except dns.resolver.NoAnswer:
            pass  # No DNSKEY records found
        except Exception as e:
            pass
        
        # Calculate security score with better weighting
        score = 0
        if security_info['spf']['present']: score += 20
        if security_info['dmarc']['present']: 
            score += 25
            # Bonus for strict DMARC policies
            if security_info['dmarc']['policy'] in ['reject', 'quarantine']:
                score += 10
        if security_info['dkim']['present']: score += 20
        if security_info['caa']['present']: score += 10
        if security_info['dnssec']['enabled']: score += 15
        
        # Additional scoring based on quality
        if security_info['spf']['valid']: score += 5
        if security_info['dmarc']['subdomain_policy'] in ['reject', 'quarantine']: score += 5
        
        security_info['security_score'] = min(score, 100)  # Cap at 100
        
        return security_info
    
    def _validate_spf(self, spf_record: str) -> bool:
        """Basic SPF record validation"""
        required_elements = ['v=spf1']
        ends_properly = spf_record.endswith(('~all', '-all', '?all', '+all'))
        
        return all(elem in spf_record for elem in required_elements) and ends_properly
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for domain"""
        print(f"📋 Fetching WHOIS information for {domain}...")
        
        try:
            w = python_whois.whois(domain)
            
            # Convert datetime objects to strings for JSON serialization
            whois_data = {}
            for key, value in w.items():
                if isinstance(value, datetime):
                    whois_data[key] = value.isoformat()
                elif isinstance(value, list):
                    # Handle lists that might contain datetime objects
                    converted_list = []
                    for item in value:
                        if isinstance(item, datetime):
                            converted_list.append(item.isoformat())
                        else:
                            converted_list.append(str(item) if item else None)
                    whois_data[key] = converted_list
                else:
                    whois_data[key] = str(value) if value else None
            
            # Add some analysis
            if whois_data.get('expiration_date'):
                try:
                    exp_date_str = whois_data['expiration_date']
                    if isinstance(exp_date_str, str):
                        exp_date = datetime.fromisoformat(exp_date_str.replace('Z', '+00:00'))
                        days_until_expiry = (exp_date - datetime.now()).days
                        whois_data['days_until_expiry'] = days_until_expiry
                        whois_data['expires_soon'] = days_until_expiry < 30
                except:
                    pass
            
            return whois_data
        
        except Exception as e:
            return {'error': str(e)}
    
    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        """Get IP address information for domain"""
        print(f"🌐 Resolving IP information for {domain}...")
        
        ip_data = {
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'reverse_dns': {},
            'cdn_detection': {},
            'load_balancer_detection': False
        }
        
        try:
            # Get IPv4 addresses
            ipv4_addresses = socket.getaddrinfo(domain, None, socket.AF_INET)
            unique_ipv4 = set()
            for addr in ipv4_addresses:
                ip = addr[4][0]
                unique_ipv4.add(ip)
            
            ip_data['ipv4_addresses'] = list(unique_ipv4)
            
            # Detect load balancing (multiple A records)
            if len(ip_data['ipv4_addresses']) > 1:
                ip_data['load_balancer_detection'] = True
            
            # Get IPv6 addresses
            try:
                ipv6_addresses = socket.getaddrinfo(domain, None, socket.AF_INET6)
                unique_ipv6 = set()
                for addr in ipv6_addresses:
                    ip = addr[4][0]
                    unique_ipv6.add(ip)
                ip_data['ipv6_addresses'] = list(unique_ipv6)
            except:
                pass
            
            # Reverse DNS lookup for IPv4 addresses
            for ip in ip_data['ipv4_addresses']:
                try:
                    reverse_name = socket.gethostbyaddr(ip)
                    ip_data['reverse_dns'][ip] = reverse_name[0]
                    
                    # CDN Detection based on reverse DNS
                    reverse_lower = reverse_name[0].lower()
                    cdns = {
                        'cloudflare': ['cloudflare'],
                        'aws': ['amazonaws', 'aws'],
                        'cloudfront': ['cloudfront'],
                        'fastly': ['fastly'],
                        'akamai': ['akamai'],
                        'maxcdn': ['maxcdn'],
                        'incapsula': ['incapsula'],
                        'sucuri': ['sucuri']
                    }
                    
                    for cdn_name, keywords in cdns.items():
                        if any(keyword in reverse_lower for keyword in keywords):
                            ip_data['cdn_detection'][ip] = cdn_name
                            break
                            
                except:
                    ip_data['reverse_dns'][ip] = 'No reverse DNS'
        
        except Exception as e:
            ip_data['error'] = str(e)
        
        return ip_data
    
    def get_ip_intelligence(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Get IP intelligence including ASN and geolocation"""
        print(f"🔍 Gathering IP intelligence...")
        
        intelligence = {}
        
        for ip in ip_addresses:
            try:
                print(f"  → Analyzing {ip}...")
                obj = IPWhois(ip)
                results = obj.lookup_rdap()
                
                # Debug: check what type results is
                if not isinstance(results, dict):
                    intelligence[ip] = {'error': f'IPWhois returned {type(results)} instead of dict'}
                    continue
                
                intelligence[ip] = {
                    'asn': results.get('asn'),
                    'asn_description': results.get('asn_description'),
                    'asn_country_code': results.get('asn_country_code'),
                    'asn_date': results.get('asn_date'),
                    'asn_registry': results.get('asn_registry'),
                    'network': {},
                    'entities': []
                }
                
                # Safely handle network data
                network_data = results.get('network', {})
                if isinstance(network_data, dict):
                    intelligence[ip]['network'] = {
                        'cidr': network_data.get('cidr'),
                        'name': network_data.get('name'),
                        'handle': network_data.get('handle'),
                        'start_address': network_data.get('start_address'),
                        'end_address': network_data.get('end_address'),
                        'country': network_data.get('country'),
                        'type': network_data.get('type')
                    }
                
                # Extract entity information
                if 'entities' in results and isinstance(results['entities'], list):
                    for entity in results['entities'][:3]:  # Limit to first 3 entities
                        if isinstance(entity, dict):
                            entity_info = {
                                'handle': entity.get('handle'),
                                'name': entity.get('name'),
                                'kind': entity.get('kind'),
                                'roles': entity.get('roles', [])
                            }
                            if entity.get('contact') and isinstance(entity.get('contact'), dict):
                                entity_info['contact'] = {
                                    'name': entity['contact'].get('name'),
                                    'kind': entity['contact'].get('kind')
                                }
                            intelligence[ip]['entities'].append(entity_info)
                
            except Exception as e:
                intelligence[ip] = {'error': str(e)}
        
        return intelligence
    
    def quick_port_scan(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """Perform a quick port scan on common ports"""
        print(f"🔍 Quick port scan on common ports...")
        
        port_results = {}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for ip in ip_addresses[:2]:  # Limit to first 2 IPs
            try:
                print(f"  → Scanning {ip}...")
                cmd = ['nmap', '-sS', '-O', '--top-ports', '100', '--max-retries', '1', 
                       '--host-timeout', '30s', ip]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    port_results[ip] = {
                        'scan_successful': True,
                        'open_ports': self._parse_nmap_output(result.stdout),
                        'os_detection': self._extract_os_info(result.stdout)
                    }
                else:
                    port_results[ip] = {'scan_successful': False, 'error': result.stderr}
                    
            except subprocess.TimeoutExpired:
                port_results[ip] = {'scan_successful': False, 'error': 'Scan timeout'}
            except FileNotFoundError:
                # Fallback to manual port checking
                port_results[ip] = self._manual_port_check(ip, common_ports[:5])
        
        return port_results
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output for open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    port_service = parts[0].split('/')
                    if len(port_service) >= 2:
                        open_ports.append({
                            'port': int(port_service[0]),
                            'protocol': port_service[1],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        })
        
        return open_ports
    
    def _extract_os_info(self, output: str) -> Dict[str, Any]:
        """Extract OS information from nmap output"""
        os_info = {'detected': False, 'os_matches': []}
        
        lines = output.split('\n')
        in_os_section = False
        
        for line in lines:
            if 'OS detection results' in line or 'Running:' in line:
                in_os_section = True
                os_info['detected'] = True
            elif in_os_section and line.strip():
                if 'OS:' in line or 'Running:' in line:
                    os_info['os_matches'].append(line.strip())
            elif in_os_section and not line.strip():
                break
        
        return os_info
    
    def _manual_port_check(self, ip: str, ports: List[int]) -> Dict[str, Any]:
        """Manual port checking when nmap is not available"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': 'unknown'
                    })
                sock.close()
            except:
                continue
        
        return {'scan_successful': True, 'open_ports': open_ports, 'method': 'manual'}
    
    def detect_technology_stack(self, domain: str) -> Dict[str, Any]:
        """Detect web technology stack"""
        print(f"🔧 Detecting technology stack for {domain}...")
        
        tech_info = {
            'web_server': 'unknown',
            'cms': 'unknown',
            'programming_language': 'unknown',
            'frameworks': [],
            'cdn': 'unknown',
            'headers': {},
            'ssl_info': {}
        }
        
        try:
            # Try HTTP first, then HTTPS
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{domain}"
                    response = requests.get(url, timeout=10, allow_redirects=True)
                    
                    # Analyze headers
                    tech_info['headers'] = dict(response.headers)
                    
                    # Web server detection
                    server_header = response.headers.get('Server', '').lower()
                    if 'apache' in server_header:
                        tech_info['web_server'] = 'Apache'
                    elif 'nginx' in server_header:
                        tech_info['web_server'] = 'Nginx'
                    elif 'iis' in server_header:
                        tech_info['web_server'] = 'IIS'
                    elif 'cloudflare' in server_header:
                        tech_info['cdn'] = 'Cloudflare'
                    
                    # CMS detection based on headers and content
                    x_powered_by = response.headers.get('X-Powered-By', '').lower()
                    if 'wordpress' in response.text.lower() or 'wp-content' in response.text:
                        tech_info['cms'] = 'WordPress'
                    elif 'drupal' in response.text.lower():
                        tech_info['cms'] = 'Drupal'
                    elif 'joomla' in response.text.lower():
                        tech_info['cms'] = 'Joomla'
                    
                    # Programming language detection
                    if 'php' in x_powered_by:
                        tech_info['programming_language'] = 'PHP'
                    elif 'asp.net' in x_powered_by:
                        tech_info['programming_language'] = 'ASP.NET'
                    
                    # Framework detection
                    if 'laravel' in response.text.lower():
                        tech_info['frameworks'].append('Laravel')
                    if 'react' in response.text.lower():
                        tech_info['frameworks'].append('React')
                    if 'vue' in response.text.lower():
                        tech_info['frameworks'].append('Vue.js')
                    
                    break  # Success, no need to try other protocol
                    
                except requests.RequestException:
                    continue
        
        except Exception as e:
            tech_info['error'] = str(e)
        
        return tech_info
    
    def comprehensive_subdomain_enum(self, domain: str, resolve_ips: bool = False) -> Dict[str, Any]:
        """Fast subdomain enumeration using subfinder"""
        print(f"🔍 Fast subdomain enumeration on {domain}...")
        
        subdomain_data = {
            'subdomains': {},
            'total_count': 0,
            'tools_used': [],
            'statistics': {}
        }
        
        all_subdomains = set()
        
        # Method 1: subfinder (primary tool)
        try:
            print("  → Running subfinder...")
            cmd = ['subfinder', '-d', domain, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                subfinder_subs = set(result.stdout.strip().split('\n'))
                subfinder_subs = {sub.strip() for sub in subfinder_subs if sub.strip() and sub != domain}
                all_subdomains.update(subfinder_subs)
                subdomain_data['tools_used'].append('subfinder')
                subdomain_data['statistics']['subfinder'] = len(subfinder_subs)
                print(f"    → Found {len(subfinder_subs)} subdomains with subfinder")
            else:
                print("    → subfinder failed")
                subdomain_data['statistics']['subfinder'] = 0
        except subprocess.TimeoutExpired:
            print("    → subfinder timeout")
            subdomain_data['statistics']['subfinder'] = 0
        except Exception as e:
            print(f"    → subfinder error: {str(e)[:50]}")
            subdomain_data['statistics']['subfinder'] = 0
        
        # Method 2: dnsrecon brute force (as backup if subfinder finds very few)
        if len(all_subdomains) < 5:  # Only run if subfinder didn't find much
            try:
                print("  → Running dnsrecon brute force...")
                wordlist_paths = [
                    '/usr/share/dnsrecon/subdomains-top1mil-5000.txt',
                    '/usr/share/wordlists/dnsmap.txt',
                    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
                ]
                
                for wordlist in wordlist_paths:
                    if os.path.exists(wordlist):
                        cmd = ['dnsrecon', '-d', domain, '-t', 'brt', '-D', wordlist]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        
                        dnsrecon_subs = set()
                        for line in result.stdout.split('\n'):
                            if '[A]' in line or '[AAAA]' in line:
                                match = re.search(r'(\S+\.' + re.escape(domain) + r')', line)
                                if match:
                                    dnsrecon_subs.add(match.group(1))
                        
                        new_from_dnsrecon = dnsrecon_subs - all_subdomains
                        all_subdomains.update(dnsrecon_subs)
                        subdomain_data['statistics']['dnsrecon'] = len(dnsrecon_subs)
                        subdomain_data['statistics']['dnsrecon_new'] = len(new_from_dnsrecon)
                        if 'dnsrecon' not in subdomain_data['tools_used']:
                            subdomain_data['tools_used'].append('dnsrecon')
                        print(f"    → Found {len(dnsrecon_subs)} subdomains with dnsrecon ({len(new_from_dnsrecon)} new)")
                        break
            except Exception as e:
                print(f"    → dnsrecon error: {str(e)[:50]}")
                subdomain_data['statistics']['dnsrecon'] = 0
        
        # Method 3: Common subdomain check (basic fallback)
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn', 'blog', 'app', 'portal', 'secure', 'vpn', 'remote']
        common_found = 0
        for sub in common_subs:
            full_domain = f"{sub}.{domain}"
            if full_domain not in all_subdomains:
                try:
                    dns.resolver.resolve(full_domain, 'A')
                    all_subdomains.add(full_domain)
                    common_found += 1
                except:
                    continue
        
        if common_found > 0:
            subdomain_data['statistics']['common_check'] = common_found
            if 'common_check' not in subdomain_data['tools_used']:
                subdomain_data['tools_used'].append('common_check')
            print(f"    → Found {common_found} additional subdomains with common check")
        
        # Store subdomains with optional IP resolution
        if resolve_ips:
            print(f"  → Resolving IP addresses for {len(all_subdomains)} subdomains...")
            resolved_count = 0
            for i, subdomain in enumerate(sorted(all_subdomains)):
                if subdomain and subdomain != domain:
                    # Show progress every 50 subdomains
                    if i % 50 == 0 and i > 0:
                        print(f"    → Progress: {i}/{len(all_subdomains)} subdomains processed...")
                    
                    try:
                        # Try both A and AAAA records with shorter timeout
                        ips = []
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = 2  # 2 second timeout
                            resolver.lifetime = 2
                            a_records = resolver.resolve(subdomain, 'A')
                            ips.extend([str(record) for record in a_records])
                        except:
                            pass
                        
                        try:
                            resolver = dns.resolver.Resolver()
                            resolver.timeout = 2
                            resolver.lifetime = 2
                            aaaa_records = resolver.resolve(subdomain, 'AAAA')
                            ips.extend([str(record) for record in aaaa_records])
                        except:
                            pass
                        
                        if ips:
                            subdomain_data['subdomains'][subdomain] = {
                                'subdomain': subdomain,
                                'ips': ips,
                                'ipv4_count': len([ip for ip in ips if ':' not in ip]),
                                'ipv6_count': len([ip for ip in ips if ':' in ip])
                            }
                            resolved_count += 1
                        else:
                            # Subdomain exists but no A/AAAA records (might have CNAME only)
                            subdomain_data['subdomains'][subdomain] = {
                                'subdomain': subdomain,
                                'ips': [],
                                'note': 'No A/AAAA records found'
                            }
                    except Exception as e:
                        # Subdomain might have been removed or is unreachable
                        continue
            
            print(f"  → Successfully resolved IPs for: {resolved_count} subdomains")
        else:
            print(f"  → Storing {len(all_subdomains)} subdomains (skipping IP resolution for speed)...")
            for subdomain in sorted(all_subdomains):
                if subdomain and subdomain != domain:
                    subdomain_data['subdomains'][subdomain] = {
                        'subdomain': subdomain,
                        'ips': [],  # Empty for speed
                        'note': 'IP resolution skipped for performance'
                    }
        
        subdomain_data['total_count'] = len(subdomain_data['subdomains'])
        
        print(f"  → ✅ Total unique subdomains found: {subdomain_data['total_count']}")
        print(f"  → Tools used: {', '.join(subdomain_data['tools_used'])}")
        
        return subdomain_data
    
    def run_reconnaissance(self, domain: str, full_scan: bool = True, resolve_ips: bool = False) -> Dict[str, Any]:
        """Run complete reconnaissance on target domain"""
        print(f"\n🎯 Starting reconnaissance on: {domain}")
        print("=" * 60)
        
        self.results['target'] = domain
        
        # Basic DNS Records
        self.results['dns_records'] = self.get_dns_records(domain)
        
        # Security Records Analysis
        self.results['security_records'] = self.analyze_security_records(domain, self.results['dns_records'])
        
        # WHOIS Information
        self.results['whois_info'] = self.get_whois_info(domain)
        
        # IP Information
        self.results['ip_info'] = self.get_ip_info(domain)
        
        # IP Intelligence
        if self.results['ip_info'].get('ipv4_addresses'):
            self.results['ip_intelligence'] = self.get_ip_intelligence(
                self.results['ip_info']['ipv4_addresses']
            )
        
        if full_scan:
            # Technology Stack Detection
            self.results['technology_stack'] = self.detect_technology_stack(domain)
            
            # Fast Subdomain Enumeration
            try:
                comprehensive_subdomains = self.comprehensive_subdomain_enum(domain, resolve_ips=resolve_ips)
                self.results['comprehensive_subdomains'] = comprehensive_subdomains
                # Convert to old format for compatibility with display code
                subdomain_list = []
                for subdomain, data in comprehensive_subdomains['subdomains'].items():
                    subdomain_list.append({
                        'subdomain': subdomain,
                        'ips': data.get('ips', []),
                        'method': 'comprehensive'
                    })
                self.results['subdomain_enum'] = subdomain_list
            except Exception as e:
                print(f"  → Subdomain enum failed, falling back to basic method...")
                # Fallback to original dnsrecon method
                try:
                    dnsrecon_results = self.run_dnsrecon(domain)
                    self.results['dnsrecon'] = dnsrecon_results
                    self.results['subdomain_enum'] = dnsrecon_results.get('subdomain_enum', [])
                except Exception as e2:
                    self.results['subdomain_enum'] = []
                    self.results['dnsrecon'] = {'error': str(e2)}
            
            # Quick Port Scan
            if self.results['ip_info'].get('ipv4_addresses'):
                self.results['port_scan'] = self.quick_port_scan(
                    self.results['ip_info']['ipv4_addresses']
                )
        
        return self.results
    
    def display_results(self):
        """Display results in a formatted way"""
        print("\n" + "=" * 80)
        print("🎯 RECONNAISSANCE RESULTS")
        print("=" * 80)
        
        # Target info
        print(f"Target: {self.results['target']}")
        print(f"Scan Time: {self.results['timestamp']}")
        print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # DNS Records Summary
        print("\n📡 DNS RECORDS SUMMARY:")
        dns_records = self.results['dns_records']
        for record_type, records in dns_records.items():
            if isinstance(records, list) and records:
                print(f"  {record_type:6}: {len(records)} record(s)")
                if record_type == 'A':
                    for record in records[:3]:
                        print(f"         → {record}")
                elif record_type == 'MX':
                    for record in records[:3]:
                        if isinstance(record, dict):
                            print(f"         → {record['priority']:2} {record['exchange']}")
            elif isinstance(records, dict) and 'error' not in records:
                print(f"  {record_type:6}: Complex record found")
        
        # Security Analysis
        print("\n🔒 SECURITY ANALYSIS:")
        sec = self.results['security_records']
        print(f"  SPF Record:   {'✅ Present' if sec['spf']['present'] else '❌ Missing'}")
        if sec['spf']['present']:
            print(f"    Valid:      {'✅ Yes' if sec['spf']['valid'] else '❌ No'}")
            print(f"    Mechanisms: {len(sec['spf']['mechanisms'])}")
        
        print(f"  DMARC Policy: {'✅ Present' if sec['dmarc']['present'] else '❌ Missing'}")
        if sec['dmarc']['present']:
            print(f"    Policy:     {sec['dmarc']['policy']}")
        
        print(f"  DKIM Setup:   {'✅ Present' if sec['dkim']['present'] else '❌ Missing'}")
        if sec['dkim']['present']:
            print(f"    Selectors:  {', '.join(sec['dkim']['selectors_found'])}")
        
        print(f"  CAA Records:  {'✅ Present' if sec['caa']['present'] else '❌ Missing'}")
        print(f"  DNSSEC:       {'✅ Enabled' if sec['dnssec']['enabled'] else '❌ Disabled'}")
        if sec['dnssec']['enabled'] and sec['dnssec']['algorithms']:
            print(f"    Algorithms: {', '.join(set(sec['dnssec']['algorithms']))}")
        print(f"  Security Score: {sec['security_score']}/100")
        
        # IP Information
        print("\n🌐 IP INFORMATION:")
        ip_info = self.results['ip_info']
        if ip_info.get('ipv4_addresses'):
            print(f"  IPv4: {', '.join(ip_info['ipv4_addresses'])}")
            if ip_info.get('load_balancer_detection'):
                print("  Load Balancer: ✅ Detected (Multiple A records)")
        
        if ip_info.get('ipv6_addresses'):
            print(f"  IPv6: {', '.join(ip_info['ipv6_addresses'][:2])}...")
        
        if ip_info.get('cdn_detection'):
            cdns = list(ip_info['cdn_detection'].values())
            print(f"  CDN Detected: {', '.join(set(cdns))}")
        
        # IP Intelligence Summary
        if self.results.get('ip_intelligence'):
            print("\n🔍 IP INTELLIGENCE:")
            for ip, intel in list(self.results['ip_intelligence'].items())[:2]:
                # Check if intel is a dictionary and has valid data
                if isinstance(intel, dict) and 'error' not in intel and intel:
                    print(f"  {ip}:")
                    asn = intel.get('asn', 'Unknown')
                    asn_desc = intel.get('asn_description', 'Unknown')
                    if asn_desc and isinstance(asn_desc, str) and len(asn_desc) > 50:
                        asn_desc = asn_desc[:50] + "..."
                    print(f"    ASN: {asn} ({asn_desc})")
                    print(f"    Country: {intel.get('asn_country_code', 'Unknown')}")
                    if intel.get('network', {}) and isinstance(intel.get('network'), dict):
                        network = intel['network']
                        if network.get('cidr'):
                            print(f"    Network: {network['cidr']}")
                        if network.get('name'):
                            isp_name = network['name']
                            if isinstance(isp_name, str) and len(isp_name) > 40:
                                isp_name = isp_name[:40] + "..."
                            print(f"    ISP: {isp_name}")
                elif isinstance(intel, dict) and 'error' in intel:
                    print(f"  {ip}: ❌ {intel['error']}")
                elif isinstance(intel, str):
                    # Handle case where intel is an error string instead of dict
                    print(f"  {ip}: ❌ {intel}")
                else:
                    print(f"  {ip}: ❌ Invalid data format")
        else:
            print("\n🔍 IP INTELLIGENCE:")
            print("  ❌ No IP intelligence data available")
        
        # Technology Stack
        if self.results.get('technology_stack'):
            print("\n🔧 TECHNOLOGY STACK:")
            tech = self.results['technology_stack']
            if tech.get('web_server') != 'unknown':
                print(f"  Web Server: {tech['web_server']}")
            if tech.get('cms') != 'unknown':
                print(f"  CMS: {tech['cms']}")
            if tech.get('programming_language') != 'unknown':
                print(f"  Language: {tech['programming_language']}")
            if tech.get('frameworks'):
                print(f"  Frameworks: {', '.join(tech['frameworks'])}")
            if tech.get('cdn') != 'unknown':
                print(f"  CDN: {tech['cdn']}")
        
        # Subdomain Enumeration
        if self.results.get('comprehensive_subdomains'):
            comp_subs = self.results['comprehensive_subdomains']
            total_found = comp_subs['total_count']
            tools_used = ', '.join(comp_subs['tools_used'])
            
            print(f"\n🔍 SUBDOMAIN ENUMERATION: ({total_found} found)")
            print(f"  Tools used: {tools_used}")
            
            # Show statistics
            stats = comp_subs['statistics']
            for tool, count in stats.items():
                if tool.endswith('_new'):
                    continue
                print(f"  {tool}: {count} subdomains", end="")
                if f"{tool}_new" in stats:
                    print(f" ({stats[f'{tool}_new']} unique)")
                else:
                    print()
            
            # Show top subdomains
            if comp_subs['subdomains']:
                print(f"\n  📋 Top subdomains (showing first 10):")
                shown = 0
                for subdomain, data in list(comp_subs['subdomains'].items())[:10]:
                    ips = data.get('ips', [])
                    if ips:
                        # Show first 2 IPs if multiple
                        ip_display = ', '.join(ips[:2])
                        if len(ips) > 2:
                            ip_display += f" (+{len(ips) - 2} more)"
                        print(f"    → {subdomain} → {ip_display}")
                    else:
                        note = data.get('note', 'No IP resolved')
                        if 'skipped for performance' in note:
                            print(f"    → {subdomain}")
                        else:
                            print(f"    → {subdomain} → {note}")
                    shown += 1
                
                if total_found > 10:
                    print(f"    ... and {total_found - 10} more subdomains")
                    
                # Show tip about IP resolution
                if any('skipped for performance' in data.get('note', '') for data in comp_subs['subdomains'].values()):
                    print(f"\n  💡 Tip: Use --resolve-ips flag to resolve IP addresses (slower)")
            else:
                print("  ❌ No valid subdomains resolved")
                
        elif self.results.get('subdomain_enum'):
            subdomains = self.results['subdomain_enum']
            if isinstance(subdomains, list) and subdomains:
                print(f"\n🔍 SUBDOMAIN ENUMERATION: ({len(subdomains)} found)")
                valid_subdomains = 0
                for subdomain in subdomains[:5]:
                    if isinstance(subdomain, dict):
                        subdomain_name = subdomain.get('subdomain', 'N/A')
                        # Skip if subdomain name is missing or N/A
                        if subdomain_name == 'N/A' or not subdomain_name:
                            continue
                        
                        # Handle both old format (single IP) and new format (multiple IPs)
                        if 'ips' in subdomain and subdomain['ips']:
                            ips = ', '.join(subdomain['ips'])
                        else:
                            ips = subdomain.get('ip', 'N/A')
                        
                        # Skip if IP is N/A
                        if ips == 'N/A' or not ips:
                            print(f"  → {subdomain_name} → Failed to resolve")
                        else:
                            print(f"  → {subdomain_name} → {ips}")
                            valid_subdomains += 1
                
                if valid_subdomains == 0:
                    print("  ❌ No valid subdomains found")
                elif len(subdomains) > 5:
                    print(f"  ... and {len(subdomains) - 5} more")
            else:
                print("\n🔍 SUBDOMAIN ENUMERATION:")
                print("  ❌ No subdomains discovered")
        else:
            print("\n🔍 SUBDOMAIN ENUMERATION:")
            print("  ❌ No subdomain data available")
        
        # Port Scan Results
        if self.results.get('port_scan'):
            print("\n🔍 PORT SCAN RESULTS:")
            for ip, scan_result in self.results['port_scan'].items():
                if scan_result.get('scan_successful'):
                    open_ports = scan_result.get('open_ports', [])
                    print(f"  {ip}: {len(open_ports)} open ports")
                    for port in open_ports[:5]:
                        print(f"    → {port['port']}/{port['protocol']} ({port['service']})")
        
        # WHOIS Summary
        print("\n📋 WHOIS SUMMARY:")
        whois_info = self.results['whois_info']
        if 'error' not in whois_info and whois_info:
            print(f"  Registrar: {whois_info.get('registrar', 'N/A')}")
            print(f"  Created: {whois_info.get('creation_date', 'N/A')}")
            print(f"  Expires: {whois_info.get('expiration_date', 'N/A')}")
            if whois_info.get('expires_soon'):
                print("  ⚠️  Domain expires within 30 days!")
            if whois_info.get('country'):
                print(f"  Country: {whois_info['country']}")
            if whois_info.get('registrant_name'):
                print(f"  Registrant: {whois_info['registrant_name']}")
            if whois_info.get('admin_email'):
                print(f"  Admin Email: {whois_info['admin_email']}")
        elif 'error' in whois_info:
            print(f"  ❌ Error: {whois_info['error']}")
        else:
            print("  ❌ No WHOIS information available")
        
        print("\n" + "=" * 80)
        print("🔧 Made by: DEBASIS (hello@debasisbiswas.me)")
        print("⚖️  For educational purposes only - Not for illegal activities")
        print("=" * 80)
    
    def save_results(self, filename: str):
        """Save results to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"\n💾 Results saved to: {filename}")
            print(f"📁 File size: {os.path.getsize(filename)} bytes")
        except Exception as e:
            print(f"❌ Error saving results: {e}")
    
    def export_summary_report(self, filename: str):
        """Export a summary report in text format"""
        try:
            with open(filename, 'w') as f:
                f.write("RECONLITE - DOMAIN RECONNAISSANCE REPORT\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Target Domain: {self.results['target']}\n")
                f.write(f"Scan Date: {self.results['timestamp']}\n\n")
                
                # Security Summary
                sec = self.results['security_records']
                f.write("SECURITY POSTURE:\n")
                f.write(f"- SPF: {'Present' if sec['spf']['present'] else 'Missing'}\n")
                f.write(f"- DMARC: {'Present' if sec['dmarc']['present'] else 'Missing'}\n")
                f.write(f"- DKIM: {'Present' if sec['dkim']['present'] else 'Missing'}\n")
                f.write(f"- Security Score: {sec['security_score']}/100\n\n")
                
                # IP Summary
                f.write("IP ADDRESSES:\n")
                for ip in self.results['ip_info'].get('ipv4_addresses', []):
                    f.write(f"- {ip}\n")
                f.write("\n")
                
                # Technology Stack
                if self.results.get('technology_stack'):
                    tech = self.results['technology_stack']
                    f.write("TECHNOLOGY STACK:\n")
                    f.write(f"- Web Server: {tech.get('web_server', 'Unknown')}\n")
                    f.write(f"- CMS: {tech.get('cms', 'Unknown')}\n")
                    f.write(f"- Language: {tech.get('programming_language', 'Unknown')}\n")
                
            print(f"📄 Summary report saved to: {filename}")
        except Exception as e:
            print(f"❌ Error saving summary report: {e}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='ReconLite - Advanced Cyber Reconnaissance Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reconlite.py example.com
  python reconlite.py example.com -o results.json
  python reconlite.py example.com --quick --quiet
  python reconlite.py example.com --resolve-ips
  python reconlite.py example.com --export-summary report.txt
        """
    )
    
    parser.add_argument('domain', help='Target domain to reconnaissance')
    parser.add_argument('-o', '--output', help='Output JSON file', default='recon_results.json')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip dnsrecon and port scan)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--resolve-ips', action='store_true', help='Resolve IP addresses for subdomains (slower but more detailed)')
    parser.add_argument('--export-summary', help='Export summary report to text file')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for operations (default: 30s)')
    
    args = parser.parse_args()
    
    # Validate domain
    domain = args.domain.lower().strip()
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).netloc
    
    # Initialize tool
    tool = ReconLite()
    tool.timeout = args.timeout
    
    if not args.quiet:
        tool.banner()
        print(f"🎯 Target: {domain}")
        print(f"📊 Mode: {'Quick' if args.quick else 'Full'} scan")
        
        # Check dependencies
        available_tools = tool.check_dependencies()
        if not args.quick and not available_tools.get('dnsrecon', False):
            print("⚠️  dnsrecon not available, some features will be limited")
    
    try:
        # Run reconnaissance
        start_time = time.time()
        results = tool.run_reconnaissance(domain, full_scan=not args.quick, resolve_ips=args.resolve_ips)
        end_time = time.time()
        
        # Display results
        if not args.quiet:
            tool.display_results()
            print(f"\n⏱️  Scan completed in {end_time - start_time:.2f} seconds")
        
        # Save results
        tool.save_results(args.output)
        
        # Export summary if requested
        if args.export_summary:
            tool.export_summary_report(args.export_summary)
        
        print(f"\n✅ Reconnaissance completed successfully!")
        print(f"📊 Full results saved to: {args.output}")
        
        # Security recommendations
        sec_score = results['security_records']['security_score']
        if sec_score < 50:
            print("\n⚠️  SECURITY RECOMMENDATIONS:")
            if not results['security_records']['spf']['present']:
                print("  - Implement SPF record to prevent email spoofing")
            if not results['security_records']['dmarc']['present']:
                print("  - Configure DMARC policy for email authentication")
            if not results['security_records']['dkim']['present']:
                print("  - Set up DKIM signing for email integrity")
        
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()