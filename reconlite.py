#!/usr/bin/env python3
"""
ReconLite - Advanced Cyber Reconnaissance Tool
A comprehensive Python-based reconnaissance tool for DNS and domain information gathering.
Perfect for ethical hacking, Red Team operations, and vulnerability assessments.

💻 CLI-only tool for advanced users

Features:
- DNS Enumeration using Python libraries
- WHOIS Lookup
- IP Address Resolution & Intelligence
- Security Records Analysis (SPF, DMARC, DKIM)
- JSON Export for further analysis
- Command-line Interface

Author: DEBASIS (hello@debasisbiswas.me)
Version: 1.0

⚖️ LEGAL DISCLAIMER:
This tool is intended for educational purposes and authorized security testing only.
Users are responsible for ensuring they have proper authorization before scanning any
domains or networks. Unauthorized scanning may violate laws and regulations.
The author is not responsible for any misuse of this tool.
"""

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

import dns.query
import dns.rdatatype
import dns.zone

# Version and tool information
__version__ = "1.0.0"
__author__ = "DEBASIS"
__email__ = "hello@debasisbiswas.me"
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
║   Tech Stack: python-whois | ipwhois | dnspython | requests                 ║
║                                                                              ║
║   Made by: DEBASIS (hello@debasisbiswas.me)                                 ║
║   ⚖️  For Educational Purposes Only - Not for Illegal Activities            ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """)
    
    def check_dependencies(self):
        """Check the required Python dependencies."""
        dependencies = {
            'python-whois': True,
            'ipwhois': True,
            'dnspython': True,
            'requests': True,
        }
        return dependencies
    
    def run_dns_enumeration(self, domain: str) -> Dict[str, Any]:
        """Run Python-only DNS enumeration for compatibility with older code paths."""
        print(f"🔍 Running DNS enumeration on {domain}...")

        dns_data = {
            'standard_records': self.get_dns_records(domain),
            'zone_transfer': self._attempt_zone_transfer(domain),
            'subdomain_enum': [],
            'raw_output': '',
            'mx_enum': [],
            'srv_enum': []
        }

        standard_records = dns_data['standard_records']
        for record in standard_records.get('MX', []):
            if isinstance(record, dict):
                dns_data['mx_enum'].append({
                    'domain': domain,
                    'priority': record.get('priority'),
                    'exchange': record.get('exchange')
                })

        for record in standard_records.get('SRV', []):
            if isinstance(record, dict):
                dns_data['srv_enum'].append({
                    'service': record.get('service'),
                    'priority': record.get('priority'),
                    'weight': record.get('weight'),
                    'port': record.get('port'),
                    'target': record.get('target')
                })

        try:
            subdomain_results = self.comprehensive_subdomain_enum(domain, resolve_ips=True)
            dns_data['subdomain_enum'] = list(subdomain_results.get('subdomains', {}).values())
        except Exception as e:
            dns_data['subdomain_enum'] = [{'error': str(e)}]

        dns_data['raw_output'] = self._format_dns_summary(domain, dns_data)
        return dns_data

    def _attempt_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt an AXFR zone transfer using dnspython."""
        zone_data = {
            'attempted': True,
            'successful': False,
            'nameservers': [],
            'records': []
        }

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 4
            resolver.lifetime = 4
            nameservers = [str(answer).rstrip('.') for answer in resolver.resolve(domain, 'NS')]
            zone_data['nameservers'] = nameservers

            for nameserver in nameservers:
                server = nameserver
                try:
                    server = socket.gethostbyname(nameserver)
                except Exception:
                    pass

                try:
                    transfer = dns.query.xfr(server, domain, lifetime=10)
                    zone = dns.zone.from_xfr(transfer)
                    if zone is None:
                        continue

                    zone_data['successful'] = True
                    for relative_name, node in zone.nodes.items():
                        record_name = relative_name.to_text()
                        if record_name == '@':
                            record_name = domain
                        else:
                            record_name = f"{record_name}.{domain}"

                        for rdataset in node.rdatasets:
                            record_type = dns.rdatatype.to_text(rdataset.rdtype)
                            for rdata in rdataset:
                                zone_data['records'].append({
                                    'name': record_name.rstrip('.'),
                                    'type': record_type,
                                    'value': rdata.to_text()
                                })
                    break
                except Exception:
                    continue
        except Exception as e:
            zone_data['error'] = str(e)

        return zone_data

    def _format_dns_summary(self, domain: str, dns_data: Dict[str, Any]) -> str:
        """Build a compact text summary for DNS results."""
        lines = [f"DNS summary for {domain}"]
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DNSKEY']:
            records = dns_data.get('standard_records', {}).get(record_type, [])
            if isinstance(records, list) and records:
                lines.append(f"{record_type}: {len(records)} record(s)")
        zone_transfer = dns_data.get('zone_transfer', {})
        if zone_transfer.get('successful'):
            lines.append(f"AXFR successful via {', '.join(zone_transfer.get('nameservers', []))}")
        return "\n".join(lines)
    
    def get_dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records using dnspython"""
        print(f"📡 Gathering DNS records for {domain}...")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'DNSKEY']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 4
                resolver.lifetime = 4
                answers = resolver.resolve(domain, record_type)
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
                    elif record_type == 'SRV':
                        records[record_type].append({
                            'priority': answer.priority,
                            'weight': answer.weight,
                            'port': answer.port,
                            'target': str(answer.target).rstrip('.')
                        })
                    elif record_type == 'CAA':
                        records[record_type].append({
                            'flags': answer.flags,
                            'tag': answer.tag,
                            'value': answer.value
                        })
                    elif record_type == 'DNSKEY':
                        records[record_type].append({
                            'flags': answer.flags,
                            'protocol': answer.protocol,
                            'algorithm': answer.algorithm,
                            'key': answer.key
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
        """Perform a quick port scan on common ports using Python sockets only."""
        print(f"🔍 Quick port scan on common ports...")

        port_results = {}
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 5432, 8080, 8443]

        for ip in ip_addresses[:2]:
            print(f"  → Scanning {ip}...")
            open_ports = []

            for port in common_ports:
                try:
                    with socket.create_connection((ip, port), timeout=1.25):
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except OSError:
                            service = 'unknown'

                        open_ports.append({
                            'port': port,
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': service
                        })
                except (socket.timeout, OSError):
                    continue

            port_results[ip] = {
                'scan_successful': True,
                'open_ports': open_ports,
                'os_detection': {'detected': False, 'os_matches': []},
                'method': 'python_socket'
            }

        return port_results
    
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
    
    def _common_subdomain_candidates(self) -> List[str]:
        """Return a built-in list of common subdomain labels."""
        return [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn', 'blog',
            'app', 'portal', 'secure', 'vpn', 'remote', 'shop', 'store', 'login', 'auth', 'm',
            'dev-api', 'status', 'support', 'docs', 'help', 'webmail', 'mail1', 'smtp', 'imap', 'pop',
            'ns1', 'ns2', 'gw', 'gateway', 'edge', 'images', 'static', 'assets', 'files', 'download',
            'beta', 'preview', 'beta-api', 'internal', 'intranet', 'vpn1', 'mail2', 'mx', 'calendar', 'events'
        ]

    def _fetch_crtsh_subdomains(self, domain: str) -> List[str]:
        """Fetch passive subdomain candidates from crt.sh."""
        discovered = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        try:
            response = requests.get(url, timeout=20, headers={'User-Agent': 'ReconLite/1.0'})
            response.raise_for_status()
            certs = response.json()

            if isinstance(certs, dict):
                certs = [certs]

            for cert in certs:
                name_value = cert.get('name_value', '') if isinstance(cert, dict) else ''
                for name in str(name_value).splitlines():
                    name = name.strip().lower().lstrip('*.')
                    if name.endswith(domain.lower()) and name != domain.lower():
                        discovered.add(name)
        except Exception:
            return []

        return sorted(discovered)

    def _probe_subdomain(self, subdomain: str) -> List[str]:
        """Resolve A and AAAA records for a subdomain."""
        ips = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        for record_type in ['A', 'AAAA']:
            try:
                answers = resolver.resolve(subdomain, record_type)
                ips.extend([str(answer) for answer in answers])
            except Exception:
                continue

        return sorted(set(ips))

    def comprehensive_subdomain_enum(self, domain: str, resolve_ips: bool = False) -> Dict[str, Any]:
        """Enumerate subdomains using passive certificate data and built-in DNS probes."""
        print(f"🔍 Subdomain enumeration on {domain}...")

        subdomain_data = {
            'subdomains': {},
            'total_count': 0,
            'methods_used': [],
            'statistics': {}
        }

        all_subdomains = set()

        print("  → Querying certificate transparency data...")
        crtsh_subdomains = self._fetch_crtsh_subdomains(domain)
        if crtsh_subdomains:
            all_subdomains.update(crtsh_subdomains)
            subdomain_data['methods_used'].append('crtsh')
            subdomain_data['statistics']['crtsh'] = len(crtsh_subdomains)
            print(f"    → Found {len(crtsh_subdomains)} candidates from crt.sh")
        else:
            subdomain_data['statistics']['crtsh'] = 0

        print("  → Probing common subdomain names...")
        common_found = 0
        for candidate in self._common_subdomain_candidates():
            full_domain = f"{candidate}.{domain}"
            ips = self._probe_subdomain(full_domain)
            if ips:
                all_subdomains.add(full_domain)
                common_found += 1
                if resolve_ips:
                    subdomain_data['subdomains'][full_domain] = {
                        'subdomain': full_domain,
                        'ips': ips,
                        'ipv4_count': len([ip for ip in ips if ':' not in ip]),
                        'ipv6_count': len([ip for ip in ips if ':' in ip]),
                        'method': 'common_dns'
                    }

        if common_found > 0:
            subdomain_data['methods_used'].append('common_dns')
            subdomain_data['statistics']['common_dns'] = common_found
            print(f"    → Found {common_found} subdomains with built-in DNS probes")
        else:
            subdomain_data['statistics']['common_dns'] = 0

        if resolve_ips:
            remaining_subdomains = sorted(all_subdomains - set(subdomain_data['subdomains'].keys()))
            if remaining_subdomains:
                print(f"  → Resolving IP addresses for {len(remaining_subdomains)} additional subdomains...")

            resolved_count = len(subdomain_data['subdomains'])
            for index, subdomain in enumerate(remaining_subdomains):
                if index and index % 50 == 0:
                    print(f"    → Progress: {index}/{len(remaining_subdomains)} subdomains processed...")

                ips = self._probe_subdomain(subdomain)
                if ips:
                    subdomain_data['subdomains'][subdomain] = {
                        'subdomain': subdomain,
                        'ips': ips,
                        'ipv4_count': len([ip for ip in ips if ':' not in ip]),
                        'ipv6_count': len([ip for ip in ips if ':' in ip]),
                        'method': 'crtsh'
                    }
                    resolved_count += 1

            print(f"  → Successfully resolved IPs for: {resolved_count} subdomains")
        else:
            print(f"  → Storing {len(all_subdomains)} subdomains (skipping IP resolution for speed)...")
            for subdomain in sorted(all_subdomains):
                subdomain_data['subdomains'][subdomain] = {
                    'subdomain': subdomain,
                    'ips': [],
                    'note': 'IP resolution skipped for performance'
                }

        subdomain_data['total_count'] = len(subdomain_data['subdomains'])

        print(f"  → ✅ Total unique subdomains found: {subdomain_data['total_count']}")
        print(f"  → Methods used: {', '.join(subdomain_data['methods_used']) if subdomain_data['methods_used'] else 'none'}")

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
                print(f"  → Subdomain enumeration failed: {e}")
                self.results['subdomain_enum'] = []
                self.results['dns_enumeration'] = {'error': str(e)}
            
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
  reconlite example.com
  reconlite example.com -o results.json
  reconlite example.com --quick --quiet
  reconlite example.com --resolve-ips
  reconlite example.com --export-summary report.txt
  reconlite --version
  reconlite -V
        """
    )
    
    parser.add_argument('domain', nargs='?', help='Target domain to reconnaissance')
    parser.add_argument('-o', '--output', help='Output JSON file', default='recon_results.json')
    parser.add_argument('--quick', action='store_true', help='Quick scan (skip subdomain enumeration and port scan)')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--resolve-ips', action='store_true', help='Resolve IP addresses for subdomains (slower but more detailed)')
    parser.add_argument('--export-summary', help='Export summary report to text file')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout for operations (default: 30s)')
    parser.add_argument('-v', '--version', action='version', 
                        version=f'ReconLite {__version__}',
                        help='Show version information')
    parser.add_argument('-V', '--Version', action='store_true', 
                        help='Show detailed version information')
    
    args = parser.parse_args()
    
    # Handle detailed version display
    if args.Version:
        print(f"""
🔍 ReconLite - Advanced Cyber Reconnaissance Tool
===============================================

Version: {__version__}
Author:  {__author__}
Email:   {__email__}
GitHub:  {__github__}

💻 CLI-only Version: Command-line tool for advanced users

Features:
- DNS Enumeration & Analysis
- Passive and active Subdomain Discovery
- WHOIS Information Gathering
- IP Intelligence & Geolocation
- Security Records Analysis (SPF, DMARC, DKIM)
- Technology Stack Detection
- Port Scanning & Service Detection
- JSON Export & Summary Reports

⚖️  For Educational & Authorized Testing Only
""")
        sys.exit(0)
    
    # Validate domain is provided (unless showing version)
    if not args.domain:
        parser.error("Domain argument is required")
    
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