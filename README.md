# 🔍 ReconLite - Advanced Cyber Reconnaissance Tool

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🔍 RECONLITE TOOL                                 ║
║                                                                              ║
║   Advanced DNS & Domain Intelligence Gathering Tool                         ║
║   Perfect for Ethical Hacking, Red Team Ops & Vulnerability Assessment      ║
║                                                                              ║
║   Features: DNS Enum | WHOIS | IP Intel | Security Records | JSON Export    ║
║   Tech Stack: subfinder | python-whois | ipwhois | dnspython                ║
║                                                                              ║
║   Made by: DEBASIS (hello@debasisbiswas.me)                                 ║
║   ⚖️  For Educational Purposes Only - Not for Illegal Activities            ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com)

## 📋 Table of Contents
- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Output Formats](#-output-formats)
- [Legal Disclaimer](#️-legal-disclaimer)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

## 🎯 Overview

**ReconLite** is a comprehensive Python-based reconnaissance tool designed for DNS and domain information gathering. It's perfect for ethical hackers, red team operators, penetration testers, and cybersecurity professionals who need to perform thorough domain reconnaissance.

The tool combines multiple reconnaissance techniques and presents the results in a clean, organized format with both terminal output and JSON export capabilities.

## ✨ Features

### 🔍 Core Reconnaissance Capabilities
- **DNS Enumeration**: Complete DNS record gathering (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Fast Subdomain Discovery**: Powered by subfinder for rapid subdomain enumeration
- **WHOIS Information**: Comprehensive domain registration details
- **IP Intelligence**: ASN lookup, geolocation, and ISP information
- **Technology Stack Detection**: Web server, CMS, frameworks identification
- **Port Scanning**: Quick scan of common ports with service detection

### 🔒 Security Analysis
- **SPF Record Analysis**: Email security policy validation
- **DMARC Policy Check**: Domain-based Message Authentication reporting
- **DKIM Detection**: DomainKeys Identified Mail signature verification
- **DNSSEC Validation**: DNS Security Extensions status
- **CAA Records**: Certificate Authority Authorization check
- **Security Scoring**: Overall domain security posture (0-100 scale)

### 📊 Output & Export
- **Beautiful Terminal Output**: Color-coded, organized results display
- **JSON Export**: Machine-readable format for integration
- **Summary Reports**: Text-based executive summaries
- **Performance Optimized**: Fast scans with optional detailed analysis

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- Internet connection
- Linux, macOS, or Windows

### Step 1: Clone the Repository
```bash
git clone https://github.com/debasisbiswas/reconlite.git
cd reconlite
```

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Install System Tools

#### On Kali Linux / Ubuntu / Debian:
```bash
sudo apt update
sudo apt install dnsrecon dnsutils nmap subfinder
```

#### On Arch Linux:
```bash
sudo pacman -S dnsrecon bind nmap
yay -S subfinder
```

#### On CentOS / RHEL / Fedora:
```bash
sudo dnf install bind-utils nmap
# For subfinder, install from GitHub releases or use Go
```

#### Manual Installation (All Systems):
For **subfinder** (if not available in package manager):
```bash
# Install Go first (if not installed)
# Method 1: Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Method 2: Download binary from GitHub releases
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
sudo mv subfinder /usr/local/bin/
```

### Step 4: Verify Installation
```bash
python3 reconlite.py --help
```

## 📖 Usage

### Basic Syntax
```bash
python3 reconlite.py [domain] [options]
```

### Command Line Options
| Option | Description |
|--------|-------------|
| `domain` | Target domain to reconnaissance (required) |
| `-o, --output` | Output JSON file (default: recon_results.json) |
| `--quick` | Quick scan (skip port scan and advanced enumeration) |
| `--quiet` | Quiet mode with minimal output |
| `--resolve-ips` | Resolve IP addresses for subdomains (slower but detailed) |
| `--export-summary` | Export summary report to text file |
| `--timeout` | Timeout for operations in seconds (default: 30) |

## 🔥 Examples

### Basic Domain Scan
```bash
python3 reconlite.py example.com
```

### Quick Security Assessment
```bash
python3 reconlite.py example.com --quick
```

### Detailed Scan with IP Resolution
```bash
python3 reconlite.py example.com --resolve-ips
```

### Export Results
```bash
python3 reconlite.py example.com -o my_scan.json --export-summary report.txt
```

### Quiet Mode for Automation
```bash
python3 reconlite.py example.com --quiet -o results.json
```

### Custom Timeout
```bash
python3 reconlite.py example.com --timeout 60
```

## 📊 Sample Output

```
🎯 RECONNAISSANCE RESULTS
================================================================================
Target: example.com
Security Score: 85/100

📡 DNS RECORDS SUMMARY:
  A     : 2 record(s)
         → 93.184.216.34
  MX    : 1 record(s)
         → 10 mail.example.com

🔒 SECURITY ANALYSIS:
  SPF Record:   ✅ Present
  DMARC Policy: ✅ Present (Policy: reject)
  DKIM Setup:   ✅ Present
  DNSSEC:       ✅ Enabled
  Security Score: 85/100

🔍 SUBDOMAIN ENUMERATION: (15 found)
  Tools used: subfinder
  📋 Top subdomains:
    → www.example.com
    → mail.example.com
    → api.example.com
    → cdn.example.com
    → admin.example.com
    ... and 10 more subdomains

🌐 IP INFORMATION:
  IPv4: 93.184.216.34
  CDN Detected: Cloudflare
```

## 📁 Output Formats

### JSON Export
The tool exports comprehensive results in JSON format containing:
- DNS records and analysis
- Security configuration details
- Subdomain enumeration results
- IP intelligence data
- Technology stack information
- Port scan results

### Summary Report
Text-based executive summary including:
- Security posture overview
- Key findings and recommendations
- IP addresses and infrastructure
- Technology stack summary

## ⚖️ Legal Disclaimer

**IMPORTANT: This tool is intended for educational purposes and authorized security testing only.**

### ✅ Authorized Use Cases:
- Testing your own domains and infrastructure
- Authorized penetration testing with proper written permission
- Educational and research purposes
- Bug bounty programs where explicitly allowed
- Security assessments with documented authorization

### ❌ Prohibited Activities:
- Scanning domains without explicit authorization
- Unauthorized reconnaissance of third-party systems
- Using this tool for illegal activities
- Violating terms of service of target systems
- Any activity that may be considered malicious or harmful

### 📜 Your Responsibilities:
- Ensure you have proper authorization before scanning any domain
- Comply with local laws and regulations
- Respect rate limits and don't overload target systems
- Use the information responsibly and ethically
- Report security vulnerabilities through proper channels

**The author and contributors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization and are complying with applicable laws and regulations.**

## 🛠️ Troubleshooting

### Common Issues

#### "Command not found" errors
```bash
# Check if tools are installed
which subfinder
which dnsrecon
which nmap

# Install missing tools
sudo apt install subfinder dnsrecon nmap dnsutils
```

#### Permission denied errors
```bash
# Run with appropriate permissions
sudo python3 reconlite.py example.com
```

#### Timeout errors
```bash
# Increase timeout
python3 reconlite.py example.com --timeout 60
```

#### No subdomains found
```bash
# Try with IP resolution enabled
python3 reconlite.py example.com --resolve-ips
```

### Performance Tips
- Use `--quick` for faster scans
- Increase `--timeout` for slower networks
- Use `--quiet` for automated workflows
- Enable `--resolve-ips` only when needed for detailed analysis

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the Repository**
2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make Your Changes**
4. **Test Thoroughly**
5. **Commit Your Changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to Your Branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Guidelines
- Follow PEP 8 style guidelines
- Add comments for complex logic
- Include error handling
- Test with various domain types
- Update documentation when needed

## 📞 Support

If you encounter issues or have questions:

1. **Check the troubleshooting section above**
2. **Search existing issues on GitHub**
3. **Create a new issue with detailed information**
4. **Contact the author: hello@debasisbiswas.me**

## 👨‍💻 Author

**DEBASIS**
- 🌐 Website: [https://debasisbiswas.me](https://debasisbiswas.me)
- 📧 Email: hello@debasisbiswas.me
- 🐱 GitHub: [@debasisbiswas](https://github.com/debasisbiswas)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- **ProjectDiscovery** for the amazing subfinder tool
- **Python community** for excellent libraries
- **Cybersecurity community** for inspiration and feedback
- **Open source contributors** worldwide

---

## 📈 Version History

### v1.0.0 (Current)
- Initial release
- Fast subdomain enumeration with subfinder
- Comprehensive DNS analysis
- Security posture assessment
- JSON export capabilities
- Clean terminal output

---

<div align="center">

**⭐ If you find ReconLite useful, please give it a star on GitHub! ⭐**

Made with ❤️ by [DEBASIS](https://debasisbiswas.me)

</div>
