# 🔍 ReconLite - Advanced Cyber Reconnaissance Tool

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com/DebaA17/reconlite)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/DebaA17/reconlite)

</div>

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🔍 RECONLITE TOOL                                 ║
║                                                                              ║
║   Advanced DNS & Domain Intelligence Gathering Tool                         ║
║   for Ethical Hacking, Red Team Ops & Vulnerability Assessment              ║
║                                                                              ║
║   Features: DNS Enum | WHOIS | IP Intel | Security Records | JSON Export    ║
║   Tech Stack: python-whois | ipwhois | dnspython | requests                ║
║                                                                              ║
║   Made by: DEBASIS                                 ║
║   ⚖️  For Educational Purposes Only - Not for Illegal Activities            ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

<div align="center">

**A comprehensive reconnaissance tool for DNS & domain intelligence gathering**

💻 **CLI Version**: Fast & Powerful

</div>

## 📋 Table of Contents
- [🎯 Overview](#-overview)
- [✨ Features](#-features)  
- [🚀 Installation](#-installation)
- [📖 Usage](#-usage)
- [🔥 Examples](#-examples)
- [📊 Output Formats](#-output-formats)
- [⚖️ Legal Disclaimer](#️-legal-disclaimer)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📞 Support](#-support)
- [👨‍💻 Author](#-author)
- [📄 License](#-license)

## 🎯 Overview

**ReconLite** is a comprehensive Python-based reconnaissance tool designed for DNS and domain information gathering. It's perfect for ethical hackers, red team operators, penetration testers, and cybersecurity professionals who need to perform thorough domain reconnaissance.

The tool combines multiple reconnaissance techniques and presents the results in a clean, organized format with both terminal output and JSON export capabilities.

### 💻 CLI Overview

ReconLite is a command-line tool for advanced users and automation.

## ✨ Features

### 🔍 Core Reconnaissance Capabilities
- **DNS Enumeration**: Complete DNS record gathering (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **Subdomain Discovery**: Passive certificate transparency lookup plus built-in DNS probing
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

### 💻 CLI Installation

For command-line usage and automation:

### Prerequisites
- Python 3.7 or higher
- Internet connection
- Linux, macOS, or Windows

### Step 1: Clone the Repository
```bash
git clone https://github.com/DebaA17/reconlite.git
cd reconlite
```

### Step 2: Install ReconLite

#### Option 1: Docker from GHCR (Recommended)
```bash
docker run --rm ghcr.io/debaa17/reconlite:latest example.com
```

To save results locally:
```bash
docker run --rm -v "$PWD:/work" ghcr.io/debaa17/reconlite:latest example.com -o /work/results.json
```

#### Option 2: Local pip install
```bash
# Run the installation script for a local install
./install.sh

# Or install dependencies directly
pip install -r requirements.txt

# Use with: python3 reconlite.py domain.com
```

### Step 3: Verify Installation
```bash
reconlite --help
```

ReconLite is Python-only, so no additional system tools are required.

### 🐳 Docker Installation

Use the published GHCR image:
```bash
docker run --rm ghcr.io/debaa17/reconlite:latest example.com
```

Save results to the host:
```bash
docker run --rm -v "$PWD:/work" ghcr.io/debaa17/reconlite:latest example.com -o /work/results.json
```

## 📖 Usage

### Basic Syntax
```bash
reconlite [domain] [options]
```

**Alternative (if not installed globally):**
```bash
python3 reconlite.py [domain] [options]
```

### Command Line Options
| Option | Description |
|--------|-------------|
| `domain` | Target domain to reconnaissance (required) |
| `-v, --version` | Show version number |
| `-V, --Version` | Show detailed version information |
| `-o, --output` | Output JSON file (default: recon_results.json) |
| `--quick` | Quick scan (skip port scan and advanced enumeration) |
| `--quiet` | Quiet mode with minimal output |
| `--resolve-ips` | Resolve IP addresses for subdomains (slower but detailed) |
| `--export-summary` | Export summary report to text file |
| `--timeout` | Timeout for operations in seconds (default: 30) |

## 🔥 Examples

### 💻 CLI Version Usage

### Check Version
```bash
reconlite --version          # Short version
reconlite -V                 # Detailed version info
```

### Basic Domain Scan
```bash
reconlite example.com
```

### Quick Security Assessment
```bash
reconlite example.com --quick
```

### Detailed Scan with IP Resolution
```bash
reconlite example.com --resolve-ips
```

### Export Results
```bash
reconlite example.com -o my_scan.json --export-summary report.txt
```

### Quiet Mode for Automation
```bash
reconlite example.com --quiet -o results.json
```

### Custom Timeout
```bash
reconlite example.com --timeout 60
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
  Methods used: crtsh, common_dns
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

#### Missing Python package errors
```bash
# Install the required Python packages
pip install -r requirements.txt
```

#### Permission denied errors
```bash
# Run with appropriate permissions
sudo reconlite example.com
```

#### Timeout errors
```bash
# Increase timeout
reconlite example.com --timeout 60
```

#### No subdomains found
```bash
# Try with IP resolution enabled
reconlite example.com --resolve-ips
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
- 📧 Email: hello@debasisbiswas.me
- 🐱 GitHub: [@DebaA17](https://github.com/DebaA17)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Acknowledgments

- **Python community** for excellent libraries
- **Cybersecurity community** for inspiration and feedback
- **Open source contributors** worldwide

---

## 📈 Version History

### v1.0.0 (Current)
- Initial release
- Python-only subdomain enumeration with crt.sh and DNS probes
- Comprehensive DNS analysis
- Security posture assessment
- JSON export capabilities
- Clean terminal output

---

<div align="center">

**⭐ If you find ReconLite useful, please give it a star on GitHub! ⭐**

Made with ❤️ by DEBASIS

</div>
