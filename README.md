# 🔍 SensiX - Advanced Sensitive Data Scanner

<div align="center">

```
   _____ _____ __________   ________
  / ____// ____// ____/ __ \/  _/ __ \
 / /    / __/  / __/ / /_/ // // /_/ /
/ /___ / /____/ /____/ _, _// / ____/
\____//_____/_____/_/ |_/___/_/_/
```

**A powerful, multi-threaded sensitive data exposure scanner for identifying exposed credentials, configuration files, and dangerous data.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red.svg)]()

</div>

---

## 🌟 Features

✅ **Real-time Scanning** - Results saved as they're discovered  
✅ **Multi-threaded** - 5+ concurrent workers by default  
✅ **150+ Sensitive Paths** - Comprehensive file/path detection  
✅ **Credential Detection** - AWS, Stripe, Google, GitHub, Slack, MongoDB, etc.  
✅ **Private Key Detection** - RSA, DSA, EC, OPENSSH keys  
✅ **Configuration Exposure** - .env, wp-config.php, settings.php, terraform state  
✅ **Database Dumps** - SQL injection test files  
✅ **API Documentation** - Swagger, OpenAPI, GraphQL endpoints  
✅ **Cloud Credentials** - AWS, GCP/Firebase, Kubernetes, Docker credentials  
✅ **Interactive CLI** - User-friendly menu-driven interface  
✅ **Shuffle Mode** - Randomized scanning order for stealth  
✅ **Verbose Logging** - Detailed output for debugging  

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/SensiX.git
cd SensiX
pip install -r requirements.txt
```

### Usage - Interactive Mode (Recommended)

```bash
python3 SensiX.py
```

Then follow the interactive menu:
- Select scan mode (single URL or mass scan)
- Configure threads, output file, shuffle/verbose options
- Watch real-time results

### Usage - Command Line

#### Single URL Scan
```bash
python3 SensiX.py -u https://target.com
```

#### Mass Scan from File
```bash
python3 SensiX.py -l targets.txt -w 10 -o results.txt -s
```

#### Advanced Options
```bash
python3 SensiX.py \
  -l targets.txt \           # File with URLs
  -w 15 \                    # 15 worker threads
  -t 15 \                    # 15 second timeout
  -o scan_results \          # Output file
  -s \                       # Shuffle scan order
  -v \                       # Verbose output
  -p https                   # Default to https
```

---

## 📊 Detection Capabilities

### 🔐 Credentials Detected
- **AWS Access Keys** - `AKIA*` pattern matching
- **Stripe Keys** - `sk_live_*` secret keys
- **Google API Keys** - `AIza*` pattern
- **GitHub Tokens** - `ghp_*` personal access tokens
- **Slack Tokens** - `xox*` workspace tokens
- **MongoDB Connections** - Connection strings with credentials
- **Database URIs** - PostgreSQL, MySQL, Redis connections

### 📁 Files & Paths (150+)
- Environment files: `.env*`, `*.local`, `*.prod`
- Configuration: `.htpasswd`, `web.config`, `appsettings.json`
- CMS: `wp-config.php`, `settings.php`, `configuration.php`
- Git: `.git/config`, `.gitignore`
- CI/CD: `.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`
- Cloud: `terraform.tfstate`, `.kube/config`, `.aws/credentials`
- API: `swagger.json`, `openapi.yaml`, `graphql`
- Private Keys: RSA, DSA, EC, OPENSSH formats

### 🎯 Severity Levels
| Level | CVSS | Examples |
|-------|------|----------|
| 🔴 Critical | 9.0-10.0 | Private keys, Terraform state, .env files |
| 🟠 High | 7.0-8.9 | Git repos, Database dumps, API keys |
| 🟡 Medium | 5.0-6.9 | PHPInfo, Log files |
| 🟢 Low | 0.1-4.9 | robots.txt, CHANGELOG |

---

## 📋 Output Format

### Console Output
```
[CRITICAL] Private Key Exposed (CVSS: 9.8)
  URL: https://target.com/.env
  Evidence: AKIA0123456789ABCDEF...
  
[HIGH] AWS Credentials File Exposed (CVSS: 9.8)
  URL: https://target.com/.aws/credentials
  Evidence: aws_access_key_id=AKIAIOSFODNN7EXAMPLE...
```

### File Output
```
================================================================================
SensiX - SENSITIVE DATA SCANNER - SCAN REPORT
================================================================================
Started: 2024-05-23 14:30:45
================================================================================

[CRITICAL] Private Key Exposed
URL: https://target.com/.env
CWE: CWE-321
CVSS: 9.8
Evidence: -----BEGIN RSA PRIVATE KEY-----...
Remediation: Rotate the exposed private key immediately.
Discovered: 2024-05-23T14:30:50.123456

================================================================================
SCAN SUMMARY
================================================================================
Total Targets: 50
Total Tests: 7500
Total Vulnerabilities: 23

Breakdown by Severity:
  Critical: 8
  High: 10
  Medium: 4
  Low: 1

Duration: 234.56 seconds
================================================================================
```

---

## ⚙️ Configuration

### Timeout Settings
```bash
python3 SensiX.py -u target.com -t 20  # 20 second timeout
```

### Thread Control
```bash
# Fast scan (more threads, less reliable on slow connections)
python3 SensiX.py -l targets.txt -w 20

# Slow scan (fewer threads, more reliable)
python3 SensiX.py -l targets.txt -w 3
```

### Protocol Selection
```bash
# Default to HTTP
python3 SensiX.py -u example.com -p http

# Default to HTTPS
python3 SensiX.py -u example.com -p https
```

---

## 📈 Performance

| Config | Targets | Files/Target | Time | Speed |
|--------|---------|--------------|------|-------|
| 5 threads | 100 | 150 paths | ~8 min | 3,125 URLs/min |
| 10 threads | 100 | 150 paths | ~4 min | 6,250 URLs/min |
| 20 threads | 100 | 150 paths | ~2.5 min | 10,000 URLs/min |

*Performance depends on target response times and network conditions*

---

## 🔒 Safety & Responsible Disclosure

⚠️ **Use Only on Systems You Own or Have Permission to Test**

- This tool is designed for authorized security testing
- Unauthorized access to computer systems is illegal
- Always obtain written permission before scanning
- Follow responsible disclosure practices
- Report findings privately before public disclosure (90-day window)

---

## 🛠️ Requirements

```
Python 3.8+
requests >= 2.28.0
urllib3 >= 1.26.0
```

See `requirements.txt` for full list.

---

## 📝 Examples

### Example 1: Quick Website Audit
```bash
python3 SensiX.py -u https://example.com -v -o example_audit.txt
```

### Example 2: Mass Scanning Campaign
```bash
python3 SensiX.py -l company_domains.txt -w 15 -s -o campaign_results.txt -v
```

### Example 3: Slow, Reliable Scan
```bash
python3 SensiX.py -l targets.txt -w 3 -t 30 -o results.txt
```

### Example 4: Interactive Mode
```bash
python3 SensiX.py
# Follow the interactive menu
```

---

## 🐛 Troubleshooting

### Issue: "No module named requests"
```bash
pip install -r requirements.txt
```

### Issue: "Connection timeout"
Increase timeout:
```bash
python3 SensiX.py -u target.com -t 30
```

### Issue: Too many false positives
Reduce threads or enable verbose mode to debug:
```bash
python3 SensiX.py -l targets.txt -w 5 -v
```

---

## 📊 CWE Coverage

| CWE | Title | Severity |
|-----|-------|----------|
| CWE-200 | Information Exposure | High |
| CWE-215 | Information Exposure Through Debug Information | Critical |
| CWE-321 | Use of Hard-coded Cryptographic Key | Critical |
| CWE-498 | Cloneable Class | High |
| CWE-522 | Insufficiently Protected Credentials | Critical |
| CWE-532 | Insertion of Sensitive Information into Log File | Medium |
| CWE-538 | Use of Persistent Cookies Containing Sensitive Information | High |
| CWE-540 | Information Exposure Through Source Code | High |
| CWE-798 | Use of Hard-coded Credentials | Critical |

---

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Add tests if applicable
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## ⚖️ Disclaimer

**This tool is provided "as-is" for authorized security testing only.**

The authors assume no liability for misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before conducting security testing on any system.

---

## 🙏 Acknowledgments

Built with passion for the cybersecurity community.

---

## 📞 Contact & Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: contact@example.com

---

## 🌐 Related Projects

- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [Nuclei](https://nuclei.projectdiscovery.io/) - Vulnerability scanner
- [Burp Suite](https://portswigger.net/burp) - Web security testing
- [Nikto](https://github.com/sullo/nikto) - Web server scanner

---

<div align="center">

**[⭐ Star this repo if it was useful!](https://github.com/yourusername/SensiX)**

Made with ❤️ by the Security Community

</div>
