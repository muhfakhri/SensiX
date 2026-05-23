#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SensiX - Sensitive Data Scanner
Mass vulnerability scanner for exposed credentials, config files, and sensitive data
Supports: shuffle, multi-threading, batch processing, mass scanning
"""

# ASCII Banner
BANNER = r"""
.d8888. d88888b d8b   db .d8888. d888888b db    db 
88'  YP 88'     888o  88 88'  YP   `88'   `8b  d8' 
`8bo.   88ooooo 88V8o 88 `8bo.      88     `8bd8'  
  `Y8b. 88~~~~~ 88 V8o88   `Y8b.    88     .dPYb.  
db   8D 88.     88  V888 db   8D   .88.   .8P  Y8. 
`8888Y' Y88888P VP   V8P `8888Y' Y888888P YP    YP 
                                                   
                                                   

  Sensitive Data Scanner v1.0
  [*] Mass Vulnerability Scanner
  [*] Exposed Credentials Detection
  [*] Configuration File Exposure
  
"""

import requests
import re
import sys
import json
import time
import random
import uuid
import threading
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for terminal output
class Color:
    """ANSI color codes"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    # Severity colors
    CRITICAL = RED
    HIGH = '\033[38;5;208m'  # Orange
    MEDIUM = YELLOW
    LOW = GREEN
    INFO = CYAN


class Severity(Enum):
    """Severity levels for vulnerabilities"""
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Info = "Info"


@dataclass
class Vulnerability:
    """Vulnerability record"""
    vuln_id: str
    vuln_type: str
    severity: str
    url: str
    evidence: Optional[str]
    cwe: str
    cvss: float
    remediation: str
    discovered_at: str
    
    def to_dict(self):
        return asdict(self)


class SensiX:
    """SensiX - Scanner for sensitive data exposure (files, credentials, configuration)"""
    
    def __init__(self, timeout: int = 10, retries: int = 3, protocol: str = "http", output_file: Optional[str] = None):
        self.timeout = timeout
        self.retries = retries
        self.protocol = protocol  # default protocol for domain normalization
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.output_file = output_file
        self.file_lock = threading.Lock()
        self.scan_start_time = None
        self.scan_stats = {'total_targets': 0, 'total_tests': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        # Initialize output file with header if provided
        if self.output_file:
            self._init_output_file()
    
    def _init_output_file(self):
        """Initialize output file with header"""
        with self.file_lock:
            with open(self.output_file, 'w') as f:
                f.write(f"{'='*80}\n")
                f.write(f"SensiX - SENSITIVE DATA SCANNER - SCAN REPORT\n")
                f.write(f"{'='*80}\n")
                f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*80}\n\n")
    
    def _write_vulnerability_to_file(self, vuln: 'Vulnerability'):
        """Write vulnerability to output file immediately (streaming)"""
        if not self.output_file:
            return
        
        with self.file_lock:
            with open(self.output_file, 'a') as f:
                f.write(f"[{vuln.severity.upper()}] {vuln.vuln_type}\n")
                f.write(f"URL: {vuln.url}\n")
                f.write(f"CWE: {vuln.cwe}\n")
                f.write(f"CVSS: {vuln.cvss}\n")
                f.write(f"Evidence: {vuln.evidence}\n")
                f.write(f"Remediation: {vuln.remediation}\n")
                f.write(f"Discovered: {vuln.discovered_at}\n")
                f.write(f"{'-'*80}\n\n")
                f.flush()
    
    def _print_colored(self, message: str, color: str = Color.WHITE):
        """Print colored message"""
        print(f"{color}{message}{Color.RESET}")
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        severity_upper = severity.upper()
        if severity_upper == 'CRITICAL':
            return Color.CRITICAL
        elif severity_upper == 'HIGH':
            return Color.HIGH
        elif severity_upper == 'MEDIUM':
            return Color.MEDIUM
        elif severity_upper == 'LOW':
            return Color.LOW
        else:
            return Color.INFO
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL - add protocol if missing (domain-only input)"""
        url = url.strip()
        # If URL already has protocol, return as-is
        if url.startswith('http://') or url.startswith('https://'):
            return url
        # Otherwise, add default protocol
        return f"{self.protocol}://{url}"
    
    def http_get(self, url: str) -> Optional[Dict]:
        """Make HTTP GET request"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            return {
                'status_code': response.status_code,
                'body': response.text,
                'headers': dict(response.headers)
            }
        except Exception:
            return None
    
    def scan(self, url: str, shuffle: bool = False, verbose: bool = False) -> Tuple[List[Vulnerability], int]:
        """Run sensitive data exposure scan on single URL"""
        if verbose:
            self._print_colored(f"[*] Starting sensitive data exposure scan on {url}", Color.BLUE)
        
        all_vulnerabilities = []
        total_tests = 0
        
        try:
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        except Exception as e:
            if verbose:
                self._print_colored(f"[-] Failed to parse URL: {e}", Color.RED)
            return all_vulnerabilities, 0
        
        # Get sensitive paths
        sensitive_paths = self.get_sensitive_paths()
        
        # Shuffle if requested
        if shuffle:
            random.shuffle(sensitive_paths)
        
        # Test sensitive file paths
        for path in sensitive_paths:
            total_tests += 1
            test_url = f"{base_url}{path}"
            
            try:
                response = self.http_get(test_url)
                if response:
                    vuln = self.analyze_sensitive_file(
                        response['body'],
                        response['status_code'],
                        path,
                        test_url
                    )
                    if vuln:
                        all_vulnerabilities.append(vuln)
                        # Write immediately to file
                        self._write_vulnerability_to_file(vuln)
                        # Update stats
                        self._update_stats(vuln.severity)
                        if verbose:
                            color = self._get_severity_color(vuln.severity)
                            self._print_colored(f"[!] FOUND: {vuln.vuln_type} at {test_url}", color)
            except Exception:
                pass
        
        # Check main response for exposed credentials
        total_tests += 1
        try:
            response = self.http_get(url)
            if response:
                cred_vulns = self.scan_for_credentials(response['body'], url)
                for vuln in cred_vulns:
                    all_vulnerabilities.append(vuln)
                    # Write immediately to file
                    self._write_vulnerability_to_file(vuln)
                    # Update stats
                    self._update_stats(vuln.severity)
                    if verbose:
                        color = self._get_severity_color(vuln.severity)
                        self._print_colored(f"[!] FOUND: {vuln.vuln_type} at {url}", color)
        except Exception:
            pass
        
        if verbose:
            self._print_colored(f"[+] Scan completed: {total_tests} tests, {len(all_vulnerabilities)} vulns found", Color.GREEN)
        
        return all_vulnerabilities, total_tests
    
    def _update_stats(self, severity: str):
        """Update vulnerability statistics"""
        severity_upper = severity.upper()
        if severity_upper == 'CRITICAL':
            self.scan_stats['critical'] += 1
        elif severity_upper == 'HIGH':
            self.scan_stats['high'] += 1
        elif severity_upper == 'MEDIUM':
            self.scan_stats['medium'] += 1
        elif severity_upper == 'LOW':
            self.scan_stats['low'] += 1
    
    def mass_scan(self, urls: List[str], shuffle: bool = True, 
                  workers: int = 5, verbose: bool = False) -> Dict:
        """Mass scan multiple URLs with threading"""
        self._print_colored(f"\n[*] Mass scanning {len(urls)} targets (workers: {workers}, shuffle: {shuffle})", Color.BLUE)
        
        if shuffle:
            random.shuffle(urls)
        
        results = defaultdict(list)
        results['total_targets'] = len(urls)
        self.scan_stats['total_targets'] = len(urls)
        results['vulnerabilities'] = []
        results['total_tests'] = 0
        results['start_time'] = datetime.now().isoformat()
        self.scan_start_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self.scan, url, shuffle=False, verbose=verbose): url
                for url in urls
            }
            
            for i, future in enumerate(as_completed(futures), 1):
                url = futures[future]
                try:
                    vulns, tests = future.result()
                    results['total_tests'] += tests
                    self.scan_stats['total_tests'] += tests
                    
                    if vulns:
                        color = Color.GREEN if len(vulns) > 0 else Color.BLUE
                        self._print_colored(f"[{i}/{len(urls)}] {url} - {len(vulns)} vulns found", color)
                    else:
                        self._print_colored(f"[{i}/{len(urls)}] {url} - clean", Color.CYAN)
                except Exception as e:
                    self._print_colored(f"[{i}/{len(urls)}] {url} - ERROR: {e}", Color.RED)
        
        results['end_time'] = datetime.now().isoformat()
        results['total_vulnerabilities'] = len(results['vulnerabilities'])
        results['critical'] = self.scan_stats['critical']
        results['high'] = self.scan_stats['high']
        results['medium'] = self.scan_stats['medium']
        results['low'] = self.scan_stats['low']
        
        # Write final summary to file
        self._write_summary_to_file(results)
        
        return results
    
    def _write_summary_to_file(self, results: Dict):
        """Write final summary to output file"""
        if not self.output_file:
            return
        
        with self.file_lock:
            with open(self.output_file, 'a') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"SCAN SUMMARY\n")
                f.write(f"{'='*80}\n")
                f.write(f"Total Targets: {results['total_targets']}\n")
                f.write(f"Total Tests: {results['total_tests']}\n")
                f.write(f"Total Vulnerabilities: {results['total_vulnerabilities']}\n")
                f.write(f"\nBreakdown by Severity:\n")
                f.write(f"  Critical: {results.get('critical', 0)}\n")
                f.write(f"  High: {results.get('high', 0)}\n")
                f.write(f"  Medium: {results.get('medium', 0)}\n")
                f.write(f"  Low: {results.get('low', 0)}\n")
                f.write(f"\nScan Started: {results['start_time']}\n")
                f.write(f"Scan Ended: {results['end_time']}\n")
                
                # Calculate duration
                try:
                    start = datetime.fromisoformat(results['start_time'])
                    end = datetime.fromisoformat(results['end_time'])
                    duration = (end - start).total_seconds()
                    f.write(f"Duration: {duration:.2f} seconds\n")
                except:
                    pass
                
                f.write(f"{'='*80}\n")
                f.flush()
    
    def get_sensitive_paths(self) -> List[str]:
        """Get list of sensitive paths to test"""
        return [
            # Environment and config files
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.stage",
            "/.env.staging",
            "/.env.prod",
            "/.env.dev",
            "/.env.test",
            "/.env.backup",
            "/.env.bak",
            "/.env.old",
            "/.env.save",
            "/.env.sample",
            "/.env.example",
            "/config.php",
            "/configuration.php",
            "/wp-config.php",
            "/wp-config.php.bak",
            "/wp-config.php.old",
            "/wp-config.php~",
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/settings.json",
            "/settings.yml",
            "/web.config",
            "/appsettings.json",
            "/appsettings.Development.json",
            "/appsettings.Production.json",
            "/application.properties",
            "/application.yml",
            "/bootstrap.properties",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/master.key",
            "/config/credentials.yml.enc",
            # Django
            "/settings.py",
            "/local_settings.py",
            # Magento
            "/app/etc/local.xml",
            "/app/etc/env.php",
            "/app/etc/config.php",
            # Drupal
            "/sites/default/settings.php",
            "/sites/default/settings.local.php",
            "/sites/default/default.settings.php",
            # Joomla
            "/configuration.php.bak",
            # Git files
            "/.git/config",
            "/.git/HEAD",
            "/.git/index",
            "/.gitignore",
            "/.gitconfig",
            # Subversion
            "/.svn/entries",
            # Package manager files
            "/package.json",
            "/composer.json",
            "/composer.lock",
            "/requirements.txt",
            "/auth.json",
            "/.npmrc",
            "/.yarnrc",
            # Database dumps
            "/backup.sql",
            "/backup.sql.gz",
            "/dump.sql",
            "/database.sql",
            "/mysql.sql",
            "/postgres.sql",
            # Terraform state (CRITICAL - contains all secrets plaintext)
            "/terraform.tfstate",
            "/terraform.tfstate.backup",
            "/terraform.tfvars",
            "/terraform.tfvars.json",
            # Debug and info files
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/debug.php",
            "/debug",
            "/elmah.axd",
            "/trace.axd",
            "/server-status",
            # Log files
            "/logs/error.log",
            "/logs/access.log",
            "/logs/debug.log",
            "/error.log",
            "/access.log",
            "/error_log",
            # API documentation
            "/api/swagger.json",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi.json",
            "/openapi.yaml",
            "/graphql",
            "/redoc",
            # Server status
            "/server-info",
            "/status",
            "/health",
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
            # Cloud credentials
            "/.aws/credentials",
            "/.aws/config",
            "/.docker/config.json",
            "/.kube/config",
            # Private keys
            "/id_rsa",
            "/id_dsa",
            "/.ssh/id_rsa",
            "/.ssh/authorized_keys",
            "/server.key",
            "/private.key",
            "/cert.pem",
            # Secret store files
            "/secrets.yml",
            "/secrets.json",
            # IDE config
            "/.vscode/sftp.json",
            "/.idea/datasources.xml",
            "/sftp-config.json",
            # CI/CD
            "/.travis.yml",
            "/.gitlab-ci.yml",
            "/Jenkinsfile",
            # Container
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            # Shell history
            "/.bash_history",
            "/.zsh_history",
            "/.mysql_history",
            "/.psql_history",
            # Core dumps
            "/core.dump",
            "/heapdump.hprof",
            # Other
            "/.DS_Store",
            "/robots.txt",
            "/.well-known/security.txt",
            "/sitemap.xml",
            "/.htaccess",
            "/.htpasswd",
            "/passwd",
            "/users.txt",
            "/password.txt",
            "/secrets.txt",
            "/CHANGELOG",
            "/VERSION",
            # Backups
            "/backup.zip",
            "/backup.tar.gz",
            "/site.zip",
            "/release.zip",
        ]
    
    def analyze_sensitive_file(self, body: str, status_code: int, path: str, url: str) -> Optional[Vulnerability]:
        """Analyze response for sensitive file exposure"""
        if status_code != 200 or not body:
            return None
        
        body_lower = body.lower()
        path_lower = path.lower()
        
        # Reject HTML error pages / SPA shells
        if self.looks_like_generic_html(body_lower):
            return None
        
        # Private SSH/PEM key blocks
        if self.contains_private_key_block(body):
            return self.create_vulnerability(
                "Private Key Exposed",
                url,
                self.truncate_evidence(body, 200),
                Severity.Critical,
                "CWE-321",
                9.8,
                "Rotate the exposed private key immediately."
            )
        
        # AWS credentials
        if "/.aws/credentials" in path_lower:
            if ("aws_access_key_id" in body and "aws_secret_access_key" in body) or "AKIA" in body:
                return self.create_vulnerability(
                    "AWS Credentials File Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-798",
                    9.8,
                    "Rotate all AWS credentials immediately."
                )
        
        # Kubernetes kubeconfig
        if "kubeconfig" in path_lower or ".kube/config" in path_lower:
            if ("apiversion" in body_lower and "kind: config" in body_lower) or \
               ("clusters:" in body and "contexts:" in body) or \
               "client-certificate-data" in body:
                return self.create_vulnerability(
                    "Kubernetes kubeconfig Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-798",
                    9.8,
                    "Rotate cluster credentials immediately."
                )
        
        # GCP Service Account
        if ".json" in path_lower and \
           ('"type": "service_account"' in body or '"private_key"' in body):
            return self.create_vulnerability(
                "GCP/Firebase Service Account Key Exposed",
                url,
                self.truncate_evidence(body, 200),
                Severity.Critical,
                "CWE-798",
                9.8,
                "Revoke the service account key immediately."
            )
        
        # Terraform state file (contains ALL plaintext secrets)
        if ".tfstate" in path_lower:
            if ('"terraform_version"' in body and '"resources"' in body) or \
               '"serial":' in body or '"lineage"' in body:
                return self.create_vulnerability(
                    "Terraform State File Exposed - CRITICAL",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-200",
                    9.8,
                    "Terraform state stores ALL secrets in plaintext. Rotate ALL secrets immediately."
                )
        
        # .htpasswd file
        if ".htpasswd" in path_lower:
            if ":$2" in body or ":$apr1$" in body or ":{SHA}" in body:
                return self.create_vulnerability(
                    ".htpasswd File Exposed",
                    url,
                    self.truncate_evidence(body, 150),
                    Severity.Critical,
                    "CWE-522",
                    9.1,
                    "Remove .htpasswd from web root."
                )
        
        # .env file exposure
        if ".env" in path:
            env_patterns = [
                "db_password=", "api_key=", "secret_key=", "app_secret=",
                "aws_secret_access_key=", "jwt_secret=", "database_url="
            ]
            if any(p in body_lower for p in env_patterns):
                return self.create_vulnerability(
                    "Environment File Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-215",
                    9.8,
                    "Remove .env from web root. Use environment variables."
                )
        
        # Git repository exposure
        if ".git" in path:
            if "[core]" in body or "repositoryformatversion" in body or "ref: refs/" in body:
                return self.create_vulnerability(
                    "Git Repository Files Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.High,
                    "CWE-540",
                    7.5,
                    "Remove .git directory from web root."
                )
        
        # SQL dumps
        if ".sql" in path:
            if "INSERT INTO" in body or "CREATE TABLE" in body or "DROP TABLE" in body:
                return self.create_vulnerability(
                    "Database Dump File Exposed",
                    url,
                    "SQL dump contains database structure and data",
                    Severity.Critical,
                    "CWE-538",
                    8.8,
                    "Remove SQL dumps from web root."
                )
        
        # PHPInfo
        if "phpinfo" in path or "info.php" in path:
            if "PHP Version" in body or "phpinfo()" in body or "php.ini" in body:
                return self.create_vulnerability(
                    "PHPInfo Page Exposed",
                    url,
                    "PHPInfo reveals server configuration",
                    Severity.Medium,
                    "CWE-200",
                    5.3,
                    "Remove phpinfo() from production."
                )
        
        # Drupal settings.php
        if "settings.php" in path_lower:
            if "$databases" in body or "$settings['hash_salt']" in body:
                return self.create_vulnerability(
                    "Drupal settings.php Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-200",
                    9.1,
                    "Rotate credentials and secure the file."
                )
        
        # WordPress wp-config.php
        if "wp-config.php" in path_lower:
            if "DB_PASSWORD" in body or "DB_USER" in body or "AUTH_KEY" in body:
                return self.create_vulnerability(
                    "WordPress wp-config.php Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-200",
                    9.1,
                    "Rotate database credentials and authentication keys."
                )
        
        # Configuration files with credentials
        is_config = any(path.endswith(ext) for ext in [".conf", ".cfg", ".ini", ".yaml", ".yml"])
        if is_config:
            cred_patterns = ["password=", "password:", "secret_key=", "db_password"]
            if any(p in body_lower for p in cred_patterns):
                return self.create_vulnerability(
                    "Configuration File with Credentials Exposed",
                    url,
                    self.truncate_evidence(body, 200),
                    Severity.Critical,
                    "CWE-200",
                    9.1,
                    "Remove config files from web root."
                )
        
        # Log files
        if body.count("ERROR") > 2 and "[" in body:
            if "Stack trace" in body or ("Exception" in body and " at " in body):
                return self.create_vulnerability(
                    "Log File Exposed",
                    url,
                    "Log file may contain sensitive information",
                    Severity.Medium,
                    "CWE-532",
                    5.3,
                    "Remove log files from web root."
                )
        
        return None
    
    def scan_for_credentials(self, body: str, url: str) -> List[Vulnerability]:
        """Scan response body for exposed credentials"""
        vulnerabilities = []
        
        # AWS Access Keys (AKIA + 16 alphanumeric)
        if matches := self.regex_scan(body, r"AKIA[0-9A-Z]{16}"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "AWS Access Key Exposed",
                    url,
                    evidence,
                    Severity.Critical,
                    "CWE-798",
                    9.5,
                    "Rotate AWS credentials immediately."
                ))
        
        # Stripe Secret Keys
        if matches := self.regex_scan(body, r"sk_live_[a-zA-Z0-9]{24,}"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "Stripe Secret Key Exposed",
                    url,
                    evidence,
                    Severity.Critical,
                    "CWE-798",
                    9.5,
                    "Rotate Stripe key immediately."
                ))
        
        # Google API Keys
        if matches := self.regex_scan(body, r"AIza[0-9A-Za-z\-_]{35}"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "Google API Key Exposed",
                    url,
                    evidence,
                    Severity.High,
                    "CWE-798",
                    7.5,
                    "Rotate Google API key."
                ))
        
        # GitHub Tokens
        if matches := self.regex_scan(body, r"ghp_[a-zA-Z0-9]{36}"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "GitHub Token Exposed",
                    url,
                    evidence,
                    Severity.Critical,
                    "CWE-798",
                    9.0,
                    "Revoke GitHub token immediately."
                ))
        
        # Slack Tokens
        if matches := self.regex_scan(body, r"xox[baprs]-[a-zA-Z0-9\-]{10,}"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "Slack Token Exposed",
                    url,
                    evidence,
                    Severity.High,
                    "CWE-798",
                    8.0,
                    "Revoke Slack token immediately."
                ))
        
        # MongoDB Connection String with credentials
        if matches := self.regex_scan(body, r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[a-zA-Z0-9.-]+\.mongodb\.net"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "MongoDB Connection String Exposed",
                    url,
                    evidence,
                    Severity.Critical,
                    "CWE-798",
                    9.8,
                    "Rotate MongoDB credentials immediately."
                ))
        
        # Database connection URLs
        if matches := self.regex_scan(body, r"(?:postgres|mysql|redis)://[A-Za-z0-9_\-]+:[^@\s]+@[A-Za-z0-9.-]+"):
            for evidence in matches[:2]:
                vulnerabilities.append(self.create_vulnerability(
                    "Database Connection String Exposed",
                    url,
                    evidence,
                    Severity.Critical,
                    "CWE-798",
                    9.1,
                    "Rotate database password immediately."
                ))
        
        return vulnerabilities
    
    def looks_like_generic_html(self, body_lower: str) -> bool:
        """Detect if body is generic HTML vs actual file"""
        html_indicators = ["<!doctype html", "<html", "<head", "<body"]
        hit_count = sum(1 for ind in html_indicators if ind in body_lower)
        
        if hit_count < 2:
            return False
        
        # Check for non-HTML structured data
        return not any(marker in body_lower for marker in [
            '"private_key"', '-----begin', '"terraform_version"',
            'aws_access_key_id', '<datasource'
        ])
    
    def contains_private_key_block(self, body: str) -> bool:
        """Detect PEM-encoded private key blocks"""
        return any(key_type in body for key_type in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ]) or ("-----BEGIN PRIVATE KEY-----" in body and "-----END PRIVATE KEY-----" in body)
    
    def regex_scan(self, content: str, pattern: str) -> Optional[List[str]]:
        """Perform regex scan and return matches"""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = []
            for match in regex.finditer(content):
                matched_text = match.group(0)
                if len(matched_text) > 50:
                    matches.append(f"{matched_text[:50]}...")
                else:
                    matches.append(matched_text)
            return matches if matches else None
        except Exception:
            return None
    
    def truncate_evidence(self, text: str, max_len: int) -> str:
        """Truncate evidence to specified length"""
        return f"{text[:max_len]}..." if len(text) > max_len else text
    
    def create_vulnerability(self, vuln_type: str, url: str, evidence: str,
                            severity: Severity, cwe: str, cvss: float,
                            remediation: str) -> Vulnerability:
        """Create a vulnerability record"""
        return Vulnerability(
            vuln_id=f"sensdata_{uuid.uuid4()}",
            vuln_type=vuln_type,
            severity=severity.value,
            url=url,
            evidence=evidence,
            cwe=cwe,
            cvss=cvss,
            remediation=remediation,
            discovered_at=datetime.utcnow().isoformat()
        )


def interactive_mode():
    """Interactive CLI mode for user-friendly scanning"""
    print(BANNER)
    print(f"{Color.CYAN}{'='*70}{Color.RESET}")
    print(f"{Color.MAGENTA}[*] SensiX - Sensitive Data Scanner - Interactive Mode{Color.RESET}")
    print(f"{Color.CYAN}{'='*70}{Color.RESET}\n")
    
    # Mode selection
    print(f"{Color.YELLOW}[1] Single URL Scan{Color.RESET}")
    print(f"{Color.YELLOW}[2] Mass Scan (from file){Color.RESET}")
    print(f"{Color.YELLOW}[3] Exit{Color.RESET}\n")
    
    mode = input(f"{Color.CYAN}Select mode (1-3): {Color.RESET}").strip()
    
    if mode == "3":
        print(f"{Color.CYAN}[*] Exiting...{Color.RESET}")
        return
    
    if mode not in ["1", "2"]:
        print(f"{Color.RED}[-] Invalid mode selection!{Color.RESET}")
        return
    
    # Get number of threads
    while True:
        try:
            threads_input = input(f"\n{Color.CYAN}Number of threads (default: 5): {Color.RESET}").strip()
            threads = int(threads_input) if threads_input else 5
            if threads < 1 or threads > 50:
                print(f"{Color.RED}[-] Threads must be between 1 and 50{Color.RESET}")
                continue
            break
        except ValueError:
            print(f"{Color.RED}[-] Invalid number!{Color.RESET}")
    
    # Get output file
    output_file = input(f"{Color.CYAN}Output file name (optional, e.g., results.txt): {Color.RESET}").strip()
    if output_file and not output_file.endswith('.txt'):
        output_file = f"{output_file}.txt"
    
    # Get shuffle option
    shuffle_input = input(f"{Color.CYAN}Shuffle scan order? (y/n, default: y): {Color.RESET}").strip().lower()
    shuffle = shuffle_input != 'n'
    
    # Get verbose option
    verbose_input = input(f"{Color.CYAN}Verbose output? (y/n, default: y): {Color.RESET}").strip().lower()
    verbose = verbose_input != 'n'
    
    print()
    
    # Initialize scanner
    scanner = SensiX(timeout=10, protocol='http', output_file=output_file)
    
    if mode == "1":
        # Single URL mode
        url = input(f"{Color.CYAN}Enter target URL: {Color.RESET}").strip()
        if not url:
            print(f"{Color.RED}[-] No URL provided!{Color.RESET}")
            return
        
        url = scanner.normalize_url(url)
        print()
        scanner._print_colored(f"[*] Scanning: {url}", Color.BLUE)
        vulns, tests = scanner.scan(url, shuffle=False, verbose=verbose)
        
        print()
        scanner._print_colored(f"[+] Results: {len(vulns)} vulnerabilities found in {tests} tests", Color.GREEN)
        
        if vulns:
            print()
            for vuln in vulns:
                color = scanner._get_severity_color(vuln.severity)
                scanner._print_colored(f"  [{vuln.severity.upper()}] {vuln.vuln_type} (CVSS: {vuln.cvss})", color)
                print(f"    URL: {vuln.url}")
                print(f"    Evidence: {vuln.evidence}")
                print()
        
        if output_file:
            scanner._print_colored(f"[+] Results saved to: {output_file}", Color.CYAN)
    
    elif mode == "2":
        # Mass scan mode
        list_file = input(f"{Color.CYAN}Enter file path with URLs (one per line): {Color.RESET}").strip()
        
        if not list_file or not list_file.endswith(('.txt', '.list')):
            print(f"{Color.RED}[-] Invalid file path!{Color.RESET}")
            return
        
        try:
            with open(list_file, 'r') as f:
                urls = [scanner.normalize_url(line) for line in f if line.strip()]
            
            if not urls:
                scanner._print_colored("[-] No URLs found in file", Color.RED)
                return
            
            print()
            results = scanner.mass_scan(urls, shuffle=shuffle, workers=threads, verbose=verbose)
            
            print()
            scanner._print_colored(f"{'='*60}", Color.CYAN)
            scanner._print_colored(f"[+] SCAN COMPLETED", Color.GREEN)
            scanner._print_colored(f"{'='*60}", Color.CYAN)
            scanner._print_colored(f"Total Targets: {results['total_targets']}", Color.WHITE)
            scanner._print_colored(f"Total Tests: {results['total_tests']}", Color.WHITE)
            scanner._print_colored(f"Total Vulnerabilities: {results['total_vulnerabilities']}", Color.GREEN if results['total_vulnerabilities'] > 0 else Color.CYAN)
            print()
            
            # Summary by severity
            scanner._print_colored("Vulnerabilities by Severity:", Color.MAGENTA)
            if results.get('critical', 0) > 0:
                scanner._print_colored(f"  Critical: {results['critical']}", Color.CRITICAL)
            if results.get('high', 0) > 0:
                scanner._print_colored(f"  High: {results['high']}", Color.HIGH)
            if results.get('medium', 0) > 0:
                scanner._print_colored(f"  Medium: {results['medium']}", Color.MEDIUM)
            if results.get('low', 0) > 0:
                scanner._print_colored(f"  Low: {results['low']}", Color.LOW)
            
            print()
            if output_file:
                scanner._print_colored(f"[+] All results saved to: {output_file}", Color.GREEN)
                scanner._print_colored(f"[*] Vulnerabilities saved in real-time as they are discovered", Color.CYAN)
        
        except FileNotFoundError:
            scanner._print_colored(f"[-] File not found: {list_file}", Color.RED)
            return


def main():
    """Main entry point"""
    import argparse
    import sys
    
    # If no arguments provided, run interactive mode
    if len(sys.argv) == 1:
        interactive_mode()
        return
    
    parser = argparse.ArgumentParser(description="SensiX - Sensitive Data Scanner with Shuffle & Real-time Output")
    parser.add_argument("-i", "--interactive", action="store_true", help="Launch interactive mode")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--list", help="File with list of URLs (one per line)")
    parser.add_argument("-s", "--shuffle", action="store_true", help="Shuffle scanning order")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("-o", "--output", help="Output file (txt format) - results saved in real-time")
    parser.add_argument("-p", "--protocol", choices=['http', 'https'], default='http', help="Default protocol for domain normalization (default: http)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive:
        interactive_mode()
        return
    
    # Ensure output file has .txt extension
    output_file = args.output
    if output_file and not output_file.endswith('.txt'):
        output_file = f"{output_file}.txt"
    
    scanner = SensiX(timeout=args.timeout, protocol=args.protocol, output_file=output_file)
    
    if args.url:
        # Single URL scan
        url = scanner.normalize_url(args.url)
        print()
        scanner._print_colored(f"[*] Scanning: {url}", Color.BLUE)
        vulns, tests = scanner.scan(url, shuffle=False, verbose=args.verbose)
        
        print()
        scanner._print_colored(f"[+] Results: {len(vulns)} vulnerabilities found in {tests} tests", Color.GREEN)
        
        if vulns:
            print()
            for vuln in vulns:
                color = scanner._get_severity_color(vuln.severity)
                scanner._print_colored(f"  [{vuln.severity.upper()}] {vuln.vuln_type} (CVSS: {vuln.cvss})", color)
                print(f"    URL: {vuln.url}")
                print(f"    Evidence: {vuln.evidence}")
                print()
        
        if output_file:
            scanner._print_colored(f"[+] Results saved to: {output_file}", Color.CYAN)
    
    elif args.list:
        # Mass scan from file
        try:
            with open(args.list, 'r') as f:
                urls = [scanner.normalize_url(line) for line in f if line.strip()]
            
            if not urls:
                scanner._print_colored("[-] No URLs found in file", Color.RED)
                return
            
            results = scanner.mass_scan(urls, shuffle=args.shuffle, workers=args.workers, verbose=args.verbose)
            
            print()
            scanner._print_colored(f"{'='*60}", Color.CYAN)
            scanner._print_colored(f"[+] SCAN COMPLETED", Color.GREEN)
            scanner._print_colored(f"{'='*60}", Color.CYAN)
            scanner._print_colored(f"Total Targets: {results['total_targets']}", Color.WHITE)
            scanner._print_colored(f"Total Tests: {results['total_tests']}", Color.WHITE)
            scanner._print_colored(f"Total Vulnerabilities: {results['total_vulnerabilities']}", Color.GREEN if results['total_vulnerabilities'] > 0 else Color.CYAN)
            print()
            
            # Summary by severity
            scanner._print_colored("Vulnerabilities by Severity:", Color.MAGENTA)
            if results.get('critical', 0) > 0:
                scanner._print_colored(f"  Critical: {results['critical']}", Color.CRITICAL)
            if results.get('high', 0) > 0:
                scanner._print_colored(f"  High: {results['high']}", Color.HIGH)
            if results.get('medium', 0) > 0:
                scanner._print_colored(f"  Medium: {results['medium']}", Color.MEDIUM)
            if results.get('low', 0) > 0:
                scanner._print_colored(f"  Low: {results['low']}", Color.LOW)
            
            print()
            if output_file:
                scanner._print_colored(f"[+] All results saved to: {output_file}", Color.GREEN)
                scanner._print_colored(f"[*] Vulnerabilities saved in real-time as they are discovered", Color.CYAN)
        
        except FileNotFoundError:
            scanner._print_colored(f"[-] File not found: {args.list}", Color.RED)
            return
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
