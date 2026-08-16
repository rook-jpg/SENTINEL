#!/usr/bin/env python3
"""
Web Security Scanner - Integrates Nikto, SSL/TLS scanning, and other security tools
WARNING: Only use on systems you own or have explicit permission to test!
"""

import subprocess
import sys
import os
import json
import datetime
import argparse
import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

class WebSecurityScanner:
    def __init__(self, target, output_dir="scan_results", threads=5, timeout=10):
        """
        Initialize the Web Security Scanner
        
        Args:
            target: Target URL or IP to scan
            output_dir: Directory to store scan results
            threads: Number of concurrent threads
            timeout: Timeout for requests in seconds
        """
        self.target = target
        self.output_dir = output_dir
        self.threads = threads
        self.timeout = timeout
        self.results = {}
        self.tools_available = self._check_tools()
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Parse target
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'https://{target}')
        self.hostname = parsed.hostname or target
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
    def _check_tools(self):
        """Check which security tools are available on the system"""
        tools = {
            'nikto': False,
            'nmap': False,
            'testssl': False,
            'sslyze': False,
            'openssl': False,
            'whatweb': False,
            'wafw00f': False,
            'gobuster': False,
        }
        
        for tool in tools:
            try:
                subprocess.run([tool, '--version' if tool != 'nikto' else '-Version'], 
                             capture_output=True, timeout=5)
                tools[tool] = True
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
                
        return tools
    
    def _print_repo_banner(self):
        """Print a prominent repository banner with the repo name (SENTINEL).
        This will appear when the scanner runs.
        """
        # Try to use pyfiglet for a large banner if available, otherwise use a built-in ASCII fallback
        banner_text = "SENTINEL"
        try:
            import pyfiglet
            fig = pyfiglet.Figlet(font='slant')
            art = fig.renderText(banner_text)
            print(Style.BRIGHT + Fore.MAGENTA + art + Style.RESET_ALL)
        except Exception:
            # Simple ASCII fallback
            art = (
                "  _____  _____ _____ _____ _   _ _____ _   _ \n"
                " / ____|/ ____/ ____/ ____| \ | |_   _| \ | |\n"
                "| (___ | (___| (___| (___ |  \| | | | |  \| |\n"
                " \___ \\ \___ \\___ \\___ \\| . ` | | | | . ` |\n"
                " ____) |____) |___) |___) | |\  |_| |_| | |\  |\n"
                "|_____/|_____/_____/_____/|_| \_|_____|_| \_|\n"
            )
            print(Style.BRIGHT + Fore.MAGENTA + art + Style.RESET_ALL)
            # Also print bold repo name for clarity
            print(Style.BRIGHT + Fore.YELLOW + "**SENTINEL**" + Style.RESET_ALL)

    def print_banner(self):
        """Print scanner banner"""
        # Repo banner (big name) — this is what the user asked to appear when it runs
        self._print_repo_banner()

        banner = f"""
 {Fore.CYAN}{'='*60}
 {Fore.YELLOW}🔍 WEB SECURITY SCANNER
 {Fore.CYAN}{'='*60}
 {Fore.GREEN}Target: {self.target}
 {Fore.GREEN}Hostname: {self.hostname}
 {Fore.GREEN}Port: {self.port}
 {Fore.GREEN}Output Directory: {self.output_dir}
 {Fore.CYAN}{'='*60}
         """
        print(banner)
        self._print_tools_status()
        
    def _print_tools_status(self):
        """Print available tools status"""
        print(f"\n{Fore.YELLOW}Available Tools:")
        for tool, available in self.tools_available.items():
            status = f"{Fore.GREEN}✓ Available" if available else f"{Fore.RED}✗ Not Found"
            print(f"  • {tool}: {status}")
        print(f"{Fore.CYAN}{'='*60}\n")
    
    def run_command(self, command, timeout=300):
        """Execute a shell command and return output"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {str(e)}"
    
    def scan_nikto(self):
        """Run Nikto web server scanner"""
        if not self.tools_available['nikto']:
            return "Nikto is not installed. Install with: sudo apt-get install nikto"
        
        print(f"{Fore.BLUE}[*] Running Nikto scan...")
        output_file = os.path.join(self.output_dir, "nikto_scan.txt")
        
        # Nikto command with various options
        command = (
            f"nikto -h {self.target} "
            f"-port {self.port} "
            f"-Tuning 123456789 "  # Enable all tests
            f"-Format txt "
            f"-output {output_file} "
            f"-timeout {self.timeout}"
        )
        
        result = self.run_command(command, timeout=600)
        self.results['nikto'] = {
            'output_file': output_file,
            'raw_output': result
        }
        return result
    
    def scan_ssl_tls(self):
        """Perform comprehensive SSL/TLS scanning"""
        print(f"{Fore.BLUE}[*] Running SSL/TLS scan...")
        
        ssl_results = {}
        
        # Basic SSL/TLS check using Python's ssl module
        ssl_results['basic_check'] = self._python_ssl_check()
        
        # OpenSSL check if available
        if self.tools_available['openssl']:
            ssl_results['openssl'] = self._openssl_check()
        
        # SSLyze scan if available
        if self.tools_available['sslyze']:
            ssl_results['sslyze'] = self._sslyze_scan()
        
        # TestSSL.sh if available
        if self.tools_available['testssl']:
            ssl_results['testssl'] = self._testssl_scan()
        
        self.results['ssl_tls'] = ssl_results
        return ssl_results
    
    def _python_ssl_check(self):
        """Perform basic SSL/TLS check using Python's ssl module"""
        result = {}
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    result['ssl_version'] = ssock.version()
                    result['cipher'] = ssock.cipher()
                    result['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
                    
                    # Check certificate expiration
                    from datetime import datetime
                    import time
                    
                    exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (exp_date - datetime.now()).days
                    result['days_until_expiration'] = days_left
                    result['expired'] = days_left <= 0
                    
                    # Check for vulnerabilities
                    result['vulnerabilities'] = self._check_ssl_vulnerabilities(ssock)
                    
        except Exception as e:
            result['error'] = str(e)
        
        # Save to file
        output_file = os.path.join(self.output_dir, "ssl_basic_check.json")
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        result['output_file'] = output_file
        
        return result
    
    def _check_ssl_vulnerabilities(self, ssock):
        """Check for common SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        # Check SSL version
        version = ssock.version()
        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
            vulnerabilities.append({
                'type': 'outdated_protocol',
                'severity': 'HIGH',
                'description': f'Using outdated protocol: {version}'
            })
        
        # Check for weak ciphers
        cipher = ssock.cipher()
        if cipher:
            cipher_name = cipher[0]
            if 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
                vulnerabilities.append({
                    'type': 'weak_cipher',
                    'severity': 'MEDIUM',
                    'description': f'Using weak cipher: {cipher_name}'
                })
        
        return vulnerabilities
    
    def _openssl_check(self):
        """Check SSL/TLS using OpenSSL"""
        output_file = os.path.join(self.output_dir, "openssl_check.txt")
        result = {}
        
        # Check supported protocols
        protocols = ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2', 'tls1_3']
        for proto in protocols:
            cmd = f"echo | openssl s_client -connect {self.hostname}:{self.port} -{proto} 2>&1"
            output = self.run_command(cmd, timeout=10)
            result[proto] = "CONNECTED" if "CONNECTED" in output else "FAILED"
        
        # Get certificate information
        cert_cmd = f"echo | openssl s_client -connect {self.hostname}:{self.port} -showcerts 2>&1"
        result['certificate_info'] = self.run_command(cert_cmd, timeout=10)
        
        # Save results
        with open(output_file, 'w') as f:
            f.write("=== OpenSSL SSL/TLS Check ===\n\n")
            for proto, status in result.items():
                if proto != 'certificate_info':
                    f.write(f"{proto}: {status}\n")
            f.write(f"\n{result['certificate_info']}")
        
        result['output_file'] = output_file
        return result
    
    def _sslyze_scan(self):
        """Run SSLyze scanner"""
        output_file = os.path.join(self.output_dir, "sslyze_scan.json")
        
        command = f"sslyze --regular {self.hostname}:{self.port} --json_out={output_file}"
        result = self.run_command(command, timeout=300)
        
        return {
            'output_file': output_file,
            'raw_output': result
        }
    
    def _testssl_scan(self):
        """Run testssl.sh scanner"""
        output_file = os.path.join(self.output_dir, "testssl_scan.txt")
        
        command = f"testssl --quiet --color 0 {self.hostname}:{self.port} > {output_file}"
        result = self.run_command(command, timeout=300)
        
        return {
            'output_file': output_file,
            'raw_output': result
        }
    
    def scan_nmap(self):
        """Run Nmap scan for web-related ports and services"""
        if not self.tools_available['nmap']:
            return "Nmap is not installed. Install with: sudo apt-get install nmap"
        
        print(f"{Fore.BLUE}[*] Running Nmap scan...")
        output_file = os.path.join(self.output_dir, "nmap_scan.txt")
        
        command = (
            f"nmap -sV -sC -p {self.port},80,443,8080,8443 "
            f"--script=http-* "
            f"-oN {output_file} "
            f"{self.hostname}"
        )
        
        result = self.run_command(command, timeout=600)
        self.results['nmap'] = {
            'output_file': output_file,
            'raw_output': result
        }
        return result
    
    def scan_whatweb(self):
        """Run WhatWeb scanner to identify technologies"""
        if not self.tools_available['whatweb']:
            return "WhatWeb is not installed. Install with: sudo apt-get install whatweb"
        
        print(f"{Fore.BLUE}[*] Running WhatWeb scan...")
        output_file = os.path.join(self.output_dir, "whatweb_scan.json")
        
        command = f"whatweb {self.target} --log-json={output_file} --colour=never"
        result = self.run_command(command, timeout=120)
        
        self.results['whatweb'] = {
            'output_file': output_file,
            'raw_output': result
        }
        return result
    
    def scan_waf(self):
        """Detect Web Application Firewall using wafw00f"""
        if not self.tools_available['wafw00f']:
            return "wafw00f is not installed. Install with: pip install wafw00f"
        
        print(f"{Fore.BLUE}[*] Running WAF detection...")
        output_file = os.path.join(self.output_dir, "waf_detection.txt")
        
        command = f"wafw00f {self.target} -o {output_file}"
        result = self.run_command(command, timeout=60)
        
        self.results['waf'] = {
            'output_file': output_file,
            'raw_output': result
        }
        return result
    
    def scan_headers(self):
        """Check security headers"""
        print(f"{Fore.BLUE}[*] Checking security headers...")
        
        try:
            # Ensure URL has scheme
            url = self.target if self.target.startswith(('http://', 'https://')) else f'https://{self.target}'
            response = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = dict(response.headers)
            
            # Check important security headers
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'MISSING'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'MISSING'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'MISSING'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'MISSING'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'MISSING'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'MISSING'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'MISSING'),
            }
            
            # Analyze headers
            analysis = []
            if security_headers['Strict-Transport-Security'] == 'MISSING':
                analysis.append("Missing HSTS header - vulnerable to SSL stripping attacks")
            if security_headers['Content-Security-Policy'] == 'MISSING':
                analysis.append("Missing CSP header - vulnerable to XSS attacks")
            if security_headers['X-Frame-Options'] == 'MISSING':
                analysis.append("Missing X-Frame-Options header - vulnerable to clickjacking")
            
            result = {
                'status_code': response.status_code,
                'security_headers': security_headers,
                'all_headers': headers,
                'analysis': analysis
            }
            
            # Save to file
            output_file = os.path.join(self.output_dir, "security_headers.json")
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            self.results['headers'] = {
                'output_file': output_file,
                'result': result
            }
            
            return result
            
        except Exception as e:
            return f"Error checking headers: {str(e)}"
    
    def scan_cookies(self):
        """Check cookie security"""
        print(f"{Fore.BLUE}[*] Checking cookie security...")
        
        try:
            url = self.target if self.target.startswith(('http://', 'https://')) else f'https://{self.target}'
            response = requests.get(url, timeout=self.timeout, verify=False)
            
            cookies = {}
            for cookie in response.cookies:
                cookies[cookie.name] = {
                    'value': cookie.value,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite', 'Not Set')
                }
            
            # Analyze cookie security
            issues = []
            for name, attrs in cookies.items():
                if not attrs['secure']:
                    issues.append(f"Cookie '{name}' missing Secure flag")
                if not attrs['httponly']:
                    issues.append(f"Cookie '{name}' missing HttpOnly flag")
                if attrs['samesite'] == 'Not Set':
                    issues.append(f"Cookie '{name}' missing SameSite attribute")
            
            result = {
                'cookies': cookies,
                'security_issues': issues
            }
            
            output_file = os.path.join(self.output_dir, "cookie_security.json")
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            self.results['cookies'] = {
                'output_file': output_file,
                'result': result
            }
            
            return result
            
        except Exception as e:
            return f"Error checking cookies: {str(e)}"
    
    def run_directory_scan(self):
        """Run directory/file enumeration if gobuster is available"""
        if not self.tools_available['gobuster']:
            return "Gobuster is not installed. Install with: sudo apt-get install gobuster"
        
        print(f"{Fore.BLUE}[*] Running directory enumeration...")
        output_file = os.path.join(self.output_dir, "gobuster_scan.txt")
        
        # Check if wordlist exists
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/dirb/wordlists/common.txt"
        
        if not os.path.exists(wordlist):
            return "No wordlist found for directory scanning"
        
        command = f"gobuster dir -u {self.target} -w {wordlist} -o {output_file} -q"
        result = self.run_command(command, timeout=300)
        
        self.results['directory_scan'] = {
            'output_file': output_file,
            'raw_output': result
        }
        return result
    
    def run_full_scan(self):
        """Execute all available scans"""
        self.print_banner()
        
        scans = []
        
        # Add available scans
        scans.append(('Nikto', self.scan_nikto))
        scans.append(('SSL/TLS', self.scan_ssl_tls))
        scans.append(('Nmap', self.scan_nmap))
        scans.append(('WhatWeb', self.scan_whatweb))
        scans.append(('WAF Detection', self.scan_waf))
        scans.append(('Security Headers', self.scan_headers))
        scans.append(('Cookie Security', self.scan_cookies))
        scans.append(('Directory Scan', self.run_directory_scan))
        
        # Run scans concurrently
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_scan = {
                executor.submit(scan_func): name 
                for name, scan_func in scans
            }
            
            for future in as_completed(future_to_scan):
                scan_name = future_to_scan[future]
                try:
                    print(f"\n{Fore.GREEN}[✓] Completed {scan_name} scan")
                    future.result()
                except Exception as e:
                    print(f"\n{Fore.RED}[✗] Error in {scan_name} scan: {str(e)}")
        
        self.generate_report()
    
    def generate_report(self):
        """Generate summary report of all findings"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}📊 SCAN SUMMARY REPORT")
        print(f"{Fore.CYAN}{'='*60}")
        
        report = {
            'scan_date': datetime.datetime.now().isoformat(),
            'target': self.target,
            'hostname': self.hostname,
            'port': self.port,
            'tools_used': [tool for tool, available in self.tools_available.items() if available],
            'results_summary': {}
        }
        
        # Compile findings
        for scan_type, scan_data in self.results.items():
            report['results_summary'][scan_type] = {
                'completed': True,
                'output_files': scan_data.get('output_file', 'N/A')
            }
        
        # Add critical findings
        if 'ssl_tls' in self.results:
            ssl_data = self.results['ssl_tls'].get('basic_check', {})
            if 'vulnerabilities' in ssl_data:
                vulnerabilities = ssl_data['vulnerabilities']
                if vulnerabilities:
                    report['critical_findings'] = vulnerabilities
        
        # Save report
        report_file = os.path.join(self.output_dir, "scan_summary_report.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}Report saved to: {report_file}")
        print(f"{Fore.YELLOW}All scan results saved in: {self.output_dir}/")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        # Print critical findings
        if 'critical_findings' in report:
            print(f"\n{Fore.RED}🚨 CRITICAL FINDINGS:")
            for finding in report['critical_findings']:
                print(f"  • {finding['description']}")

def main():
    parser = argparse.ArgumentParser(
        description="Web Security Scanner - Comprehensive web application security assessment tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 web_scanner.py https://example.com
  python3 web_scanner.py example.com -p 8080 -t 10
  python3 web_scanner.py https://example.com --output results/
  
WARNING: Only use on systems you own or have explicit permission to test!
        """
    )
    
    parser.add_argument('target', help='Target URL or IP address')
    parser.add_argument('-p', '--port', type=int, help='Target port (default: auto-detect)')
    parser.add_argument('-o', '--output', default='scan_results', help='Output directory for results')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--ssl-only', action='store_true', help='Run only SSL/TLS scans')
    parser.add_argument('--quick', action='store_true', help='Run quick scan (skip time-intensive scans)')
    
    args = parser.parse_args()
    
    # Suppress SSL warnings for testing
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Initialize scanner
    scanner = WebSecurityScanner(
        target=args.target,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    
    # Run appropriate scan
    if args.ssl_only:
        print(f"{Fore.YELLOW}Running SSL/TLS only scan...")
        scanner.scan_ssl_tls()
        scanner.generate_report()
    elif args.quick:
        print(f"{Fore.YELLOW}Running quick scan...")
        scanner.print_banner()
        scanner.scan_ssl_tls()
        scanner.scan_headers()
        scanner.scan_cookies()
        scanner.generate_report()
    else:
        scanner.run_full_scan()

if __name__ == "__main__":
    # Check for root privileges (some tools like Nikto prefer it)
    if os.geteuid() != 0:
        print(f"{Fore.YELLOW}⚠️  Warning: Some scans may work better with root privileges")
        print(f"{Fore.YELLOW}Consider running with: sudo python3 {sys.argv[0]}\n")
    
    main()
