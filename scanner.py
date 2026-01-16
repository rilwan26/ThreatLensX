"""
SOC Security Reconnaissance Platform - Backend
Complete security scanning tool with Tor support
"""

import requests
import socket
import ssl
import dns.resolver
import nmap
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import json
import datetime
from typing import Dict, List, Optional
import concurrent.futures
from stem import Signal
from stem.control import Controller
import socks
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess
import hashlib

# ============================================
# CONFIGURATION
# ============================================

class Config:
    TOR_PROXY_HOST = "127.0.0.1"
    TOR_PROXY_PORT = 9050
    TOR_CONTROL_PORT = 9051
    TOR_PASSWORD = ""  # Set if you have Tor password
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    TIMEOUT = 60
    MAX_THREADS = 30

# ============================================
# TOR INTEGRATION
# ============================================

class TorManager:
    """Manages Tor connections for dark web reconnaissance"""
    
    def __init__(self):
        self.session = None
        self.use_tor = False
        
    def setup_tor_session(self):
        """Configure requests to use Tor SOCKS proxy"""
        try:
            self.session = requests.Session()
            self.session.proxies = {
                'http': f'socks5h://{Config.TOR_PROXY_HOST}:{Config.TOR_PROXY_PORT}',
                'https': f'socks5h://{Config.TOR_PROXY_HOST}:{Config.TOR_PROXY_PORT}'
            }
            self.session.headers.update({'User-Agent': Config.USER_AGENT})
            self.use_tor = True
            print("[+] Tor session configured")
            return True
        except Exception as e:
            print(f"[-] Failed to setup Tor: {e}")
            return False
    
    def renew_tor_identity(self):
        """Request new Tor identity (new exit node)"""
        try:
            with Controller.from_port(port=Config.TOR_CONTROL_PORT) as controller:
                if Config.TOR_PASSWORD:
                    controller.authenticate(password=Config.TOR_PASSWORD)
                else:
                    controller.authenticate()
                controller.signal(Signal.NEWNYM)
                print("[+] Tor identity renewed")
                return True
        except Exception as e:
            print(f"[-] Failed to renew Tor identity: {e}")
            return False
    
    def get_tor_ip(self):
        """Get current Tor exit node IP"""
        try:
            response = self.session.get('https://check.torproject.org/api/ip')
            return response.json()
        except Exception as e:
            print(f"[-] Failed to get Tor IP: {e}")
            return None

# ============================================
# IP & DNS RECONNAISSANCE
# ============================================

class IPRecon:
    """IP address and DNS reconnaissance"""
    
    @staticmethod
    def resolve_dns(domain: str) -> Dict:
        """Resolve DNS records for target domain"""
        results = {
            'ipv4': [],
            'ipv6': [],
            'mx': [],
            'ns': [],
            'txt': [],
            'cname': []
        }
        
        try:
            # A records (IPv4)
            answers = dns.resolver.resolve(domain, 'A')
            results['ipv4'] = [str(rdata) for rdata in answers]
        except:
            pass
            
        try:
            # AAAA records (IPv6)
            answers = dns.resolver.resolve(domain, 'AAAA')
            results['ipv6'] = [str(rdata) for rdata in answers]
        except:
            pass
            
        try:
            # MX records
            answers = dns.resolver.resolve(domain, 'MX')
            results['mx'] = [str(rdata.exchange) for rdata in answers]
        except:
            pass
            
        try:
            # NS records
            answers = dns.resolver.resolve(domain, 'NS')
            results['ns'] = [str(rdata) for rdata in answers]
        except:
            pass
            
        try:
            # TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            results['txt'] = [str(rdata) for rdata in answers]
        except:
            pass
        
        return results
    
    @staticmethod
    def get_ip_info(ip: str) -> Dict:
        """Get geolocation and organization info for IP"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
        except Exception as e:
            print(f"[-] IP info lookup failed: {e}")
        
        return {}
    
    @staticmethod
    def reverse_dns(ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

# ============================================
# PORT SCANNING
# ============================================

class PortScanner:
    """Network port scanning"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan_ports(self, target: str, ports: str = "1-1000") -> Dict:
        """Scan common ports on target"""
        results = {
            'scan_time': datetime.datetime.now().isoformat(),
            'target': target,
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': []
        }
        
        try:
            print(f"[*] Scanning ports {ports} on {target}...")
            self.nm.scan(target, ports, arguments='-sV -T4')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports_data = self.nm[host][proto].keys()
                    for port in ports_data:
                        port_info = self.nm[host][proto][port]
                        port_data = {
                            'port': port,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        
                        if port_info['state'] == 'open':
                            results['open_ports'].append(port_data)
                        elif port_info['state'] == 'filtered':
                            results['filtered_ports'].append(port_data)
                        else:
                            results['closed_ports'].append(port_data)
            
            print(f"[+] Found {len(results['open_ports'])} open ports")
            
        except Exception as e:
            print(f"[-] Port scan failed: {e}")
        
        return results

# ============================================
# SSL/TLS CERTIFICATE ANALYSIS
# ============================================

class SSLAnalyzer:
    """SSL/TLS certificate and configuration analysis"""
    
    @staticmethod
    def analyze_certificate(hostname: str, port: int = 443) -> Dict:
        """Analyze SSL certificate"""
        results = {
            'valid': False,
            'issuer': '',
            'subject': '',
            'valid_from': '',
            'valid_to': '',
            'days_remaining': 0,
            'san': [],
            'cipher_suite': '',
            'protocol_version': ''
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=60) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    results['issuer'] = cert.issuer.rfc4514_string()
                    results['subject'] = cert.subject.rfc4514_string()
                    results['valid_from'] = cert.not_valid_before.isoformat()
                    results['valid_to'] = cert.not_valid_after.isoformat()
                    
                    # Calculate days remaining
                    days_remaining = (cert.not_valid_after - datetime.datetime.now()).days
                    results['days_remaining'] = days_remaining
                    results['valid'] = days_remaining > 0
                    
                    # Get SAN (Subject Alternative Names)
                    try:
                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        results['san'] = [str(name) for name in san_ext.value]
                    except:
                        pass
                    
                    # Get cipher and protocol
                    results['cipher_suite'] = ssock.cipher()[0]
                    results['protocol_version'] = ssock.version()
                    
        except Exception as e:
            print(f"[-] SSL analysis failed: {e}")
        
        return results

# ============================================
# WEB CRAWLER & SCRAPER
# ============================================

class WebCrawler:
    """Web crawling and data extraction"""
    
    def __init__(self, use_tor=False, tor_manager=None):
        self.session = tor_manager.session if (use_tor and tor_manager) else requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        self.visited_urls = set()
        
    def fetch_page(self, url: str) -> Optional[str]:
        """Fetch page content"""
        try:
            response = self.session.get(url, timeout=Config.TIMEOUT, verify=True)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"[-] Failed to fetch {url}: {e}")
            return None
    
    def extract_links(self, url: str, html: str) -> List[str]:
        """Extract all links from HTML"""
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                links.append(absolute_url)
        except Exception as e:
            print(f"[-] Link extraction failed: {e}")
        return links
    
    def extract_emails(self, html: str) -> List[str]:
        """Extract email addresses from HTML"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, html)))
    
    def extract_metadata(self, html: str) -> Dict:
        """Extract page metadata"""
        metadata = {
            'title': '',
            'description': '',
            'keywords': '',
            'author': '',
            'og_tags': {}
        }
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Title
            title_tag = soup.find('title')
            if title_tag:
                metadata['title'] = title_tag.text.strip()
            
            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                property_attr = meta.get('property', '').lower()
                content = meta.get('content', '')
                
                if name == 'description':
                    metadata['description'] = content
                elif name == 'keywords':
                    metadata['keywords'] = content
                elif name == 'author':
                    metadata['author'] = content
                elif property_attr.startswith('og:'):
                    metadata['og_tags'][property_attr] = content
                    
        except Exception as e:
            print(f"[-] Metadata extraction failed: {e}")
        
        return metadata
    
    def crawl(self, start_url: str, max_depth: int = 2) -> Dict:
        """Crawl website starting from URL"""
        results = {
            'start_url': start_url,
            'pages_crawled': 0,
            'links_found': [],
            'emails': [],
            'external_links': [],
            'internal_links': []
        }
        
        domain = urlparse(start_url).netloc
        to_visit = [(start_url, 0)]
        
        while to_visit and results['pages_crawled'] < 100:
            url, depth = to_visit.pop(0)
            
            if url in self.visited_urls or depth > max_depth:
                continue
            
            print(f"[*] Crawling: {url} (depth: {depth})")
            self.visited_urls.add(url)
            
            html = self.fetch_page(url)
            if not html:
                continue
            
            results['pages_crawled'] += 1
            
            # Extract emails
            emails = self.extract_emails(html)
            results['emails'].extend(emails)
            
            # Extract links
            links = self.extract_links(url, html)
            for link in links:
                link_domain = urlparse(link).netloc
                
                if link_domain == domain:
                    results['internal_links'].append(link)
                    if depth < max_depth:
                        to_visit.append((link, depth + 1))
                else:
                    results['external_links'].append(link)
        
        # Remove duplicates
        results['emails'] = list(set(results['emails']))
        results['internal_links'] = list(set(results['internal_links']))
        results['external_links'] = list(set(results['external_links']))
        
        return results

# ============================================
# VULNERABILITY SCANNER
# ============================================

class VulnerabilityScanner:
    """Web application vulnerability scanner"""
    
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
    
    def check_security_headers(self, url: str) -> Dict:
        """Check for security headers"""
        results = {
            'score': 0,
            'present': [],
            'missing': [],
            'headers': {}
        }
        
        security_headers = {
            'Strict-Transport-Security': {'risk': 'high', 'description': 'Missing HSTS header'},
            'Content-Security-Policy': {'risk': 'high', 'description': 'Missing CSP allows XSS'},
            'X-Frame-Options': {'risk': 'medium', 'description': 'Vulnerable to clickjacking'},
            'X-Content-Type-Options': {'risk': 'medium', 'description': 'MIME sniffing enabled'},
            'X-XSS-Protection': {'risk': 'medium', 'description': 'No XSS protection'},
            'Referrer-Policy': {'risk': 'low', 'description': 'Information leakage possible'}
        }
        
        try:
            response = self.session.get(url, timeout=Config.TIMEOUT)
            results['headers'] = dict(response.headers)
            
            for header, info in security_headers.items():
                if header in response.headers:
                    results['present'].append({
                        'header': header,
                        'value': response.headers[header],
                        'status': 'good'
                    })
                    results['score'] += 1
                else:
                    results['missing'].append({
                        'header': header,
                        'risk': info['risk'],
                        'description': info['description']
                    })
            
            results['score'] = f"{results['score']}/{len(security_headers)}"
            
        except Exception as e:
            print(f"[-] Security header check failed: {e}")
        
        return results
    
    def detect_waf(self, url: str) -> Dict:
        """Detect Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray'],
            'AWS WAF': ['x-amzn-', 'x-amz-'],
            'Akamai': ['AkamaiGHost'],
            'Imperva': ['incap_ses', 'visid_incap']
        }
        
        results = {
            'detected': False,
            'provider': None,
            'confidence': 0,
            'indicators': []
        }
        
        try:
            response = self.session.get(url, timeout=Config.TIMEOUT)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            cookies = response.cookies.get_dict()
            
            for provider, signatures in waf_signatures.items():
                matches = 0
                for sig in signatures:
                    sig_lower = sig.lower()
                    # Check headers
                    if any(sig_lower in h for h in headers_lower.keys()):
                        matches += 1
                        results['indicators'].append(f"Header: {sig}")
                    # Check cookies
                    if any(sig in c for c in cookies.keys()):
                        matches += 1
                        results['indicators'].append(f"Cookie: {sig}")
                
                if matches > 0:
                    results['detected'] = True
                    results['provider'] = provider
                    results['confidence'] = min(100, matches * 50)
                    break
                    
        except Exception as e:
            print(f"[-] WAF detection failed: {e}")
        
        return results

# ============================================
# MAIN SCANNER CLASS
# ============================================

class SecurityScanner:
    """Main security scanning orchestrator"""
    
    def __init__(self, use_tor=False):
        self.tor_manager = TorManager() if use_tor else None
        self.use_tor = use_tor
        
        if use_tor:
            self.tor_manager.setup_tor_session()
    
    def full_scan(self, target_url: str, scan_depth: int = 2) -> Dict:
        """Perform comprehensive security scan"""
        print(f"\n{'='*60}")
        print(f"[*] Starting Security Scan: {target_url}")
        print(f"{'='*60}\n")
        
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        results = {
            'target': target_url,
            'domain': domain,
            'scan_id': f"SCAN-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.datetime.now().isoformat(),
            'using_tor': self.use_tor
        }
        
        # 1. DNS & IP Information
        print("[*] Stage 1: DNS Resolution & IP Information")
        ip_recon = IPRecon()
        dns_records = ip_recon.resolve_dns(domain)
        results['dns_records'] = dns_records
        
        if dns_records['ipv4']:
            main_ip = dns_records['ipv4'][0]
            ip_info = ip_recon.get_ip_info(main_ip)
            results['ip_information'] = ip_info
            reverse_dns = ip_recon.reverse_dns(main_ip)
            results['reverse_dns'] = reverse_dns
        
        # 2. Port Scanning (optional - requires sudo)
        # Uncomment if you have proper permissions
        # print("[*] Stage 2: Port Scanning")
        # port_scanner = PortScanner()
        # port_results = port_scanner.scan_ports(main_ip, "1-1000")
        # results['port_scan'] = port_results
        
        # 3. SSL/TLS Analysis
        if parsed.scheme == 'https':
            print("[*] Stage 3: SSL/TLS Certificate Analysis")
            ssl_analyzer = SSLAnalyzer()
            ssl_results = ssl_analyzer.analyze_certificate(domain)
            results['ssl_certificate'] = ssl_results
        
        # 4. Security Headers
        print("[*] Stage 4: Security Headers Analysis")
        vuln_scanner = VulnerabilityScanner(
            self.tor_manager.session if self.use_tor else None
        )
        headers_results = vuln_scanner.check_security_headers(target_url)
        results['security_headers'] = headers_results
        
        # 5. WAF Detection
        print("[*] Stage 5: WAF Detection")
        waf_results = vuln_scanner.detect_waf(target_url)
        results['waf_detection'] = waf_results
        
        # 6. Web Crawling & OSINT
        print(f"[*] Stage 6: Web Crawling (depth: {scan_depth})")
        crawler = WebCrawler(self.use_tor, self.tor_manager)
        crawl_results = crawler.crawl(target_url, scan_depth)
        results['crawl_data'] = crawl_results
        
        # 7. Calculate Security Score
        results['security_score'] = self._calculate_security_score(results)
        
        print(f"\n{'='*60}")
        print(f"[+] Scan Complete!")
        print(f"[+] Security Score: {results['security_score']['overall']}/100")
        print(f"{'='*60}\n")
        
        return results
    
    def _calculate_security_score(self, scan_results: Dict) -> Dict:
        """Calculate overall security score"""
        score = {
            'overall': 0,
            'breakdown': {
                'ssl': 0,
                'headers': 0,
                'waf': 0,
                'dns': 0
            }
        }
        
        # SSL Score
        if 'ssl_certificate' in scan_results:
            ssl = scan_results['ssl_certificate']
            if ssl.get('valid'):
                score['breakdown']['ssl'] = 100
                if ssl.get('days_remaining', 0) < 30:
                    score['breakdown']['ssl'] -= 20
        
        # Headers Score
        if 'security_headers' in scan_results:
            headers = scan_results['security_headers']
            present_count = len(headers.get('present', []))
            missing_count = len(headers.get('missing', []))
            total = present_count + missing_count
            if total > 0:
                score['breakdown']['headers'] = int((present_count / total) * 100)
        
        # WAF Score
        if 'waf_detection' in scan_results:
            if scan_results['waf_detection'].get('detected'):
                score['breakdown']['waf'] = 100
            else:
                score['breakdown']['waf'] = 50
        
        # DNS Score
        if 'dns_records' in scan_results:
            dns = scan_results['dns_records']
            if dns.get('ipv4') and dns.get('ipv6'):
                score['breakdown']['dns'] = 100
            elif dns.get('ipv4'):
                score['breakdown']['dns'] = 75
        
        # Calculate overall
        score['overall'] = sum(score['breakdown'].values()) // len(score['breakdown'])
        
        return score
    
    def export_results(self, results: Dict, filename: str = None):
        """Export scan results to JSON file"""
        if not filename:
            filename = f"scan_{results['scan_id']}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"[+] Results exported to: {filename}")

# ============================================
# MAIN EXECUTION
# ============================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SOC Security Reconnaissance Platform')
    parser.add_argument('target', help='Target URL to scan')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('-t', '--tor', action='store_true', help='Use Tor network')
    parser.add_argument('-o', '--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = SecurityScanner(use_tor=args.tor)
    
    # Perform scan
    results = scanner.full_scan(args.target, args.depth)
    
    # Export results
    scanner.export_results(results, args.output)
    
    # Print summary
    print("\n=== SCAN SUMMARY ===")
    print(f"Target: {results['target']}")
    print(f"Security Score: {results['security_score']['overall']}/100")
    print(f"Pages Crawled: {results['crawl_data']['pages_crawled']}")
    print(f"Emails Found: {len(results['crawl_data']['emails'])}")
    print(f"WAF Detected: {results['waf_detection']['detected']}")
    if results['waf_detection']['detected']:
        print(f"WAF Provider: {results['waf_detection']['provider']}")

if __name__ == "__main__":
    main()
