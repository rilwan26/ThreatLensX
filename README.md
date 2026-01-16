# SOC Security Reconnaissance Platform

Advanced security reconnaissance and vulnerability scanning platform for SOC operations.

## Features

- 🔍 Comprehensive web reconnaissance
- 🌐 IP address and DNS analysis
- 🔐 SSL/TLS certificate inspection
- 🛡️ Security headers analysis
- 🕷️ Web crawling and OSINT gathering
- 🕵️ Dark web scanning with Tor support
- 📊 Vulnerability detection and scoring
- 🔥 WAF detection
- 📁 Export capabilities

## Installation

cd backend
source venv/bin/activate

# Basic scan
python scanner.py https://example.com

# Deep scan with more depth
python scanner.py https://example.com -d 3

# Scan using Tor
python scanner.py https://example.com -t

# Scan with custom output file
python scanner.py https://example.com -o my_scan_results.json

## Legal Notice

This tool is for authorized security testing only. Always obtain written permission before scanning any target.

## License

MIT License
