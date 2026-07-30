#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║   🕵️  SECRETSPY - Real Website Secret Scanner                ║
║   Finds exposed API keys, tokens, and secrets on websites    ║
║   Professional-grade security tool                          ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
    python3 secretspy.py https://example.com
    python3 secretspy.py https://example.com --max-pages 30
    python3 secretspy.py https://example.com --output report.json
"""

import requests
import re
import json
import sys
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
from datetime import datetime

class SecretSpy:
    def __init__(self):
        self.name = "SecretSpy"
        self.version = "1.0"
        self.findings = []
        self.visited = set()
        self.js_files = []
        self.source_maps = []
        self.start_time = None
        self.end_time = None
        
        # Headers to look like a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        # SECRET PATTERNS THAT ACTUALLY WORK
        self.patterns = {
            # Google APIs (common in JS files)
            '🔑 Google Maps API Key': r'AIza[0-9A-Za-z\-_]{35}',
            '🔑 Google Analytics ID': r'UA-\d{4,}-\d{1,2}',
            '🔑 Google Tag Manager': r'GTM-[A-Z0-9]{4,}',
            '🔑 Google Firebase Config': r'firebaseConfig\s*=\s*{[^}]*apiKey:\s*["\']([^"\']+)["\']',
            
            # AWS (rare but valuable)
            '🔑 AWS Access Key': r'AKIA[0-9A-Z]{16}',
            '🔑 AWS Secret Key': r'[A-Za-z0-9/+=]{40}',
            
            # Payment processors
            '🔑 Stripe Publishable Key': r'pk_(test|live)_[A-Za-z0-9]{24,}',
            '🔑 Stripe Secret Key': r'sk_(test|live)_[A-Za-z0-9]{24,}',
            
            # GitHub
            '🔑 GitHub Token': r'gh[pousr]_[A-Za-z0-9]{36,}',
            
            # JWT Tokens (common in APIs)
            '🔑 JWT Token': r'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}',
            
            # Slack
            '🔑 Slack Webhook': r'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}',
            '🔑 Slack Token': r'xox[baprs]-[A-Za-z0-9-]{10,}',
            
            # Databases
            '🔑 MongoDB URI': r'mongodb(\+srv)?://[A-Za-z0-9._%-]+:[^@\s]+@[^\s\'"]+',
            '🔑 PostgreSQL URI': r'postgresql://[A-Za-z0-9._%-]+:[^@\s]+@[^\s\'"]+',
            '🔑 MySQL URI': r'mysql://[A-Za-z0-9._%-]+:[^@\s]+@[^\s\'"]+',
            
            # Source Maps (GOLDMINE!)
            '📁 Source Map Found': r'(?://|#)\s*sourceMappingURL=([^\s]+\.map)',
            
            # Internal APIs
            '🔗 Internal API Endpoint': r'(https?://[^\s\'"]*api[^\s\'"]*)',
            
            # Test data (devs forget these)
            '🧪 Test Credential': r'(?i)(password|passwd|secret|token)\s*[=:]\s*["\']([^"\'\s]{4,})["\']',
            '🧪 Test Email': r'\b[\w\.-]+@(example|test|demo)\.com\b',
            
            # Internal IPs
            '🌐 Internal IP': r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
            
            # Private keys
            '🔒 Private Key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        }
        
        # False positives to ignore
        self.ignore = [
            'example.com', 'test.com', 'localhost', '127.0.0.1', '0.0.0.0',
            'AKIAIOSFODNN7EXAMPLE', 'sk_test_', 'pk_test_',
            'YOUR_KEY', 'REPLACE_ME', 'TODO', 'FIXME',
            'xxxxxxxx', '00000000', '11111111',
            'demo', 'sample', 'placeholder'
        ]

    def scan(self, url, max_pages=15, output=None):
        """Main scanning function"""
        self.start_time = datetime.now()
        
        print(f"""
        ╔═══════════════════════════════════════════════════════════════╗
        ║   🕵️  SECRETSPY v{self.version}                                ║
        ║   Real Website Secret Scanner                                ║
        ╚═══════════════════════════════════════════════════════════════╝
        """)
        
        print(f"🎯 Target: {url}")
        print(f"📄 Max Pages: {max_pages}")
        print("=" * 60)
        
        if not url.startswith('http'):
            url = 'https://' + url
        
        # Start crawling
        to_visit = [url]
        visited_count = 0
        
        while to_visit and visited_count < max_pages:
            current_url = to_visit.pop(0)
            
            if current_url in self.visited:
                continue
            
            self.visited.add(current_url)
            visited_count += 1
            
            print(f"\n📄 [{visited_count}/{max_pages}] Scanning: {current_url[:70]}...")
            
            try:
                # Fetch the page
                response = requests.get(current_url, headers=self.headers, timeout=10, verify=False)
                
                # Only process text content
                content_type = response.headers.get('Content-Type', '')
                if 'text' not in content_type and 'json' not in content_type:
                    continue
                
                content = response.text
                
                # SCAN FOR SECRETS
                page_findings = self.find_secrets(content, current_url)
                if page_findings:
                    self.findings.extend(page_findings)
                    print(f"   ⚠️  Found {len(page_findings)} secrets!")
                    for finding in page_findings[:3]:
                        print(f"      → {finding['type']}: {finding['match']}")
                
                # FIND JS FILES
                js_urls = self.extract_js_files(content, current_url)
                for js_url in js_urls:
                    if js_url not in self.visited and js_url not in to_visit:
                        to_visit.append(js_url)
                        self.js_files.append(js_url)
                
                # FIND SOURCE MAPS (GOLDMINE!)
                maps = self.extract_source_maps(content, current_url)
                for map_url in maps:
                    self.source_maps.append(map_url)
                    print(f"   📁 Found source map: {map_url.split('/')[-1]}")
                
                # FIND LINKS TO CRAWL
                links = self.extract_links(content, current_url)
                for link in links:
                    if self.same_domain(link, url) and link not in self.visited:
                        if link not in to_visit:
                            to_visit.append(link)
                
                time.sleep(0.3)  # Be polite
                
            except Exception as e:
                print(f"   ❌ Error: {str(e)[:50]}")
                continue
        
        # SCAN SOURCE MAPS (this is where the GOOD stuff is)
        if self.source_maps:
            print("\n📁 Scanning Source Maps (finding hidden secrets...)")
            for map_url in self.source_maps[:5]:
                self.scan_source_map(map_url)
        
        self.end_time = datetime.now()
        self.generate_report(output)
        return self.findings

    def find_secrets(self, content, url):
        """Find secrets in content"""
        findings = []
        
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            for match in matches:
                # Skip false positives
                should_ignore = False
                for ignore in self.ignore:
                    if ignore in str(match).lower():
                        should_ignore = True
                        break
                if should_ignore:
                    continue
                
                # Don't report tiny matches
                if len(str(match)) < 4:
                    continue
                
                # Get context
                context = self.get_context(content, str(match))
                
                # Determine severity
                severity = 'CRITICAL' if any(keyword in pattern_name for keyword in ['AWS', 'Secret', 'Private']) else 'HIGH'
                
                findings.append({
                    'type': pattern_name,
                    'url': url,
                    'match': str(match)[:50] + '...' if len(str(match)) > 50 else str(match),
                    'full_match': str(match),
                    'context': context[:200] + '...' if len(context) > 200 else context,
                    'severity': severity
                })
        
        return findings

    def extract_js_files(self, html, base_url):
        """Extract JavaScript file URLs"""
        js_urls = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup.find_all('script'):
            src = script.get('src')
            if src and src.endswith('.js'):
                js_urls.append(urljoin(base_url, src))
        
        for link in soup.find_all('link'):
            href = link.get('href')
            if href and href.endswith('.js'):
                js_urls.append(urljoin(base_url, href))
        
        return js_urls

    def extract_source_maps(self, content, base_url):
        """Extract source map URLs"""
        maps = []
        pattern = r'(?://|#)\s*sourceMappingURL=([^\s]+\.map)'
        matches = re.findall(pattern, content)
        
        for match in matches:
            maps.append(urljoin(base_url, match))
        
        return maps

    def scan_source_map(self, map_url):
        """Scan a source map - this finds original source code"""
        try:
            response = requests.get(map_url, headers=self.headers, timeout=10)
            data = response.json()
            
            if 'sources' in data:
                for source in data['sources']:
                    if any(keyword in source.lower() for keyword in ['api', 'key', 'secret', 'config', 'env', 'auth']):
                        self.findings.append({
                            'type': '📁 Source Map - Suspicious File',
                            'url': map_url,
                            'match': source.split('/')[-1],
                            'full_match': source,
                            'context': 'Found in source map - review for secrets',
                            'severity': 'HIGH'
                        })
            
            if 'sourcesContent' in data:
                for content in data['sourcesContent']:
                    if content and len(content) > 100:
                        hidden_findings = self.find_secrets(content, map_url)
                        if hidden_findings:
                            self.findings.extend(hidden_findings)
                            
        except Exception:
            pass

    def extract_links(self, html, base_url):
        """Extract links for crawling"""
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        for tag in soup.find_all(['a', 'link']):
            href = tag.get('href')
            if href:
                full_url = urljoin(base_url, href)
                if full_url.startswith('http'):
                    links.append(full_url)
        
        return links

    def same_domain(self, url, base_url):
        """Check if URL is on same domain"""
        try:
            return urlparse(url).netloc == urlparse(base_url).netloc
        except:
            return False

    def get_context(self, content, match):
        """Get context around the match"""
        try:
            index = content.find(match)
            if index == -1:
                return ""
            start = max(0, index - 60)
            end = min(len(content), index + len(match) + 60)
            return content[start:end].replace('\n', ' ').strip()
        except:
            return ""

    def generate_report(self, output=None):
        """Generate a summary report"""
        if not self.findings:
            print("\n" + "="*60)
            print("🔒 NO SECRETS FOUND")
            print("="*60)
            print("\nThe website appears to be clean!")
            print("\n💡 TIPS:")
            print("   • Try scanning bug bounty sites")
            print("   • Check for source maps (--max-pages 30)")
            print("   • Scan your own test website")
            return
        
        print("\n" + "="*60)
        print("📊 SECRETSPY SCAN RESULTS")
        print("="*60)
        
        # Duration
        duration = (self.end_time - self.start_time).total_seconds()
        print(f"\n⏱️  Scan Duration: {duration:.1f} seconds")
        print(f"📄 Pages Scanned: {len(self.visited)}")
        print(f"🔑 Secrets Found: {len(self.findings)}")
        
        # Group by type
        types = {}
        severities = {'CRITICAL': 0, 'HIGH': 0}
        
        for f in self.findings:
            types[f['type']] = types.get(f['type'], 0) + 1
            if f['severity'] in severities:
                severities[f['severity']] += 1
        
        print(f"\n📋 Summary by Type:")
        for type_name, count in sorted(types.items(), key=lambda x: x[1], reverse=True):
            print(f"   {type_name}: {count}")
        
        print(f"\n🚨 Severity Breakdown:")
        print(f"   CRITICAL: {severities.get('CRITICAL', 0)}")
        print(f"   HIGH: {severities.get('HIGH', 0)}")
        
        # Show top findings
        print(f"\n📝 Top Findings:")
        for i, finding in enumerate(self.findings[:5], 1):
            severity_emoji = '🔴' if finding['severity'] == 'CRITICAL' else '🟡'
            print(f"\n{i}. {severity_emoji} [{finding['severity']}] {finding['type']}")
            print(f"   URL: {finding['url'][:60]}...")
            print(f"   Match: {finding['match']}")
            if finding['context']:
                print(f"   Context: {finding['context'][:80]}...")
        
        if len(self.findings) > 5:
            print(f"\n... and {len(self.findings) - 5} more findings")
        
        # Save report
        report_filename = output or f'secretspy_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_filename, 'w') as f:
            json.dump({
                'scanner': self.name,
                'version': self.version,
                'timestamp': self.start_time.isoformat(),
                'duration': duration,
                'total_findings': len(self.findings),
                'findings': self.findings
            }, f, indent=2)
        
        print(f"\n📁 Full report saved to: {report_filename}")
        print(f"\n{'='*60}")
        print("🕵️  SecretSpy scan complete!")

def main():
    parser = argparse.ArgumentParser(
        description='SecretSpy - Real Website Secret Scanner',
        epilog='Example: python3 secretspy.py https://example.com --max-pages 30'
    )
    parser.add_argument('url', help='Website URL to scan')
    parser.add_argument('--max-pages', type=int, default=15, help='Maximum pages to scan (default: 15)')
    parser.add_argument('--output', help='Output file for JSON report')
    parser.add_argument('--delay', type=float, default=0.3, help='Delay between requests (default: 0.3)')
    
    args = parser.parse_args()
    
    scanner = SecretSpy()
    scanner.scan(args.url, max_pages=args.max_pages, output=args.output)

if __name__ == '__main__':
    main()
