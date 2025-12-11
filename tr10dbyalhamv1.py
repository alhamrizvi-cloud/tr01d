#!/usr/bin/env python3

import re
import sys
import argparse
import requests
import threading
import urllib3
from queue import Queue
from typing import Dict, List, Set, Tuple
from enum import Enum
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecretType(Enum):
    API_KEY = "api_key"
    TOKEN = "token"
    PASSWORD = "password"
    AWS_KEY = "aws_key"
    PRIVATE_KEY = "private_key"
    DATABASE = "database"
    OAUTH = "oauth"
    GENERIC = "generic"
    JWT = "jwt"
    CLOUDFLARE = "cloudflare"
    STRIPE = "stripe"
    SENDGRID = "sendgrid"
    TWILIO = "twilio"
    GITHUB = "github"
    SLACK = "slack"
    MAILGUN = "mailgun"
    HEROKU = "heroku"
    FIREBASE = "firebase"
    GOOGLE = "google"

class SecretPattern:
    def __init__(self, pattern: str, secret_type: SecretType, description: str):
        self.pattern = pattern
        self.secret_type = secret_type
        self.description = description

class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @staticmethod
    def disable():
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.PURPLE = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BOLD = ''
        Colors.RESET = ''

class TR01DScanner:
    def __init__(self, args):
        self.args = args
        self.secrets: Set[str] = set()
        self.lock = threading.Lock()
        self.session = self._create_session()
        
        if args.no_color:
            Colors.disable()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = False
        session.headers.update({'User-Agent': self.args.ua})
        if self.args.cookie:
            session.headers.update({'Cookie': self.args.cookie})
        return session

    @staticmethod
    def get_secret_patterns() -> List[SecretPattern]:
        return [
            # AWS Keys
            SecretPattern(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', 
                         SecretType.AWS_KEY, "AWS Access Key ID"),
            SecretPattern(r'aws(.{0,20})?[\'"][0-9a-zA-Z\/+]{40}[\'"]', 
                         SecretType.AWS_KEY, "AWS Secret Key"),
            SecretPattern(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
                         SecretType.AWS_KEY, "AWS MWS Key"),

            # JWT Tokens
            SecretPattern(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', 
                         SecretType.JWT, "JWT Token"),

            # Private Keys
            SecretPattern(r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----', 
                         SecretType.PRIVATE_KEY, "Private Key Header"),
            SecretPattern(r'-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----', 
                         SecretType.PRIVATE_KEY, "Complete Private Key"),
            SecretPattern(r'-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END RSA PRIVATE KEY-----', 
                         SecretType.PRIVATE_KEY, "RSA Private Key"),

            # GitHub
            SecretPattern(r'github[_-]?token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{40})[\'"]?', 
                         SecretType.GITHUB, "GitHub Token"),
            SecretPattern(r'gh[pou]_[A-Za-z0-9_]{36,}', 
                         SecretType.GITHUB, "GitHub PAT"),
            SecretPattern(r'github[_-]?pat[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{40})[\'"]?', 
                         SecretType.GITHUB, "GitHub PAT"),

            # Google API
            SecretPattern(r'AIza[0-9A-Za-z-_]{35}', 
                         SecretType.GOOGLE, "Google API Key"),
            SecretPattern(r'ya29\.[0-9A-Za-z\-_]+', 
                         SecretType.GOOGLE, "Google OAuth Token"),
            SecretPattern(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 
                         SecretType.GOOGLE, "Google OAuth Client"),

            # Slack
            SecretPattern(r'xox[baprs]-([0-9a-zA-Z]{10,48})', 
                         SecretType.SLACK, "Slack Token"),
            SecretPattern(r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}', 
                         SecretType.SLACK, "Slack Webhook"),

            # Stripe
            SecretPattern(r'sk_live_[0-9a-zA-Z]{24,}', 
                         SecretType.STRIPE, "Stripe Live Secret"),
            SecretPattern(r'rk_live_[0-9a-zA-Z]{24,}', 
                         SecretType.STRIPE, "Stripe Live Restricted"),
            SecretPattern(r'pk_live_[0-9a-zA-Z]{24,}', 
                         SecretType.STRIPE, "Stripe Live Public"),

            # SendGrid
            SecretPattern(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 
                         SecretType.SENDGRID, "SendGrid API Key"),

            # Twilio
            SecretPattern(r'SK[0-9a-fA-F]{32}', 
                         SecretType.TWILIO, "Twilio API Key"),
            SecretPattern(r'AC[a-zA-Z0-9_\-]{32}', 
                         SecretType.TWILIO, "Twilio Account SID"),

            # Cloudflare
            SecretPattern(r'cloudflare[_-]?api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{37})[\'"]?', 
                         SecretType.CLOUDFLARE, "Cloudflare API Key"),

            # Mailgun
            SecretPattern(r'key-[0-9a-zA-Z]{32}', 
                         SecretType.MAILGUN, "Mailgun API Key"),

            # Heroku
            SecretPattern(r'[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', 
                         SecretType.HEROKU, "Heroku API Key"),

            # Firebase
            SecretPattern(r'firebase[_-]?api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{39})[\'"]?', 
                         SecretType.FIREBASE, "Firebase API Key"),

            # Generic API Keys
            SecretPattern(r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,60})[\'"]?', 
                         SecretType.API_KEY, "Generic API Key"),
            SecretPattern(r'apikey[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,60})[\'"]?', 
                         SecretType.API_KEY, "Generic API Key (alt)"),
            SecretPattern(r'api[_-]?secret[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,60})[\'"]?', 
                         SecretType.API_KEY, "API Secret"),

            # Tokens
            SecretPattern(r'access[_-]?token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?', 
                         SecretType.TOKEN, "Access Token"),
            SecretPattern(r'auth[_-]?token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?', 
                         SecretType.TOKEN, "Auth Token"),
            SecretPattern(r'bearer[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?', 
                         SecretType.TOKEN, "Bearer Token"),

            # Passwords
            SecretPattern(r'password[\'"]?\s*[:=]\s*[\'"]?([^\s\'\"]{8,})[\'"]?', 
                         SecretType.PASSWORD, "Password"),
            SecretPattern(r'passwd[\'"]?\s*[:=]\s*[\'"]?([^\s\'\"]{8,})[\'"]?', 
                         SecretType.PASSWORD, "Password (passwd)"),
            SecretPattern(r'pwd[\'"]?\s*[:=]\s*[\'"]?([^\s\'\"]{8,})[\'"]?', 
                         SecretType.PASSWORD, "Password (pwd)"),

            # Database Connection Strings
            SecretPattern(r'mongodb(\+srv)?:\/\/[^\s\'\"]+', 
                         SecretType.DATABASE, "MongoDB Connection String"),
            SecretPattern(r'mysql:\/\/[^\s\'\"]+', 
                         SecretType.DATABASE, "MySQL Connection String"),
            SecretPattern(r'postgres(ql)?:\/\/[^\s\'\"]+', 
                         SecretType.DATABASE, "PostgreSQL Connection String"),
            SecretPattern(r'redis:\/\/[^\s\'\"]+', 
                         SecretType.DATABASE, "Redis Connection String"),

            # OAuth
            SecretPattern(r'client[_-]?secret[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?', 
                         SecretType.OAUTH, "OAuth Client Secret"),
            SecretPattern(r'refresh[_-]?token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?', 
                         SecretType.OAUTH, "Refresh Token"),

            # Additional patterns
            SecretPattern(r'[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}[\'\"\\s][0-9a-f]{32}[\'\"\\s]', 
                         SecretType.GENERIC, "Facebook Token"),
            SecretPattern(r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}[\'\"\\s][0-9a-zA-Z]{35,44}[\'\"\\s]', 
                         SecretType.GENERIC, "Twitter Token"),
            SecretPattern(r'EAACEdEose0cBA[0-9A-Za-z]+', 
                         SecretType.GENERIC, "Facebook Access Token"),
            SecretPattern(r'6L[0-9A-Za-z-_]{38}', 
                         SecretType.GOOGLE, "Google reCAPTCHA Key"),
            SecretPattern(r'Basic [A-Za-z0-9+/]{15,}', 
                         SecretType.GENERIC, "Basic Auth"),
        ]

    def analyze_js_variables(self, body: str) -> List[str]:
        """Analyze JavaScript variables for sensitive data"""
        findings = []
        
        sensitive_patterns = [
            r'(var|let|const)\s+(\w*[Kk]ey\w*)\s*=\s*[\'"]([^\'"]{10,})[\'"]',
            r'(var|let|const)\s+(\w*[Tt]oken\w*)\s*=\s*[\'"]([^\'"]{10,})[\'"]',
            r'(var|let|const)\s+(\w*[Ss]ecret\w*)\s*=\s*[\'"]([^\'"]{10,})[\'"]',
            r'(var|let|const)\s+(\w*[Pp]assword\w*)\s*=\s*[\'"]([^\'"]{8,})[\'"]',
            r'(var|let|const)\s+(\w*[Aa]pi\w*)\s*=\s*[\'"]([^\'"]{10,})[\'"]',
        ]
        
        for pattern in sensitive_patterns:
            matches = re.findall(pattern, body)
            for match in matches:
                if len(match) > 2:
                    findings.append(f"Variable: {match[1]} = {match[2]}")
        
        return findings

    def analyze_js_comments(self, body: str) -> List[str]:
        """Analyze JavaScript comments for sensitive information"""
        findings = []
        
        comment_patterns = [
            r'//.*(?i)(password|key|token|secret).*[:=].*',
            r'/\*[\s\S]*?(?i)(password|key|token|secret)[\s\S]*?\*/',
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, body)
            findings.extend(matches)
        
        return findings

    def matches_filter(self, secret_type: SecretType) -> bool:
        """Check if secret type matches filter"""
        if not self.args.only:
            return True
        return secret_type.value.lower() == self.args.only.lower()

    def is_excluded(self, secret_type: SecretType) -> bool:
        """Check if secret type is excluded"""
        if not self.args.exclude:
            return False
        exclude_list = [x.strip().lower() for x in self.args.exclude.split(',')]
        return secret_type.value.lower() in exclude_list

    def get_type_color(self, secret_type: SecretType) -> str:
        """Get color based on secret type severity"""
        if secret_type in [SecretType.PRIVATE_KEY, SecretType.AWS_KEY]:
            return Colors.RED
        elif secret_type in [SecretType.PASSWORD, SecretType.DATABASE]:
            return Colors.YELLOW
        else:
            return Colors.GREEN

    def process_url(self, url: str):
        """Process a single URL"""
        if 'http' not in url:
            if self.args.verbose:
                print(f"{Colors.RED}[-]{Colors.RESET} URL must contain 'http': {url}")
            return

        try:
            patterns = self.get_secret_patterns()
            
            # Add custom pattern if specified
            if self.args.extra_pattern:
                patterns.append(SecretPattern(self.args.extra_pattern, SecretType.GENERIC, "Custom Pattern"))

            if self.args.detailed:
                print(f"{Colors.YELLOW}[*]{Colors.RESET} Processing URL: {url}")

            response = self.session.get(
                url,
                timeout=self.args.timeout,
                allow_redirects=self.args.follow
            )
            
            body = response.text

            # Analyze JS-specific patterns if verbose
            if self.args.verbose:
                js_vars = self.analyze_js_variables(body)
                if js_vars:
                    print(f"{Colors.CYAN}[*]{Colors.RESET} JS Variables found in {url}")
                    for var in js_vars:
                        print(f"{Colors.CYAN}    =>{Colors.RESET} {var}")

                comments = self.analyze_js_comments(body)
                if comments:
                    print(f"{Colors.CYAN}[*]{Colors.RESET} Sensitive comments in {url}")
                    for comment in comments:
                        print(f"{Colors.CYAN}    =>{Colors.RESET} {comment.strip()}")

            # Scan for secrets
            for pattern in patterns:
                if self.is_excluded(pattern.secret_type):
                    continue
                if not self.matches_filter(pattern.secret_type):
                    continue

                matches = re.findall(pattern.pattern, body)
                for match in matches:
                    secret = match if isinstance(match, str) else match[0] if match else ""
                    
                    if not secret:
                        continue

                    with self.lock:
                        if secret in self.secrets:
                            continue
                        self.secrets.add(secret)

                    type_color = self.get_type_color(pattern.secret_type)

                    if self.args.detailed:
                        lines = body.split('\n')
                        for i, line in enumerate(lines, 1):
                            if secret in line:
                                print(f"{type_color}[+]{Colors.RESET} {url} "
                                      f"{type_color}[{pattern.description}]{Colors.RESET} "
                                      f"{Colors.WHITE}{secret}{Colors.RESET} "
                                      f"{Colors.CYAN}[Line: {i}]{Colors.RESET}")
                    else:
                        print(f"{type_color}[+]{Colors.RESET} {url} "
                              f"{type_color}[{pattern.secret_type.value}]{Colors.RESET} "
                              f"{Colors.WHITE}{secret}{Colors.RESET}")

                    # Write to output file if specified
                    if self.args.output:
                        with self.lock:
                            with open(self.args.output, 'a') as f:
                                f.write(f"{url} | {pattern.secret_type.value} | {secret}\n")

        except requests.exceptions.Timeout:
            if self.args.verbose:
                print(f"{Colors.RED}[-]{Colors.RESET} Timeout: {url}")
        except requests.exceptions.RequestException as e:
            if self.args.verbose:
                print(f"{Colors.RED}[-]{Colors.RESET} Request failed: {url} - {str(e)}")
        except Exception as e:
            if self.args.verbose:
                print(f"{Colors.RED}[-]{Colors.RESET} Error processing {url}: {str(e)}")

    def worker(self, queue: Queue):
        """Worker thread function"""
        while True:
            url = queue.get()
            if url is None:
                break
            self.process_url(url)
            queue.task_done()

    def scan(self, urls: List[str]):
        """Main scanning function"""
        queue = Queue()
        threads = []

        # Start worker threads
        for _ in range(self.args.threads):
            t = threading.Thread(target=self.worker, args=(queue,))
            t.start()
            threads.append(t)

        # Add URLs to queue
        for url in urls:
            url = url.strip()
            if url:
                queue.put(url)

        # Wait for all tasks to complete
        queue.join()

        # Stop workers
        for _ in range(self.args.threads):
            queue.put(None)
        for t in threads:
            t.join()

def banner():
    """Display banner"""
    print(f"""{Colors.RED}
  ______     ____ ___    __
 /_  __/____/ __ <  /___/ /
  / / / ___/ / / / / __  / 
 / / / /  / /_/ / / /_/ /  
/_/ /_/   \____/_/\__,_/   
                           
    {Colors.RESET}""")
    print(f"{Colors.CYAN}        by @alhamrizvi btw :3 {Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='tr01d - Advanced JavaScript Secret Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cat urls.txt | python3 tr01d.py
  cat urls.txt | python3 tr01d.py --only api_key
  cat urls.txt | python3 tr01d.py --exclude password,generic
  cat urls.txt | python3 tr01d.py -v -d -o results.txt
  cat urls.txt | python3 tr01d.py -t 100 --timeout 15
        """
    )

    parser.add_argument('-s', '--silent', action='store_true', 
                       help='Silent mode (no banner)')
    parser.add_argument('-t', '--threads', type=int, default=50, 
                       help='Number of concurrent threads (default: 50)')
    parser.add_argument('--ua', default='tr01d/3.0 (Security Scanner)', 
                       help='User-Agent string')
    parser.add_argument('-d', '--detailed', action='store_true', 
                       help='Detailed output with line numbers')
    parser.add_argument('-c', '--cookie', default='', 
                       help='Cookie header value')
    parser.add_argument('--ep', '--extra-pattern', dest='extra_pattern', 
                       help='Extra custom regex pattern')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='HTTP request timeout in seconds (default: 10)')
    parser.add_argument('--only', help='Filter by secret type (e.g., api_key, token, aws_key)')
    parser.add_argument('--exclude', help='Exclude secret types (comma-separated)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output (show JS analysis)')
    parser.add_argument('-o', '--output', help='Output file for findings')
    parser.add_argument('--no-color', action='store_true', 
                       help='Disable colored output')
    parser.add_argument('--follow', action='store_true', 
                       help='Follow redirects')

    args = parser.parse_args()

    if not args.silent:
        banner()

    # Read URLs from stdin
    urls = []
    for line in sys.stdin:
        line = line.strip()
        if line:
            urls.append(line)

    if not urls:
        print(f"{Colors.RED}[-]{Colors.RESET} No URLs provided. Pipe URLs via stdin.")
        print(f"{Colors.YELLOW}Example:{Colors.RESET} cat urls.txt | python3 tr01d.py")
        sys.exit(1)

    # Create scanner and run
    scanner = TR01DScanner(args)
    scanner.scan(urls)

    if not args.silent:
        print(f"\n{Colors.GREEN}[✓] Scan complete!{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Total unique secrets found: {len(scanner.secrets)}{Colors.RESET}")

if __name__ == '__main__':
    main()
