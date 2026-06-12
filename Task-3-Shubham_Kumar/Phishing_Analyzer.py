#!/usr/bin/env python3
"""
Phishing Analyzer - Email & URL Investigation Tool
Author: Shubham Kumar
Use: Authorized penetration testing & security awareness

"""

import re
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, field

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    dns = None
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    requests = None
    HAS_REQUESTS = False


# ====================================================================
# SECTION 1: PURE-PYTHON WHOIS CLIENT (no system binary required)
# ====================================================================

# WHOIS servers for common TLDs
TLD_WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'biz': 'whois.neulevel.biz',
    'name': 'whois.nic.name',
    'mobi': 'whois.afilias.net',
    'pro': 'whois.registrypro.pro',
    'asia': 'whois.nic.asia',
    'tel': 'whois.nic.tel',
    'travel': 'whois.nic.travel',
    'jobs': 'whois.nic.jobs',
    'gov': 'whois.dotgov.gov',
    'edu': 'whois.educause.edu',
    'mil': 'whois.nic.mil',
    'int': 'whois.iana.org',
    'aero': 'whois.information.aero',
    'cat': 'whois.nic.cat',
    'coop': 'whois.nic.coop',
    'museum': 'whois.museum',
    'uk': 'whois.nic.uk',
    'eu': 'whois.eu',
    'de': 'whois.denic.de',
    'jp': 'whois.jprs.jp',
    'cn': 'whois.cnnic.cn',
    'fr': 'whois.nic.fr',
    'au': 'whois.auda.org.au',
    'ru': 'whois.tcinet.ru',
    'br': 'whois.registro.br',
    'it': 'whois.nic.it',
    'nl': 'whois.domain-registry.nl',
    'pl': 'whois.dns.pl',
    'es': 'whois.nic.es',
    'se': 'whois.iis.se',
    'ch': 'whois.nic.ch',
    'at': 'whois.nic.at',
    'dk': 'whois.punktum.dk',
    'no': 'whois.norid.no',
    'fi': 'whois.fi',
    'be': 'whois.dns.be',
    'ie': 'whois.weare.ie',
    'nz': 'whois.srs.net.nz',
    'za': 'whois.registry.net.za',
    'in': 'whois.registry.in',
    'mx': 'whois.mx',
    'sg': 'whois.sgnic.sg',
    'hk': 'whois.hkirc.hk',
    'tw': 'whois.twnic.net',
    'kr': 'whois.kr',
    'ar': 'whois.nic.ar',
    'pt': 'whois.dns.pt',
    'gr': 'whois.gr',
    'cz': 'whois.nic.cz',
    'hu': 'whois.nic.hu',
    'ro': 'whois.rotld.ro',
    'sk': 'whois.sk-nic.sk',
    'bg': 'whois.register.bg',
    'rs': 'whois.rnids.rs',
    'hr': 'whois.dns.hr',
    'si': 'whois.register.si',
    'lt': 'whois.domreg.lt',
    'lv': 'whois.nic.lv',
    'ee': 'whois.eenet.ee',
    'is': 'whois.isnic.is',
    'lu': 'whois.restena.lu',
    'mt': 'whois.nic.org.mt',
    'li': 'whois.nic.li',
    'me': 'whois.nic.me',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'cc': 'whois.nic.cc',
    'tv': 'whois.nic.tv',
    'ws': 'whois.nic.ws',
    'bz': 'whois.belizenic.bz',
    'nu': 'whois.iis.nu',
    'xxx': 'whois.nic.xxx',
    'club': 'whois.nic.club',
    'xyz': 'whois.nic.xyz',
    'top': 'whois.nic.top',
    'loan': 'whois.nic.loan',
    'work': 'whois.nic.work',
    'date': 'whois.nic.date',
    'men': 'whois.nic.men',
    'download': 'whois.nic.download',
    'stream': 'whois.nic.stream',
    'trade': 'whois.nic.trade',
    'review': 'whois.nic.review',
    'win': 'whois.nic.win',
    'bid': 'whois.nic.bid',
    'racing': 'whois.nic.racing',
    'science': 'whois.nic.science',
    'site': 'whois.nic.site',
    'online': 'whois.nic.online',
    'live': 'whois.nic.live',
    'click': 'whois.nic.click',
    'link': 'whois.nic.link',
    'kim': 'whois.nic.kim',
    'gq': 'whois.dominio.gq',
    'ga': 'whois.dominio.ga',
    'ml': 'whois.dominio.ml',
    'cf': 'whois.dominio.cf',
    'tk': 'whois.dot.tk',
}

WHOIS_TIMEOUT = 15


def _get_tld(domain: str) -> str:
    """Extract the TLD from a domain name."""
    if '.' not in domain:
        return ''
    return domain.rsplit('.', 1)[-1].lower()


def _query_whois_server_raw(server: str, query: str) -> str:
    """
    Connect to a WHOIS server on TCP port 43, send a query,
    and return the raw text response.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(WHOIS_TIMEOUT)
    try:
        sock.connect((server, 43))
        sock.send(f"{query}\r\n".encode('utf-8', errors='ignore'))
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        return response.decode('utf-8', errors='replace')
    except socket.timeout:
        return ""
    except socket.gaierror:
        return ""
    except ConnectionRefusedError:
        return ""
    except OSError:
        return ""
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _extract_referral_server(raw: str) -> Optional[str]:
    """
    Check if the WHOIS response contains a referral to another WHOIS server.
    Verisign and many TLD registries use:
        'Whois Server: whois.markmonitor.com'
    or
        'Registrar WHOIS Server: whois.xxx'
    """
    patterns = [
        r'Whois\s*Server:\s*(\S+)',
        r'Registrar\s+WHOIS\s+Server:\s*(\S+)',
        r'whois\s*server:\s*(\S+)',
        r'Referral\s+Server:\s*(\S+)',
    ]
    for pattern in patterns:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if match:
            server = match.group(1).strip().lower()
            if server and '.' in server and 'whois.' in server:
                return server
    return None


def _whois_follow_referrals(domain: str, max_depth: int = 3) -> Dict[str, str]:
    """
    Perform a WHOIS lookup following referral/redirect chain.
    Returns dict with 'tld_response' and 'registrar_response' keys.
    """
    tld = _get_tld(domain)
    tld_server = TLD_WHOIS_SERVERS.get(tld, 'whois.iana.org')

    result = {
        'tld_server': tld_server,
        'tld_response': '',
        'registrar_server': '',
        'registrar_response': '',
        'combined': '',
        'error': '',
    }

    # Step 1: Query the TLD registry WHOIS server
    tld_response = _query_whois_server_raw(tld_server, domain)
    if not tld_response:
        result['error'] = f"No response from TLD WHOIS server ({tld_server})"
        return result

    result['tld_response'] = tld_response
    result['combined'] = tld_response

    # Step 2: Check for referral to registrar's WHOIS server
    registrar_server = _extract_referral_server(tld_response)
    if registrar_server and registrar_server != tld_server:
        result['registrar_server'] = registrar_server
        reg_response = _query_whois_server_raw(registrar_server, domain)
        if reg_response:
            result['registrar_response'] = reg_response
            result['combined'] += "\n\n" + reg_response

    return result


def _parse_whois_dates(raw: str) -> Dict[str, Any]:
    """
    Extract creation, expiration, and update dates from WHOIS text.
    Returns dict with 'creation_date' (datetime or None), etc.
    """
    result: Dict[str, Any] = {
        'creation_date': None,
        'creation_date_raw': None,
        'expiration_date': None,
        'updated_date': None,
    }

    # All the common WHOIS date patterns
    creation_patterns = [
        r'Creation\s*Date:\s*(.+)',
        r'created:\s*(.+)',
        r'Creation\s*date:\s*(.+)',
        r'Created\s*On:\s*(.+)',
        r'Domain\s*Creation\s*Date:\s*(.+)',
        r'created_date:\s*(.+)',
        r'Created:\s*(.+)',
        r'Registration\s*Date:\s*(.+)',
        r'registered:\s*(.+)',
    ]

    expiration_patterns = [
        r'Registry\s+Expiry\s+Date:\s*(.+)',
        r'Expir\w+\s+Date:\s*(.+)',
        r'expir\w+:\s*(.+)',
        r'Expir\w+\s+On:\s*(.+)',
        r'Expir\w+\s+date:\s*(.+)',
        r'Registrar\s+Registration\s+Expir\w+\s+Date:\s*(.+)',
        r'Expiry:\s*(.+)',
        r'expire:\s*(.+)',
    ]

    updated_patterns = [
        r'Updated\s*Date:\s*(.+)',
        r'updated:\s*(.+)',
        r'Last\s*Updated\s*On:\s*(.+)',
        r'Last\s*Update:\s*(.+)',
        r'Modified:\s*(.+)',
        r'Last\s*modified:\s*(.+)',
    ]

    # Parse creation date
    for pattern in creation_patterns:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if match:
            raw_date = match.group(1).strip()
            result['creation_date_raw'] = raw_date
            parsed = _parse_date_string(raw_date)
            if parsed:
                result['creation_date'] = parsed
            break

    # Parse expiration date
    for pattern in expiration_patterns:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if match:
            raw_date = match.group(1).strip()
            parsed = _parse_date_string(raw_date)
            if parsed:
                result['expiration_date'] = parsed
            break

    # Parse updated date
    for pattern in updated_patterns:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if match:
            raw_date = match.group(1).strip()
            parsed = _parse_date_string(raw_date)
            if parsed:
                result['updated_date'] = parsed
            break

    return result


def _parse_date_string(date_str: str) -> Optional[datetime]:
    """
    Parse a date string from WHOIS data using multiple common formats.
    """
    if not date_str:
        return None

    # Clean up the string
    date_str = date_str.strip()

    # Remove timezone abbreviations like UTC, GMT, EST, etc.
    date_str_clean = re.sub(
        r'\s+(UTC|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT|BST|CEST|EEST|[A-Z]{2,5})$',
        '', date_str
    )

    # Normalize whitespace
    date_str_clean = re.sub(r'\s+', ' ', date_str_clean)

    # Try common date formats in order of likelihood
    formats = [
        # ISO 8601 formats
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        # Common WHOIS formats
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
        # Text formats
        "%d %b %Y %H:%M:%S",
        "%d %b %Y",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y",
        "%d-%m-%Y %H:%M:%S",
        "%d-%m-%Y",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
        # Full text
        "%B %d %Y",
        "%d %B %Y",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Z %Y",
        # Before 2000
        "%Y-%m-%d %H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(date_str_clean, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Try parsing ISO format with flexible timezone handling
    try:
        # Handle trailing Z
        if date_str_clean.endswith('Z'):
            date_str_clean = date_str_clean[:-1]
            return datetime.strptime(date_str_clean, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Try with timezone offset like +00:00
    try:
        if '+' in date_str_clean and 'T' in date_str_clean:
            # Split off the timezone part
            main_part = re.sub(r'[+-]\d{2}:\d{2}$', '', date_str_clean)
            return datetime.strptime(main_part, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    return None


def _extract_field(raw: str, field_name: str, patterns: List[str]) -> Optional[str]:
    """Extract the first matching field value from WHOIS text."""
    for pattern in patterns:
        match = re.search(pattern, raw, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(1).strip()
            if value:
                return value
    return None


def whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Full WHOIS lookup with referral following.
    Returns structured data with creation date, registrar, etc.
    """
    result: Dict[str, Any] = {
        "domain": domain,
        "creation_date": None,
        "creation_date_raw": None,
        "registrar": None,
        "name_servers": [],
        "status": [],
        "registrant_org": None,
        "registrant_country": None,
        "error": "",
        "servers_queried": [],
    }

    whois_data = _whois_follow_referrals(domain)

    if whois_data.get('error'):
        result['error'] = whois_data['error']
        return result

    combined = whois_data.get('combined', '')
    if not combined:
        result['error'] = "Empty WHOIS response"
        return result

    result['servers_queried'] = [
        whois_data.get('tld_server', ''),
        whois_data.get('registrar_server', ''),
    ]

    # --- Extract dates from combined response ---
    dates = _parse_whois_dates(combined)
    result['creation_date'] = dates.get('creation_date')
    result['creation_date_raw'] = dates.get('creation_date_raw')

    # --- Extract registrar ---
    registrar = _extract_field(combined, 'registrar', [
        r'Registrar:\s*(.+)',
        r'registrar:\s*(.+)',
        r'Sponsoring Registrar:\s*(.+)',
        r'Registrar\s+Name:\s*(.+)',
    ])
    if registrar:
        # Clean up: remove IANA ID if present
        registrar = re.sub(r'\s+\d+$', '', registrar)
        result['registrar'] = registrar

    # --- Extract name servers ---
    ns_matches = re.findall(
        r'Name\s*Server:\s*(\S+)',
        combined, re.IGNORECASE | re.MULTILINE
    )
    if ns_matches:
        result['name_servers'] = [ns.strip().lower() for ns in ns_matches if ns.strip()]

    # --- Extract domain status ---
    status_matches = re.findall(
        r'(?:Domain\s+)?Status:\s*(.+)',
        combined, re.IGNORECASE | re.MULTILINE
    )
    if status_matches:
        result['status'] = [s.strip() for s in status_matches if s.strip()]

    # --- Extract registrant info ---
    org = _extract_field(combined, 'registrant_org', [
        r'Registrant\s+Organization:\s*(.+)',
        r'org:\s*(.+)',
        r'organisation:\s*(.+)',
    ])
    if org:
        result['registrant_org'] = org

    country = _extract_field(combined, 'registrant_country', [
        r'Registrant\s+Country:\s*(.+)',
        r'country:\s*(.+)',
    ])
    if country:
        result['registrant_country'] = country

    return result


# ====================================================================
# SECTION 2: DATA STRUCTURES
# ====================================================================

@dataclass
class AnalysisResult:
    """Stores the full analysis output for a single input."""
    input_type: str
    input_raw: str
    domain: str = ""
    suspicious_score: int = 0
    verdict: str = "safe"
    red_flags: List[str] = field(default_factory=list)
    safe_indicators: List[str] = field(default_factory=list)
    tech_details: Dict[str, Any] = field(default_factory=dict)
    lookalike_analysis: Dict[str, Any] = field(default_factory=dict)
    headers_analysis: Dict[str, Any] = field(default_factory=dict)

    def add_red_flag(self, severity: int, msg: str) -> None:
        self.red_flags.append(f"[+{severity}] {msg}")
        self.suspicious_score = min(100, self.suspicious_score + severity)
        self._update_verdict()

    def add_safe_indicator(self, msg: str) -> None:
        self.safe_indicators.append(f"[+] {msg}")

    def _update_verdict(self) -> None:
        if self.suspicious_score >= 70:
            self.verdict = "CRITICAL - PHISHING"
        elif self.suspicious_score >= 40:
            self.verdict = "SUSPICIOUS"
        elif self.suspicious_score >= 15:
            self.verdict = "CAUTION"
        else:
            self.verdict = "SAFE"

    def report(self) -> str:
        lines = [
            "=" * 65,
            f"  PHISHING ANALYSIS REPORT",
            f"  Analyzed: {self.input_raw[:80]}",
            "=" * 65,
            f"  Type:              {self.input_type.upper()}",
            f"  Domain:            {self.domain}",
            f"  Suspicion Score:   {self.suspicious_score}/100",
            f"  Verdict:           {self.verdict}",
            "-" * 65,
        ]
        if self.red_flags:
            lines.append("\n  RED FLAGS:")
            for flag in self.red_flags:
                lines.append(f"     {flag}")
        if self.safe_indicators:
            lines.append("\n  SAFE INDICATORS:")
            for ind in self.safe_indicators:
                lines.append(f"     {ind}")
        if self.tech_details:
            lines.append("\n  TECHNICAL DETAILS:")
            for k, v in self.tech_details.items():
                lines.append(f"     {k}: {v}")
        if self.lookalike_analysis:
            lines.append("\n  LOOKALIKE ANALYSIS:")
            for k, v in self.lookalike_analysis.items():
                lines.append(f"     {k}: {v}")
        lines.append("=" * 65)
        return "\n".join(lines)


# ====================================================================
# SECTION 3: DETECTION DATABASES
# ====================================================================

SUSPICIOUS_TLDS: Set[str] = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.top', '.loan', '.work', '.date', '.men', '.download',
    '.stream', '.trade', '.review', '.win', '.bid', '.racing',
    '.science', '.xyz', '.club', '.online', '.site', '.live',
    '.click', '.link', '.download', '.country', '.kim',
}

LOOKALIKE_TARGETS: Dict[str, List[str]] = {
    'google': ['g00gle', 'go0gle', 'goog1e', 'googie', 'gooqle', 'gooogle'],
    'paypal': ['paypa1', 'paypai', 'paypal'],
    'facebook': ['faceb00k', 'facebo0k'],
    'microsoft': ['micr0s0ft', 'mlcrosoft'],
    'amazon': ['arnazon', 'amaz0n'],
    'linkedin': ['1inkedin', 'linked1n', 'Iinkedin'],
    'netflix': ['netf1ix', 'netfl1x', 'netflx'],
    'apple': ['app1e'],
    'instagram': ['1nstagram'],
    'twitter': ['tw1tter', 'twltter'],
}

CYRILLIC_HOMOGLYPHS: Dict[str, str] = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i',
    'в': 'b', 'н': 'h', 'к': 'k', 'м': 'm', 'т': 't',
}

SUSPICIOUS_KEYWORDS: List[str] = [
    'verify', 'confirm', 'update', 'suspend', 'restrict',
    'unusual', 'security', 'alert', 'urgent', 'login',
    'signin', 'account', 'billing', 'payment', 'invoice',
    'reset', 'password', 'credential', 'secure', 'authenticate',
    'validate', 'reactivate', 'deactivate', 'limited',
    'blocked', 'locked', 'compromised', 'recover',
]

URGENCY_PHRASES: List[str] = [
    'immediately', 'urgent', 'act now', 'limited time', 'expires',
    'suspended', 'blocked', 'locked', 'compromised', 'unauthorized',
    'security alert', 'unusual activity', 'verify now', 'confirm now',
    'click here', 'within 24 hours', 'failure to respond', 'final warning',
    'immediate action required', 'account suspended', 'unusual sign-in',
    'unauthorized access', 'security breach', 'your account will be',
]

SENSITIVE_REQUEST_PHRASES: List[str] = [
    'password', 'credit card', 'ssn', 'social security', 'bank account',
    'routing number', 'login credentials', 'verify your account',
    'update your information', 'confirm your identity',
    'verify your identity', 'click here to verify',
    'confirm your account', 'enter your password',
]

GENERIC_GREETINGS: List[str] = [
    'dear customer', 'dear user', 'dear member', 'dear account holder',
    'dear valued customer', 'dear client',
]

URL_SHORTENERS: List[str] = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'shorturl.at', 'tiny.cc', 'tr.im',
    'rb.gy', 'cutt.ly', 'shorte.st', 'adf.ly', 'bl.ink',
    'short.link', 'v.gd', 'cli.gs', 'urlz.fr',
]


# ====================================================================
# SECTION 4: URL & DOMAIN PARSING
# ====================================================================

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'https://' + url
    return url


def extract_domain(text: str) -> str:
    text = text.strip().lower()
    email_match = re.match(r'^[^@]+@([^@]+)$', text)
    if email_match:
        return email_match.group(1)
    parsed = urllib.parse.urlparse(normalize_url(text))
    domain = parsed.netloc or parsed.path
    domain = domain.split(':')[0]
    domain = re.sub(r'^www\d*\.', '', domain)
    return domain


def looks_like_ip(text: str) -> bool:
    pattern = (
        r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    )
    return bool(re.match(pattern, text))


def get_embedded_domains(url: str) -> List[str]:
    parsed = urllib.parse.urlparse(normalize_url(url))
    domains = [parsed.netloc]
    params = urllib.parse.parse_qs(parsed.query)
    for values in params.values():
        for val in values:
            if val.startswith(('http://', 'https://', 'www.')):
                try:
                    p = urllib.parse.urlparse(val)
                    if p.netloc:
                        domains.append(p.netloc)
                except Exception:
                    pass
    return list(set(domains))


# ====================================================================
# SECTION 5: CHECK FUNCTIONS
# ====================================================================

def check_suspicious_tld(domain: str) -> Optional[str]:
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return tld
    return None


def check_domain_age(domain: str) -> Dict[str, Any]:
    """Check domain age via pure-Python WHOIS with referral following."""
    result: Dict[str, Any] = {
        "age_days": None,
        "created": None,
        "registrar": None,
        "note": "",
    }

    whois_result = whois_lookup(domain)

    if whois_result.get('error'):
        result['note'] = whois_result['error']
        result['whois_error'] = True
        return result

    creation_date = whois_result.get('creation_date')
    registrar = whois_result.get('registrar')

    if creation_date and isinstance(creation_date, datetime):
        result['created'] = creation_date.isoformat()
        age = (datetime.now(timezone.utc) - creation_date).days
        result['age_days'] = max(0, age)

        if age < 30:
            result['note'] = f"Very new domain ({age} days old) - high risk"
        elif age < 180:
            result['note'] = f"Recently registered ({age} days ago)"
        elif age < 365:
            result['note'] = f"Less than 1 year old ({age} days)"
        else:
            result['note'] = f"Established domain ({age} days old)"
    else:
        raw_date = whois_result.get('creation_date_raw')
        if raw_date:
            result['note'] = f"Raw creation date found but could not parse: '{raw_date}'"
        else:
            result['note'] = "No creation date found in WHOIS response"

    if registrar:
        result['registrar'] = registrar

    # Add some transparency about servers queried
    servers = whois_result.get('servers_queried', [])
    if servers and servers[0]:
        result['whois_server'] = servers[0]
        if servers[1]:
            result['registrar_whois_server'] = servers[1]

    return result


def check_dns_records(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "has_mx": False,
        "has_spf": False,
        "mx_records": [],
        "spf_record": "",
        "note": "",
    }
    if not HAS_DNS:
        result["note"] = "dnspython not available. Install with: pip install dnspython"
        return result
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        result["has_mx"] = True
        result["mx_records"] = [str(r.exchange) for r in mx]
    except dns.resolver.NoAnswer:
        result["note"] = "No MX records found"
    except dns.resolver.NXDOMAIN:
        result["note"] = "Domain does not exist (NXDOMAIN)"
    except Exception as e:
        result["note"] = f"DNS error: {str(e)[:60]}"
    try:
        txt = dns.resolver.resolve(domain, 'TXT')
        for record in txt:
            txt_str = str(record)
            if 'v=spf1' in txt_str:
                result["has_spf"] = True
                result["spf_record"] = txt_str[:120]
                break
    except Exception:
        pass
    return result


def check_ip_reputation(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ips": [],
        "is_cloudflare": False,
        "note": "",
    }
    if looks_like_ip(domain):
        result["ips"].append(domain)
        result["note"] = "Input is an IP address, not a domain name"
        return result
    try:
        addr_info = socket.getaddrinfo(domain, 80)
        result["ips"] = list(set(ip[4][0] for ip in addr_info))
        cf_ranges = [
            '104.16.', '104.17.', '104.18.', '104.19.',
            '172.64.', '172.65.', '172.66.', '172.67.',
            '173.245.', '103.21.', '103.22.', '103.31.',
            '141.101.', '108.162.', '190.93.', '188.114.',
            '197.234.', '198.41.', '162.158.', '131.0.',
        ]
        for ip in result["ips"]:
            for cf in cf_ranges:
                if ip.startswith(cf):
                    result["is_cloudflare"] = True
                    break
    except socket.gaierror:
        result["note"] = "Domain does not resolve (DNS resolution failed)"
    except Exception as e:
        result["note"] = f"IP error: {str(e)[:60]}"
    return result


def check_lookalike(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "impersonates": [],
        "methods": [],
    }
    domain_lower = domain.lower()
    parts = domain_lower.split('.')
    main_part = parts[-2] if len(parts) >= 2 else parts[0]
    for brand, lookalikes in LOOKALIKE_TARGETS.items():
        if main_part == brand:
            continue
        if main_part in lookalikes:
            result["impersonates"].append(brand)
            result["methods"].append(
                f"exact lookalike: '{main_part}' impersonates '{brand}'"
            )
            continue
        for part in parts:
            if part in lookalikes and part != brand:
                if brand not in result["impersonates"]:
                    result["impersonates"].append(brand)
                    result["methods"].append(
                        f"lookalike in subdomain: '{part}' impersonates '{brand}'"
                    )
        if brand in main_part and main_part != brand:
            idx = main_part.index(brand)
            prefix = main_part[:idx]
            suffix = main_part[idx + len(brand):]
            if prefix and not prefix.isalpha():
                if brand not in result["impersonates"]:
                    result["impersonates"].append(brand)
                    result["methods"].append(
                        f"brand '{brand}' with suspicious prefix '{prefix}'"
                    )
            if suffix and not suffix.isalpha():
                if brand not in result["impersonates"]:
                    result["impersonates"].append(brand)
                    result["methods"].append(
                        f"brand '{brand}' with suspicious suffix '{suffix}'"
                    )
    for brand in LOOKALIKE_TARGETS:
        if brand in parts:
            idx = parts.index(brand)
            if idx < len(parts) - 2 and brand not in result["impersonates"]:
                result["impersonates"].append(brand)
                result["methods"].append(
                    f"brand '{brand}' as subdomain of another domain"
                )
    detected = []
    for char in domain_lower:
        if char in CYRILLIC_HOMOGLYPHS:
            detected.append(char)
    if detected:
        result["has_homoglyphs"] = True
        result["homoglyph_chars"] = list(set(detected))
        result["decoded"] = domain_lower.translate(
            str.maketrans(CYRILLIC_HOMOGLYPHS)
        )
    return result


def check_url_structure(url: str) -> List[str]:
    flags = []
    parsed = urllib.parse.urlparse(normalize_url(url))
    domain = parsed.netloc
    if '@' in domain:
        flags.append("URL contains credentials in '@' syntax - likely phishing redirect")
    if looks_like_ip(domain):
        flags.append("URL uses raw IP address instead of domain name")
    if domain.count('.') >= 4:
        flags.append(f"Excessive subdomains ({domain.count('.')} levels)")
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in (parsed.path + parsed.query).lower():
            flags.append(f"Suspicious keyword in URL: '{kw}'")
    for short in URL_SHORTENERS:
        if short in domain.lower():
            flags.append(f"URL shortener: {short} - destination is hidden")
            break
    if '%25' in url.lower():
        flags.append("Double URL encoding detected (evasion technique)")
    if '://' in url and not url.startswith('https://'):
        flags.append("Non-HTTPS URL - no transport encryption")
    if len(url) > 500:
        flags.append(f"Unusually long URL ({len(url)} chars)")
    if ':' in domain and not domain.endswith(']'):
        port = domain.split(':')[-1]
        if port.isdigit() and int(port) not in {80, 443, 8080, 8443}:
            flags.append(f"Non-standard port ({port})")
    return flags


def check_ssl_cert(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "valid": False,
        "issuer": "",
        "subject": "",
        "expiry": "",
        "san": [],
        "errors": [],
    }
    if looks_like_ip(domain):
        result["errors"].append("IP address - no SSL cert expected")
        return result
    if ':' in domain:
        domain = domain.split(':')[0]
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["valid"] = True
                    if 'issuer' in cert and cert['issuer']:
                        issuer_dict = {}
                        for rdn in cert['issuer']:
                            for key, value in rdn:
                                issuer_dict[key] = value
                        result["issuer"] = issuer_dict.get(
                            'organizationName',
                            issuer_dict.get('commonName', 'Unknown')
                        )
                    if 'subject' in cert and cert['subject']:
                        subject_dict = {}
                        for rdn in cert['subject']:
                            for key, value in rdn:
                                subject_dict[key] = value
                        result["subject"] = subject_dict.get('commonName', '')
                    result["expiry"] = str(cert.get('notAfter', 'Unknown'))
                    if 'subjectAltName' in cert:
                        result["san"] = [
                            value for _, value in cert['subjectAltName']
                        ]
    except ssl.CertificateError as e:
        result["errors"].append(f"Certificate error: {str(e)[:80]}")
    except ssl.SSLCertVerificationError as e:
        result["errors"].append(f"SSL verification failed: {str(e)[:80]}")
    except ssl.SSLError as e:
        result["errors"].append(f"SSL error: {str(e)[:80]}")
    except socket.timeout:
        result["errors"].append("SSL handshake timed out")
    except ConnectionRefusedError:
        result["errors"].append("Connection refused on port 443")
    except OSError as e:
        result["errors"].append(f"Socket error: {str(e)[:80]}")
    except Exception as e:
        result["errors"].append(str(e)[:80])
    return result


def check_headers(url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status_code": None,
        "has_hsts": False,
        "server": "",
        "has_xframe": False,
        "has_xss_protection": False,
        "final_url": "",
        "redirect_count": 0,
    }
    if not HAS_REQUESTS:
        result["error"] = "requests library not available. Install with: pip install requests"
        return result
    try:
        resp = requests.get(
            normalize_url(url),
            timeout=10,
            allow_redirects=True,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (X11; Linux x86_64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                ),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            },
        )
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["redirect_count"] = len(resp.history)
        headers = resp.headers
        result["has_hsts"] = 'Strict-Transport-Security' in headers
        result["has_xframe"] = 'X-Frame-Options' in headers
        result["has_xss_protection"] = 'X-XSS-Protection' in headers
        result["server"] = headers.get('Server', 'Unknown')
    except requests.exceptions.SSLError as e:
        result["error"] = f"SSL error: {str(e)[:60]}"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {str(e)[:60]}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except requests.exceptions.TooManyRedirects:
        result["error"] = "Too many redirects"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result


# ====================================================================
# SECTION 6: EMAIL HEADER ANALYSIS
# ====================================================================

def analyze_email_headers(headers_raw: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "spf_pass": False,
        "dkim_pass": False,
        "dmarc_pass": False,
        "from_domain": "",
        "return_path_domain": "",
        "reply_to_domain": "",
        "mismatch_alerts": [],
    }
    from_match = re.search(
        r'^From:\s*.*?@([^>\s]+)', headers_raw, re.MULTILINE | re.IGNORECASE
    )
    reply_match = re.search(
        r'^Reply-To:\s*.*?@([^>\s]+)', headers_raw, re.MULTILINE | re.IGNORECASE
    )
    return_match = re.search(
        r'^Return-Path:\s*.*?@([^>\s]+)', headers_raw, re.MULTILINE | re.IGNORECASE
    )
    if from_match:
        result["from_domain"] = from_match.group(1).strip('>').strip()
    if reply_match:
        result["reply_to_domain"] = reply_match.group(1).strip('>').strip()
    if return_match:
        result["return_path_domain"] = return_match.group(1).strip('>').strip()
    if re.search(r'spf=pass', headers_raw, re.IGNORECASE):
        result["spf_pass"] = True
    if re.search(r'dkim=pass', headers_raw, re.IGNORECASE):
        result["dkim_pass"] = True
    if re.search(r'dmarc=pass', headers_raw, re.IGNORECASE):
        result["dmarc_pass"] = True
    if re.search(r'spf=fail', headers_raw, re.IGNORECASE):
        result["spf_pass"] = False
    if re.search(r'dkim=fail', headers_raw, re.IGNORECASE):
        result["dkim_pass"] = False
    if re.search(r'dmarc=fail', headers_raw, re.IGNORECASE):
        result["dmarc_pass"] = False
    if (
        result["from_domain"] and result["return_path_domain"]
        and result["from_domain"] != result["return_path_domain"]
    ):
        result["mismatch_alerts"].append(
            f"Return-Path ({result['return_path_domain']}) != From ({result['from_domain']})"
        )
    if (
        result["from_domain"] and result["reply_to_domain"]
        and result["from_domain"] != result["reply_to_domain"]
    ):
        result["mismatch_alerts"].append(
            f"Reply-To ({result['reply_to_domain']}) != From ({result['from_domain']})"
        )
    return result


# ====================================================================
# SECTION 7: MESSAGE CONTENT ANALYSIS
# ====================================================================

def analyze_message_content(subject: str, body: str) -> Dict[str, Any]:
    flags: List[str] = []
    score = 0
    text = f"{subject} {body}".lower()

    for phrase in URGENCY_PHRASES:
        if phrase in text:
            flags.append(
                f"Urgency manipulation: '{phrase}' - creates panic to bypass critical thinking"
            )
            score += 10

    for phrase in SENSITIVE_REQUEST_PHRASES:
        if phrase in text:
            flags.append(
                f"Sensitive info request: '{phrase}' - legitimate organizations never ask via email"
            )
            score += 20

    for phrase in GENERIC_GREETINGS:
        if phrase in text:
            flags.append(
                f"Generic greeting: '{phrase}' - lack of personalization is a phishing hallmark"
            )
            score += 8

    brand_pattern = (
        r'(?:from|team|support|security)\s*(?:of|at)?\s*'
        r'(paypal|google|amazon|netflix|microsoft|apple|facebook|'
        r'instagram|linkedin|dropbox|adobe|spotify|chase)'
    )
    seen_brands = set()
    for match in re.finditer(brand_pattern, text, re.IGNORECASE):
        brand = match.group(1).lower()
        if brand not in seen_brands:
            seen_brands.add(brand)
            flags.append(f"Brand impersonation in text: claims to be '{match.group(1).title()}'")
            score += 20

    typos = [
        (r"\byou're\b(?!\s+\w+)", "you're (misused)"),
        (r'\baccout\b', 'accout (account)'),
        (r'\bacount\b', 'acount (account)'),
        (r'\brecieved\b', 'recieved (received)'),
        (r'\brecieve\b', 'recieve (receive)'),
        (r'\bconfirmmation\b', 'confirmmation (confirmation)'),
        (r'\btommorow\b', 'tommorow (tomorrow)'),
        (r'\bappologies\b', 'appologies (apologies)'),
        (r'\bseperat\b', 'seperat (separate)'),
        (r'\bdefinately\b', 'definately (definitely)'),
    ]
    for pattern, label in typos:
        if re.search(pattern, text, re.IGNORECASE):
            flags.append(f"Spelling/grammar error: '{label}' - common in phishing campaigns")
            score += 5

    excl_count = len(re.findall(r'!{2,}', text))
    if excl_count > 2:
        flags.append(
            f"Excessive exclamation marks ({excl_count} instances) - emotional pressure tactic"
        )
        score += 5

    cap_words = re.findall(r'\b[A-Z]{4,}\b', body)
    if len(cap_words) >= 5:
        flags.append(
            f"Excessive capitalization ({len(cap_words)} all-caps words) - urgency manipulation"
        )
        score += 5

    urls_in_body = re.findall(r'https?://[^\s\'\"<>\)]+', body, re.IGNORECASE)
    if urls_in_body:
        flags.append(
            f"Contains {len(urls_in_body)} hyperlink(s) - verify each URL independently"
        )

    html_links = re.findall(
        r'<a\s+[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>([^<]+)</a>',
        body, re.IGNORECASE
    )
    for href, display in html_links:
        display_domain = extract_domain(display) if '.' in display else None
        href_domain = extract_domain(href)
        if display_domain and href_domain and display_domain != href_domain:
            flags.append(
                f"Link text mismatch: display shows "
                f"'{display[:40]}' but links to '{href[:60]}'"
            )
            score += 25

    return {
        "score": min(100, score),
        "red_flags": flags,
        "urls_found": urls_in_body,
    }


# ====================================================================
# SECTION 8: MAIN ANALYSIS ENGINE
# ====================================================================

def analyze_email(email_address: str) -> AnalysisResult:
    result = AnalysisResult(input_type="email", input_raw=email_address)
    domain = extract_domain(email_address)
    result.domain = domain

    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]{2,}$', email_address):
        result.add_red_flag(50, "Invalid email format - no valid domain extension")
        return result

    tld = check_suspicious_tld(domain)
    if tld:
        result.add_red_flag(25, f"Suspicious TLD: {tld} (commonly abused in phishing)")

    lookalike = check_lookalike(domain)
    if lookalike.get("impersonates"):
        for brand in lookalike["impersonates"]:
            result.add_red_flag(40, f"Appears to impersonate '{brand}'")
    if lookalike.get("has_homoglyphs"):
        result.add_red_flag(35, f"Homoglyph characters detected: {lookalike['homoglyph_chars']}")
        if 'decoded' in lookalike:
            result.add_red_flag(0, f"Decoded domain: {lookalike['decoded']}")
    result.lookalike_analysis = lookalike

    age_info = check_domain_age(domain)
    result.tech_details["domain_created"] = age_info.get("created", "Unknown")
    result.tech_details["domain_age_days"] = age_info.get("age_days", "Unknown")
    result.tech_details["registrar"] = age_info.get("registrar", "Unknown")
    days = age_info.get("age_days")
    if days is not None:
        if days < 30:
            result.add_red_flag(30, f"Domain registered {days} days ago - very recent")
        elif days < 180:
            result.add_red_flag(15, f"Domain less than 6 months old ({days} days)")
        elif days > 365:
            result.add_safe_indicator(f"Domain established ({days} days)")
    if age_info.get("note") and days is None:
        result.tech_details["whois_note"] = age_info["note"]

    dns_info = check_dns_records(domain)
    if not dns_info.get("has_mx"):
        result.add_red_flag(20, "No MX records found - cannot be a legitimate email sender")
    if dns_info.get("has_spf"):
        result.add_safe_indicator("SPF record found")
    else:
        result.add_red_flag(10, "No SPF record (email spoofing not prevented)")
    result.tech_details["dns"] = dns_info

    ip_info = check_ip_reputation(domain)
    if ip_info.get("ips"):
        result.tech_details["resolved_ips"] = ip_info["ips"]
    else:
        result.add_red_flag(30, "Domain does not resolve to any IP")

    return result


def analyze_url(url: str) -> AnalysisResult:
    result = AnalysisResult(input_type="url", input_raw=url)
    domain = extract_domain(url)
    result.domain = domain

    tld = check_suspicious_tld(domain)
    if tld:
        result.add_red_flag(25, f"Suspicious TLD: {tld} (commonly abused in phishing)")

    url_flags = check_url_structure(url)
    for flag in url_flags:
        if "shortener" in flag:
            score = 25
        elif "@" in flag:
            score = 35
        elif "IP address" in flag:
            score = 25
        else:
            score = 15
        result.add_red_flag(score, flag)

    lookalike = check_lookalike(domain)
    if lookalike.get("impersonates"):
        for brand in lookalike["impersonates"]:
            result.add_red_flag(45, f"Domain impersonates '{brand}'")
    if lookalike.get("has_homoglyphs"):
        result.add_red_flag(40, f"Homoglyph characters: {lookalike['homoglyph_chars']}")
        if 'decoded' in lookalike:
            result.add_red_flag(0, f"Decoded: {lookalike['decoded']}")
    result.lookalike_analysis = lookalike

    age_info = check_domain_age(domain)
    result.tech_details["domain_created"] = age_info.get("created", "Unknown")
    result.tech_details["domain_age_days"] = age_info.get("age_days", "Unknown")
    days = age_info.get("age_days")
    if days is not None:
        if days < 30:
            result.add_red_flag(35, f"Domain age: {days} days (very new)")
        elif days < 180:
            result.add_red_flag(15, f"Domain age: {days} days (< 6 months)")
        elif days > 365:
            result.add_safe_indicator(f"Established domain ({days} days)")
    if age_info.get("note") and days is None:
        result.tech_details["whois_note"] = age_info["note"]

    if normalize_url(url).startswith('https://'):
        ssl_info = check_ssl_cert(domain)
        result.headers_analysis["ssl"] = ssl_info
        if ssl_info.get("valid"):
            issuer = ssl_info.get("issuer", "Unknown")
            result.add_safe_indicator(f"Valid SSL cert: {issuer}")
            result.tech_details["ssl_issuer"] = ssl_info["issuer"]
            result.tech_details["ssl_expiry"] = ssl_info["expiry"]
        else:
            errs = ssl_info.get("errors", [])
            if errs:
                result.add_red_flag(30, f"SSL issues: {'; '.join(errs)}")

    header_info = check_headers(url)
    result.headers_analysis["headers"] = header_info

    if "error" in header_info:
        result.add_red_flag(10, f"HTTP error: {header_info['error']}")
    else:
        status = header_info.get("status_code")
        if status == 200:
            result.add_safe_indicator("Page loads successfully (HTTP 200)")
        elif status and status >= 400:
            result.add_red_flag(10, f"HTTP {status} response")

        redirects = header_info.get("redirect_count", 0)
        if redirects > 2:
            result.add_red_flag(15, f"Multiple redirects ({redirects}) - potential evasion technique")

        if header_info.get("has_hsts"):
            result.add_safe_indicator("HSTS enabled")
        else:
            result.add_red_flag(5, "No HSTS header")

        final_url = header_info.get("final_url", "")
        if final_url and final_url != normalize_url(url):
            result.add_red_flag(20, f"Redirects to: {final_url[:80]}")
            final_domain = extract_domain(final_url)
            if final_domain and final_domain != domain:
                result.add_red_flag(30, f"Redirects to DIFFERENT domain: {final_domain}")

    internal_domains = get_embedded_domains(url)
    if len(internal_domains) > 1:
        for d in internal_domains[1:]:
            if d != domain:
                result.add_red_flag(15, f"Embedded domain in URL params: {d}")

    return result


def analyze_raw_email_headers(headers_raw: str) -> AnalysisResult:
    result = AnalysisResult(input_type="email_headers", input_raw=headers_raw[:100])
    header_analysis = analyze_email_headers(headers_raw)
    result.headers_analysis = header_analysis
    if header_analysis.get("from_domain"):
        result.domain = header_analysis["from_domain"]
    if header_analysis["spf_pass"]:
        result.add_safe_indicator("SPF authentication passed")
    else:
        result.add_red_flag(30, "SPF authentication FAILED - sender may be spoofed")
    if header_analysis["dkim_pass"]:
        result.add_safe_indicator("DKIM signature verified")
    else:
        result.add_red_flag(25, "DKIM signature FAILED - email may be tampered")
    if header_analysis["dmarc_pass"]:
        result.add_safe_indicator("DMARC policy enforced")
    else:
        result.add_red_flag(20, "DMARC verification FAILED - domain may be impersonated")
    for alert in header_analysis.get("mismatch_alerts", []):
        result.add_red_flag(35, f"Header mismatch: {alert}")
    return result


# ====================================================================
# SECTION 9: INTERACTIVE CLI
# ====================================================================

def interactive() -> None:
    print("=" * 65)
    print("  PHISHING ANALYZER - Security Testing Tool")
    print("  Authorized penetration testing use only")
    print("=" * 65)
    while True:
        print("\nWhat would you like to analyze?")
        print("  1) URL")
        print("  2) Email address")
        print("  3) Raw email headers")
        print("  4) Message body text")
        print("  5) Exit")
        choice = input("  Choice [1-5]: ").strip()
        if choice == "5":
            print("Exiting. Stay sharp.")
            break
        elif choice == "1":
            url = input("\n  Enter URL: ").strip()
            if url:
                result = analyze_url(url)
                print("\n" + result.report())
        elif choice == "2":
            email = input("\n  Enter email address: ").strip()
            if email:
                result = analyze_email(email)
                print("\n" + result.report())
        elif choice == "3":
            print("\n  Paste raw email headers below.")
            print("  Type 'END' on its own line when finished:")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            headers = "\n".join(lines)
            if headers.strip():
                result = analyze_raw_email_headers(headers)
                print("\n" + result.report())
        elif choice == "4":
            subject = input("\n  Email subject: ").strip()
            print("  Email body below (type 'END' on its own line when done):")
            lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            body = "\n".join(lines)
            if subject or body.strip():
                msg = analyze_message_content(subject, body)
                print("\n" + "=" * 65)
                print("  MESSAGE CONTENT ANALYSIS")
                print("=" * 65)
                print(f"  Suspicion Score: {msg['score']}/100")
                if msg['red_flags']:
                    print("\n  RED FLAGS:")
                    for flag in msg['red_flags']:
                        print(f"     \u2022 {flag}")
                if msg.get('urls_found'):
                    print("\n  URLS IN MESSAGE:")
                    for u in msg['urls_found']:
                        print(f"     \u2022 {u}")
                print("=" * 65)


def analyze_from_file(filepath: str) -> List[AnalysisResult]:
    results = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                item = line.strip()
                if not item or item.startswith('#'):
                    continue
                if '@' in item and '.' in item.split('@')[-1]:
                    results.append(analyze_email(item))
                else:
                    results.append(analyze_url(item))
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
    except Exception as e:
        print(f"[!] Error reading file: {e}")
    return results


# ====================================================================
# SECTION 10: MAIN ENTRY POINT
# ====================================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ("--help", "-h"):
            print("Usage:")
            print("  python phishing_analyzer.py <url|email>")
            print("  python phishing_analyzer.py <file.txt>")
            print("  python phishing_analyzer.py  (interactive mode)")
            sys.exit(0)

        if '@' in arg and arg.count('@') == 1 and '.' in arg.split('@')[-1]:
            result = analyze_email(arg)
        elif '.' in arg:
            result = analyze_url(arg)
        elif arg.endswith(('.txt', '.csv')):
            results = analyze_from_file(arg)
            if not results:
                print("No valid entries found in file.")
            for r in results:
                print(r.report())
                print()
            sys.exit(0)
        else:
            print("Unknown input. Use --help for usage.")
            sys.exit(1)

        print(result.report())
    else:
        interactive()