# Phishing Analyzer

![python](https://img.shields.io/badge/python-3.8+-blue) ![license](https://img.shields.io/badge/License-MIT-green) ![platform](https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey)

A comprehensive, cross-platform **phishing detection and analysis tool** for cybersecurity professionals. Analyzes URLs, email addresses, raw email headers, and message body content for phishing indicators — all without relying on external APIs or cloud services.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Output Example](#output-example)
- [Detection Categories](#detection-categories)
- [Project Structure](#project-structure)
- [Algorithm Details](#algorithm-details)
- [Ethical Use](#ethical-use)
- [Author](#author)
- [License](#license)

---

## Overview

This project implements a complete **Phishing Analyzer** in Python that inspects suspicious URLs, email addresses, raw email headers, and message text — and produces a detailed report with a suspicion score, red flags, safe indicators, and technical details.

This tool implements:

- **URL analysis** — scans for suspicious patterns, TLDs, brand impersonation, and lookalike domains
- **Email header parsing** — extracts and validates SPF, DKIM, and DMARC authentication results
- **WHOIS domain age lookup** — pure-Python client, no system binary required
- **SSL certificate inspection** — validates TLS cert issuer, expiry, and errors
- **HTTP header analysis** — tracks redirects, checks HSTS, detects cross-domain hops
- **Lookalike / homoglyph detection** — Levenshtein edit distance + Cyrillic character normalization
- **Message body analysis** — urgency phrases, credential requests, and mismatched anchor tags

> **Note:** This tool is intended for **authorized penetration testing and security awareness training only**. Do not use it against systems or domains you do not have explicit permission to analyze.

---

## Features

### Core Analysis Capabilities

| Feature | Description |
|---|---|
| **URL Analysis** | Scans for suspicious TLDs, lookalike domains, URL shorteners, IP-based URLs, credential-in-URL patterns, double encoding, excessive subdomains, and suspicious keywords |
| **Email Address Analysis** | Validates format, checks domain reputation via WHOIS, DNS records (MX/SPF), and lookalike/brand impersonation detection |
| **Email Header Analysis** | Parses SPF, DKIM, and DMARC authentication results; detects From/Reply-To/Return-Path domain mismatches |
| **Message Content Analysis** | Identifies urgency manipulation, sensitive information requests, generic greetings, brand impersonation claims, spelling errors, link text mismatches, and HTML anchor tag analysis |

### Detection Engine

- **Levenshtein Edit Distance** — Built-in algorithm detects typosquatting (e.g., `paypa1` → `paypal`, `g00gle` → `google`)
- **Homoglyph Detection** — Identifies Cyrillic characters that visually mimic Latin letters (e.g., `paypal` with Cyrillic 'a' and 'p')
- **Brand Impersonation** — 25+ protected brands checked across all domain segments
- **Domain Age Verification** — Pure-Python WHOIS client with referral following
- **SSL Certificate Inspection** — Extracts issuer, subject, expiry, and SAN entries
- **DNS Record Analysis** — MX and SPF record validation

### Technical Highlights

- **Zero External API Dependencies** — All analysis runs locally. No API keys, no cloud services, no data leaves your machine
- **Pure-Python WHOIS Client** — Custom implementation connects directly to WHOIS servers over TCP port 43. No system `whois` binary required — works on **Windows, Linux, and macOS**
- **WHOIS Referral Following** — Automatically follows registrar referrals (e.g., Verisign → registrar's WHOIS server) for complete domain data
- **Comprehensive Date Parsing** — Handles 20+ datetime formats used by different WHOIS registries worldwide

---

## How It Works

### Scoring System

Each analysis produces a **Suspicion Score out of 100**. Points are added for red flags and the final score maps to a verdict:

| Score Range | Verdict |
|---|---|
| 0 – 20 | ✅ LIKELY SAFE |
| 21 – 49 | ⚠️ SUSPICIOUS |
| 50 – 74 | 🔶 HIGH RISK |
| 75 – 100 | 🚨 CRITICAL — PHISHING |

### Red Flag Scoring Examples

| Red Flag | Points Added |
|---|---|
| Domain impersonates a known brand | +45 |
| Domain age under 30 days | +35 |
| SPF authentication failed | +30 |
| SSL errors or invalid cert | +30 |
| Redirects to a different domain | +30 |
| DKIM signature failed | +25 |
| URL shortener detected | +25 |
| IP address used instead of domain | +25 |
| DMARC verification failed | +20 |
| Multiple redirects (> 2) | +15 |
| Suspicious keyword in URL | +15 |

### How the WHOIS Client Works

The pure-Python WHOIS client:

1. **Maps TLDs to authoritative servers** — Uses a comprehensive lookup table for 90+ TLDs
2. **Connects over TCP port 43** — Sends the domain query and reads the raw response
3. **Follows referrals** — When Verisign (for `.com` / `.net`) returns a `Whois Server:` field pointing to the registrar, it queries that server too
4. **Parses the combined response** — Extracts creation dates, registrar, name servers, and registrant information
5. **Handles 20+ date formats** — From ISO 8601 (`2024-02-09T05:41:13Z`) to human-readable (`14 Aug 2024`)

### How the Lookalike Detection Works

The detection engine uses a multi-layered approach:

1. **Direct Known Lookalikes** — Checks against a curated database of known phishing domain patterns
2. **Levenshtein Edit Distance** — A built-in implementation (no external library needed) measures how many character changes are needed to transform a domain segment into a protected brand name
3. **Homoglyph Normalization** — Cyrillic characters that look like Latin letters are converted before comparison
4. **Embedded Brand Detection** — Identifies brands appearing within longer domain names with suspicious prefixes/suffixes
5. **Subdomain Analysis** — Detects brands used as subdomains of other domains

---

## Installation

### Requirements

| Dependency | Required | Purpose |
|---|---|---|
| Python 3.8+ | Yes | Core runtime |
| `dnspython` | No | DNS MX/SPF record lookups |
| `requests` | No | HTTP header analysis and redirect tracking |

The tool works fully with just the Python standard library. DNS and HTTP checks are enhanced by the optional dependencies but all core features (WHOIS, lookalike detection, URL analysis, content analysis, SSL inspection) work without any external packages.

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Shubham22485/phishing-analyzer.git
cd phishing-analyzer

# Install optional dependencies (recommended)
pip install dnspython requests

# No additional installation needed — run directly
python phishing_analyzer.py --help
```

---

## Usage

### Interactive Mode

```bash
python phishing_analyzer.py
```

Launches an interactive menu where you can analyze URLs, emails, headers, and message content one at a time.

```
=================================================================
  PHISHING ANALYZER - Security Testing Tool
  Authorized penetration testing use only
=================================================================

What would you like to analyze?
  1) URL
  2) Email address
  3) Raw email headers
  4) Message body text
  5) Exit
  Choice [1-5]:
```

### Command-Line Mode

Analyze a single URL or email address:

```bash
# Analyze a URL
python phishing_analyzer.py "https://paypa1-secure-login.com/verify"

# Analyze an email address
python phishing_analyzer.py "support@paypa1-secure-login.com"

# Analyze a legitimate domain for comparison
python phishing_analyzer.py "https://www.paypal.com"
```

### Batch Mode

Create a text file with one URL or email per line (lines starting with `#` are ignored):

```bash
# urls.txt
https://paypa1-secure-com/login
support@rnicrosoft-verify.com
https://www.google.com
info@paypa1-security.com
```

```bash
python phishing_analyzer.py urls.txt
```

---

## Output Example

Running the tool against a phishing domain produces a detailed report:

```
=================================================================
  PHISHING ANALYSIS REPORT
  Analyzed: https://paypa1-secure-login.com/verify
=================================================================
  Type:              URL
  Domain:            paypa1-secure-login.com
  Suspicion Score:   85/100
  Verdict:           CRITICAL - PHISHING
-----------------------------------------------------------------

  RED FLAGS:
     [+25] Suspicious TLD: .xyz (commonly abused in phishing)
     [+15] Suspicious keyword in URL: 'verify'
     [+45] Domain impersonates 'paypal' (typosquatting: 'paypa1' is 1 edit(s) from 'paypal')
     [+35] Domain age: 12 days (very new)

  SAFE INDICATORS:
     [+] Valid SSL cert: Let's Encrypt

  TECHNICAL DETAILS:
     domain_created:          2026-06-01T14:23:11+00:00
     domain_age_days:         12
     registrar:               NameCheap, Inc.
     whois_server:            whois.verisign-grs.com
     registrar_whois_server:  whois.namecheap.com
     resolved_ips:            ['192.0.2.45']
     ssl_issuer:              Let's Encrypt
     ssl_expiry:              Sep 01 14:23:11 2026 GMT

  LOOKALIKE ANALYSIS:
     impersonates:  ['paypal']
     methods:       ["typosquatting: 'paypa1' is 1 edit(s) from 'paypal'"]
=================================================================
```

---

## Detection Categories

### Suspicious TLDs

Free and commonly abused TLDs: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.loan`, `.work`, `.date`, `.xyz`, `.club`, `.online`, `.site`, `.click`, `.link`, and more.

### Protected Brands

`google`, `paypal`, `facebook`, `microsoft`, `amazon`, `linkedin`, `netflix`, `apple`, `instagram`, `twitter`, `dropbox`, `adobe`, `spotify`, `chase`, `wellsfargo`, `bankofamerica`, `americanexpress`, `mastercard`, `visa`, `whatsapp`, `telegram`, `github`, `shopify`, `ebay`, `walmart`, `stripe`, and more.

### Urgency Manipulation Phrases

`immediately`, `urgent`, `act now`, `suspended`, `blocked`, `compromised`, `security alert`, `unusual activity`, `verify now`, `final warning`, and 20+ more.

### Message Body Red Flags

- Generic greetings (`Dear Customer`, `Dear User`)
- Credential/personal information requests
- Spelling and grammar errors
- Mismatched link text vs. actual href targets (HTML anchor tag analysis)
- Excessive capitalization and exclamation marks

---

## Project Structure

```
phishing-analyzer/
│
├── phishing_analyzer.py     # Main analysis tool (single file)
├── README.md                # This file
└── urls.txt                 # Example batch input file
```

Everything is contained in a single Python file for easy deployment, auditing, and modification.

### Internal Sections

| Section | Contents |
|---|---|
| Section 1 | Pure-Python WHOIS client — TLD server map, TCP queries, referral following, date parsing |
| Section 2 | URL parsing utilities — normalization, domain extraction, embedded domain detection |
| Section 3 | Domain age checks — WHOIS lookup wrapper, age calculation |
| Section 4 | SSL certificate verification — TLS handshake, issuer/expiry extraction |
| Section 5 | HTTP header analysis — redirect tracking, HSTS check, status codes |
| Section 6 | Lookalike & homoglyph detection — Levenshtein distance, Cyrillic normalization, brand matching |
| Section 7 | Email address analysis — format validation, MX/SPF DNS lookup |
| Section 8 | Email header parsing — SPF/DKIM/DMARC extraction, mismatch detection |
| Section 9 | Message content analysis — urgency phrases, credential requests, HTML anchor analysis |
| Section 10 | `AnalysisResult` dataclass — score accumulation, report generation |
| Section 11 | Top-level analyzers — `analyze_url()`, `analyze_email()`, `analyze_raw_email_headers()` |
| Section 12 | Interactive CLI and batch file processor |
| Section 13 | Main entry point — argument parsing, single-item and file modes |

---

## Algorithm Details

### `whois_lookup(domain)`

Performs a two-step WHOIS lookup:
1. Queries the TLD registry server (e.g., `whois.verisign-grs.com` for `.com`)
2. Extracts and follows any `Whois Server:` referral in the response
3. Parses creation date, registrar, name servers, and registrant country from the combined response

### `check_lookalike(domain)`

```python
# Simplified logic
for brand in PROTECTED_BRANDS:
    for segment in domain_segments:
        if levenshtein(segment, brand) <= 2:
            flag as typosquatting
        if segment contains homoglyph characters:
            normalize and re-check
        if brand is embedded inside a longer segment:
            flag as brand-in-domain
```

### `analyze_email_headers(raw_headers)`

Parses raw header text to extract:
- `Authentication-Results` — SPF / DKIM / DMARC pass/fail status
- `Received-SPF` — direct SPF verdict line
- `From`, `Reply-To`, `Return-Path` — domain mismatch detection

---

## Ethical Use

This tool is designed for **authorized penetration testing and security awareness training only**. Users must ensure they have explicit permission to analyze any domains, email addresses, or systems. The platform pre-verifies user authorization in accordance with applicable terms of service.

---

**Author:** Shubham Kumar
**Built for:** Cybersecurity professionals, penetration testers, and security awareness teams

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 Shubham Kumar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### Quick Setup

```bash
# 1. Clone the repo
git clone https://github.com/Shubham22485/phishing-analyzer.git
cd phishing-analyzer

# 2. (Optional) Install dependencies
pip install dnspython requests

# 3. Run
python phishing_analyzer.py
```
