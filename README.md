# 🛡️ Cyber Security Internship — DecodeLabs | Batch 2026

<div align="center">

![Intern](https://img.shields.io/badge/Intern-Shubham%20Kumar-blue?style=for-the-badge)
![Track](https://img.shields.io/badge/Track-Cyber%20Security-darkblue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![Projects](https://img.shields.io/badge/Projects-3%20%2F%203-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**One-month remote internship at [Decode Labs](https://www.decodelabs.tech) — a Government Registered Enterprise based in Greater Lucknow, India.**

*June 1, 2026 → July 1, 2026*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Internship Details](#-internship-details)
- [Project 1 — Password Strength Checker](#-project-1--password-strength-checker)
- [Project 2 — Caesar Cipher Encryption & Decryption](#-project-2--caesar-cipher-encryption--decryption)
- [Project 3 — Phishing Awareness Analyzer](#-project-3--phishing-awareness-analyzer)
- [Skills Developed](#-skills-developed)
- [Repository Structure](#-repository-structure)
- [How to Run](#-how-to-run)
- [Author](#-author)

---

## 🔍 Overview

This repository is the **official portfolio** for my Cyber Security Internship at **Decode Labs (Batch 2026)**. It contains all three assigned projects, each with complete Python source code and a detailed README.

The internship followed a **progressive learning model**:

```
Project 1              Project 2                   Project 3
Defensive Logic   →   Applied Cryptography   →   Threat Detection
(Validate Input)      (Encrypt/Decrypt)           (Identify Attacks)
```

> **Core Philosophy:** You cannot protect what you haven't validated. You cannot encrypt what is weak. You cannot detect what you don't understand.

---

## 🏢 Internship Details

| Field | Details |
|-------|---------|
| **Organization** | Decode Labs — Your Digital Lab |
| **Registration** | Govt. Registered Enterprise |
| **Location** | Greater Lucknow, India (Remote) |
| **Track** | Cyber Security |
| **Duration** | June 1, 2026 – July 1, 2026 |
| **Mode** | Remote / Virtual |
| **Website** | [www.decodelabs.tech](https://www.decodelabs.tech) |

---

## 🔐 Project 1 — Password Strength Checker

[![Repo](https://img.shields.io/badge/Repo-password--strength--checker-blue?style=flat-square&logo=github)](https://github.com/Shubham22485/password-strength-checker)
![Python](https://img.shields.io/badge/Python-3.6+-blue?style=flat-square&logo=python)
![Dependencies](https://img.shields.io/badge/Dependencies-None%20(stdlib)-brightgreen?style=flat-square)

**Goal:** Build a program that evaluates any password and classifies it as Weak, Medium, or Strong — with entropy scoring, leaked-password detection, and improvement tips.

### Key Features

- ✅ **Entropy Calculation** — `H = length × log₂(pool_size)` using Shannon's information theory formula
- ✅ **4-Criteria Scoring** — Length ≥ 8, uppercase + lowercase mix, digit, symbol (score: 0–4)
- ✅ **Leaked Password Detection** — instant O(1) set lookup against common/breached passwords
- ✅ **Timing Attack Defense** — `hmac.compare_digest()` for constant-time comparison (prevents side-channel attacks)
- ✅ **Visual CLI Output** — strength bar `████░`, score, entropy in bits, and actionable tips
- ✅ **No External Dependencies** — pure Python standard library (`re`, `math`, `hmac`)

### Core Algorithm

```python
# Entropy: measures how many bits of randomness a password contains
def calculate_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password): pool += 26   # a-z
    if any(c.isupper() for c in password): pool += 26   # A-Z
    if any(c.isdigit() for c in password): pool += 10   # 0-9
    if any(not c.isalnum() for c in password): pool += 32  # symbols
    return round(len(password) * math.log2(pool), 2) if pool else 0.0
```

### Quick Start

```bash
git clone https://github.com/Shubham22485/password-strength-checker.git
cd password-strength-checker
python Password_strength_checker.py
```

### Sample Output

```
==================================================
  PASSWORD STRENGTH CHECKER — DecodeLabs
==================================================
  Strength  : [████]  ✓  STRONG
  Score     : 4/4
  Entropy   : 92.68 bits
--------------------------------------------------
  Criteria Check:
    ✓ PASS  8+ characters        ✓ PASS  Uppercase (A-Z)
    ✓ PASS  12+ characters       ✓ PASS  Number (0-9)
    ✓ PASS  Lowercase (a-z)      ✓ PASS  Symbol (!@#$...)
    ✓ PASS  Not a leaked password
==================================================
```

---

## 🔑 Project 2 — Caesar Cipher Encryption & Decryption

[![Repo](https://img.shields.io/badge/Repo-caesar--cipher-blue?style=flat-square&logo=github)](https://github.com/Shubham22485/caesar-cipher)
![Python](https://img.shields.io/badge/Python-3.6+-blue?style=flat-square&logo=python)
![Dependencies](https://img.shields.io/badge/Dependencies-None%20(stdlib)-brightgreen?style=flat-square)

**Goal:** Implement a complete Caesar cipher in Python — the foundational building block of all modern encryption — with arbitrary shift support, case preservation, and graceful edge-case handling.

### Key Features

- ✅ **Encryption** — `Eₙ(x) = (x + n) % 26` — shifts each letter forward by n positions
- ✅ **Decryption** — `Dₙ(x) = (x − n) % 26` — exact mathematical inverse
- ✅ **Shift Normalization** — any integer (positive, negative, large) normalized to 0–25
- ✅ **Character Preservation** — non-alphabetic characters (spaces, digits, punctuation) pass through unchanged
- ✅ **Case Preservation** — uppercase and lowercase letters stay in their respective cases
- ✅ **No External Dependencies** — pure Python standard library

### Core Algorithm

```python
def encrypt(text, shift):
    normalized_shift = shift % 26   # normalize any integer to 0-25
    result = []
    for char in text:
        if char.isupper():
            # Convert to 0-25, add shift, wrap around, convert back
            result.append(chr((ord(char) - ord('A') + normalized_shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + normalized_shift) % 26 + ord('a')))
        else:
            result.append(char)   # non-alpha: unchanged
    return ''.join(result)
```

### Encryption Flow (A → D with shift 3)

```
Char 'A' → ASCII 65 → Subtract Base (-65) → 0 → Add Key (+3) → 3 → Modulo %26 → 3 → Add Base (+65) → 68 → Char 'D'
```

### Quick Start

```bash
git clone https://github.com/Shubham22485/caesar-cipher.git
cd caesar-cipher
python Encryption___Decryption.py
```

### Sample Output

```
=== Caesar Cipher Encryption & Decryption ===

Enter your choice (1/2/3): 1
Enter the text: Hello, World!
Enter shift value (integer): 5

Original:  Hello, World!
Encrypted: Mjqqt, Btwqi!
```

> **⚠️ Security Note:** The Caesar cipher has only 25 possible keys and is trivially breakable by brute force or frequency analysis. It is used here for educational purposes only. Modern systems use AES-256 with 2¹²⁸+ key space.

---

## 🎣 Project 3 — Phishing Awareness Analyzer

[![Repo](https://img.shields.io/badge/Repo-phishing--analyzer-blue?style=flat-square&logo=github)](https://github.com/Shubham22485/phishing-analyzer)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Optional](https://img.shields.io/badge/Optional-dnspython%2C%20requests-orange?style=flat-square)

**Goal:** Build a comprehensive, zero-external-API phishing detection tool that analyzes URLs, email addresses, raw email headers, and message body text — producing a scored threat report.

### Key Features

- ✅ **URL Analysis** — suspicious TLDs, URL shorteners, IP-based URLs, keyword detection, double encoding
- ✅ **Typosquatting Detection** — Levenshtein edit-distance (pure Python, no library) against 25+ protected brands
- ✅ **Homoglyph Detection** — Cyrillic character normalization (e.g., `paypal.com` with Cyrillic 'а')
- ✅ **Domain Age Verification** — pure-Python WHOIS client over TCP port 43, follows referral chains
- ✅ **SSL Inspection** — issuer, expiry, SAN entries extracted via Python's `ssl` module
- ✅ **Email Header Parsing** — SPF, DKIM, DMARC result extraction; From/Reply-To/Return-Path mismatch detection
- ✅ **Message Body Analysis** — urgency phrases, credential requests, anchor tag mismatch (HTML)
- ✅ **Suspicion Scoring Engine** — 0–100 scale → Safe / Suspicious / High Risk / Critical verdict

### Scoring System

| Score | Verdict |
|-------|---------|
| 0 – 20 | ✅ LIKELY SAFE |
| 21 – 49 | ⚠️ SUSPICIOUS |
| 50 – 74 | 🔶 HIGH RISK |
| 75 – 100 | 🚨 CRITICAL — PHISHING |

### Key Red Flags Scored

| Red Flag | Points |
|----------|--------|
| Brand impersonation (typosquatting) | +45 |
| Domain age < 30 days | +35 |
| SPF authentication failed | +30 |
| SSL errors / invalid certificate | +30 |
| Redirect to different domain | +30 |
| URL shortener detected | +25 |
| IP address used instead of domain | +25 |

### Quick Start

```bash
git clone https://github.com/Shubham22485/phishing-analyzer.git
cd phishing-analyzer

# Install optional dependencies (recommended)
pip install dnspython requests

# Interactive mode
python Phishing_Analyzer.py

# Single URL analysis
python Phishing_Analyzer.py "https://paypa1-secure-login.com/verify"

# Batch mode
python Phishing_Analyzer.py urls.txt
```

### Sample Output

```
=================================================================
  PHISHING ANALYSIS REPORT
  Analyzed: https://paypa1-secure-login.com/verify
=================================================================
  Suspicion Score:   85/100
  Verdict:           🚨 CRITICAL - PHISHING
-----------------------------------------------------------------
  RED FLAGS:
     [+45] Domain impersonates 'paypal' (typosquatting: 1 edit)
     [+35] Domain age: 12 days (very new)
     [+15] Suspicious keyword in URL: 'verify'
=================================================================
```

> **⚠️ Ethical Use:** This tool is for authorized penetration testing and security awareness training only. Do not analyze systems without explicit permission.

---

## 🧠 Skills Developed

| Category | Skills |
|----------|--------|
| **Programming** | Python (pure stdlib, no heavy deps), functional patterns, OOP |
| **Security Concepts** | Password entropy, timing attacks, phishing taxonomy, social engineering |
| **Cryptography** | Caesar cipher, modular arithmetic, symmetric encryption, frequency analysis |
| **Networking** | TCP WHOIS, SSL/TLS, HTTP redirects, DNS record analysis (MX, SPF, DKIM) |
| **Algorithms** | Levenshtein distance, Shannon entropy, homoglyph normalization, scoring engines |
| **CLI Development** | Interactive menus, formatted terminal output, batch processing, argument parsing |
| **Documentation** | Professional READMEs, algorithm walkthroughs, edge-case documentation |

---

## 📁 Repository Structure

```
Shubham22485/
├── password-strength-checker/        # Project 1
│   ├── Password_strength_checker.py  # Main program
│   ├── README.md
│   └── LICENSE
│
├── caesar-cipher/                    # Project 2
│   ├── Encryption___Decryption.py    # Main program
│   ├── README.md
│   └── LICENSE
│
└── phishing-analyzer/                # Project 3
    ├── Phishing_Analyzer.py          # Main program
    ├── README.md
    ├── urls.txt                      # Example batch input
    └── LICENSE
```

---

## ▶️ How to Run

**Prerequisites:** Python 3.6+ (Projects 1 & 2), Python 3.8+ (Project 3)

```bash
# Check your Python version
python --version

# Project 1 — Password Strength Checker
cd password-strength-checker
python Password_strength_checker.py

# Project 2 — Caesar Cipher
cd caesar-cipher
python Encryption___Decryption.py

# Project 3 — Phishing Analyzer
cd phishing-analyzer
pip install dnspython requests   # optional but recommended
python Phishing_Analyzer.py
```

All projects use **zero external dependencies for core functionality** — they run with Python's standard library out of the box.

---

## 👤 Author

**Shubham Kumar**
Cyber Security Intern | Decode Labs | Batch 2026

[![GitHub](https://img.shields.io/badge/GitHub-Shubham22485-black?style=flat-square&logo=github)](https://github.com/Shubham22485)

---

<div align="center">

**Decode Labs** — Your Digital Lab

🌐 [www.decodelabs.tech](https://www.decodelabs.tech) · 📧 hr@decodelabs.tech · 📞 +91 92360 11887

*Govt. Registered Enterprise | Greater Lucknow, India*

</div>
