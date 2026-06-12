# Password Strength Checker — DecodeLabs

A clean, well-documented Python implementation of a **Password Strength Checker** for educational purposes.
Evaluates password security using entropy calculation, criteria checks, and a leaked-password detection system.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Example Run](#example-run)
- [Project Structure](#project-structure)
- [Algorithm Details](#algorithm-details)
- [Edge Cases Handled](#edge-cases-handled)
- [Possible Extensions](#possible-extensions)
- [Author](#author)
- [License](#license)

---

## Overview

This project builds a complete **Password Strength Checker** in Python that analyzes any password and gives instant feedback. It uses entropy-based scoring, multi-criteria checks, and a built-in leaked password list to help users understand how secure their passwords really are.

This project implements:

- **Entropy calculation** — estimates password strength in bits
- **Criteria-based scoring** — checks length, case, digits, symbols
- **Leaked password detection** — flags common/known passwords
- **Interactive CLI** — a clean menu-driven terminal interface
- **Timing attack defense** — uses `hmac.compare_digest` for safe comparison

> **Note:** This project is intended for **educational purposes** to demonstrate fundamental security concepts. Do not use this as a production authentication system.

---

## How It Works

### Scoring System

The password is evaluated against 4 criteria, each worth 1 point:

| Criteria | Condition |
|---|---|
| Length | 8+ characters |
| Case Mix | Has both uppercase (A-Z) and lowercase (a-z) |
| Digit | Contains at least one number (0-9) |
| Symbol | Contains at least one special character (!@#$...) |

### Strength Classification

| Score | Strength |
|---|---|
| 0 | ⚠️ Weak |
| 1 – 2 | ~ Medium |
| 3 – 4 | ✓ Strong |

> If the password is found in the **leaked passwords list**, the score is forced to `0` regardless of other criteria.

### Entropy Calculation

Entropy is calculated using the formula:

```
entropy = length × log₂(pool_size)
```

The pool size is determined by which character sets are used:

| Character Set | Pool Size |
|---|---|
| Lowercase (a-z) | +26 |
| Uppercase (A-Z) | +26 |
| Digits (0-9) | +10 |
| Symbols | +32 |

Higher entropy = harder to crack by brute force.

---

## Features

- ✅ **Pure Python** — no external dependencies except built-in `re`, `math`, `hmac`
- ✅ **Entropy-based analysis** — estimates bits of security
- ✅ **Multi-criteria scoring** — 4 independent checks, score out of 4
- ✅ **Leaked password detection** — flags 15+ common passwords instantly
- ✅ **Improvement tips** — tells the user exactly what to fix
- ✅ **Timing attack defense** — `hmac.compare_digest` prevents side-channel attacks
- ✅ **Visual strength bar** — `████░` progress bar in the terminal
- ✅ **Loop mode** — check multiple passwords without restarting
- ✅ **Empty input detection** — gracefully prompts again if nothing is entered
- ✅ **Clean exit** — type `quit` to exit safely

---

## Getting Started

### Prerequisites

- **Python 3.6 or higher** installed on your system

To check your Python version:

```bash
python --version
```

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/Shubham22485/password-strength-checker.git
cd password-strength-checker
```

2. **(Optional) Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows
```

3. **Run the program**

```bash
python Password_strength_checker.py
```

---

## Usage

When you run the program, it shows a prompt in a loop:

```
  DecodeLabs — Password Strength Checker
  Project 1 | Batch 2026

 Enter password to check (or 'quit' to exit):
```

- Type any password and press **Enter** to see the analysis
- Repeat as many times as you want
- Type `quit` to exit the program

---

## Example Run

### Weak Password (leaked)

```
 Enter password to check (or 'quit' to exit): password

==================================================
  PASSWORD STRENGTH CHECKER — DecodeLabs
==================================================
  Strength  : [░░░░]  ✗  WEAK
  Score     : 0/4
  Entropy   : 37.6 bits
--------------------------------------------------
  Criteria Check:
    ✓ PASS  8+ characters
    ✗ FAIL  12+ characters
    ✗ FAIL  Uppercase (A-Z)
    ✓ PASS  Lowercase (a-z)
    ✗ FAIL  Number (0-9)
    ✗ FAIL  Symbol (!@#$...)
    ✗ FAIL  Not a leaked password
--------------------------------------------------
  Tips to Improve:
    → Password must contain at least one uppercase letter (A-Z).
    → Password must contain at least one digit (0-9).
    → Add one or more symbols (!@#$%^&*).
    → This password is leaked! Use a different password!.
    → A 12+ character password will be even more secure.
==================================================
```

### Strong Password

```
 Enter password to check (or 'quit' to exit): MyS3cur3@Pass!

==================================================
  PASSWORD STRENGTH CHECKER — DecodeLabs
==================================================
  Strength  : [████]  ✓  STRONG
  Score     : 4/4
  Entropy   : 92.68 bits
--------------------------------------------------
  Criteria Check:
    ✓ PASS  8+ characters
    ✓ PASS  12+ characters
    ✓ PASS  Uppercase (A-Z)
    ✓ PASS  Lowercase (a-z)
    ✓ PASS  Number (0-9)
    ✓ PASS  Symbol (!@#$...)
    ✓ PASS  Not a leaked password
==================================================
```

---

## Project Structure

```
password-strength-checker/
├── Password_strength_checker.py               # Main program — all logic + CLI
├── README.md                                  # This file
└── LICENSE                                    # MIT License
```

### Single-file design

The entire implementation lives in one file. This keeps the project minimal and easy to understand — ideal for learning and code review.

---

## Algorithm Details

### `calculate_entropy(password)`

```python
def calculate_entropy(password: str) -> float:
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)
```

Uses Python's `any()` for efficient O(n) linear scanning to detect character sets.

---

### `check_password_strength(password)`

Runs all criteria checks, calculates the score, classifies strength, and generates improvement tips. Returns a structured `dict` with keys: `strength`, `score`, `entropy`, `checks`, `tips`.

---

### `safe_compare(a, b)`

```python
def safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
```

Uses Python's built-in `hmac.compare_digest` for **constant-time string comparison** — this prevents **timing attacks** where an attacker could guess characters by measuring how long a comparison takes.

---

## Edge Cases Handled

| Scenario | Behavior |
|---|---|
| Empty input | User is prompted to enter a password again |
| Leaked / common password | Score forced to 0, flagged as Weak with a tip |
| Password with only symbols | Entropy calculated correctly, criteria checked individually |
| Very long password | Works correctly; higher entropy reported |
| Mixed case + digits + symbols | Full score of 4/4 and Strong classification |
| `quit` as input | Program exits cleanly using `safe_compare` |
| Uppercase `QUIT` input | Handled via `.lower()` before comparison |

---

## Possible Extensions

| Extension | Description |
|---|---|
| **Larger leaked password list** | Load from `rockyou.txt` or HaveIBeenPwned API |
| **Password generator** | Auto-generate a strong password meeting all criteria |
| **GUI version** | Build a graphical interface using `tkinter` or a web frontend |
| **File input** | Check a batch of passwords from a `.txt` file |
| **Vigenère / hash demo** | Show what a hashed password looks like (SHA-256) |
| **Unit tests** | Add a test suite using Python's `unittest` or `pytest` |
| **Zxcvbn integration** | Use Dropbox's `zxcvbn` library for advanced pattern analysis |
| **Colorized output** | Use `colorama` library to add colors to the terminal output |

---

## Author

**Shubham Kumar** — [@Shubham22485](https://github.com/Shubham22485)

Project completed as part of **DecodeLabs | Batch 2026** to explore fundamental cybersecurity and Python programming concepts.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 [Your Name]

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

### Quick Setup Instructions

```bash
# 1. Create a new directory
mkdir password-strength-checker
cd password-strength-checker

# 2. Save the Python file
# 3. Save this README as README.md
# 4. Save the MIT License as LICENSE

# 5. Initialize git and push
git init
git add .
git commit -m "Initial commit: Password strength checker"
git remote add origin https://github.com/Shubham22485/password-strength-checker.git
git push -u origin main
```