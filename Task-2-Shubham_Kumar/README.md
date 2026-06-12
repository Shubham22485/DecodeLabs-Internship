# Caesar Cipher — Basic Encryption & Decryption

![python](https://img.shields.io/badge/python-3.6+-blue) ![license](https://img.shields.io/badge/License-MIT-green) ![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)

A clean, well-documented Python implementation of the classic **Caesar cipher** for educational purposes.
Supports encrypting and decrypting text with arbitrary integer shift values.

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

The **Caesar cipher** is one of the simplest and most widely known encryption techniques. It is a type of **substitution cipher** where each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet.

This project implements a complete Caesar cipher system in Python, including:

- **Encryption** — shifts letters forward by a user-specified amount
- **Decryption** — reverses the shift to recover the original text
- **Interactive CLI** — a simple menu-driven interface
- **Input validation** — handles edge cases gracefully

> **Note:** The Caesar cipher is trivially breakable and should **not** be used for real-world security. This project is intended for **educational purposes** to demonstrate fundamental encryption concepts.

---

## How It Works

### Encryption

For each character in the input text:

| Character Type | Operation |
|---|---|
| Uppercase letter (A–Z) | Shifted forward within A–Z, wraps around at Z |
| Lowercase letter (a–z) | Shifted forward within a–z, wraps around at z |
| Non-alphabetic (spaces, digits, punctuation) | Passed through unchanged |

The shift is **normalized** to the range `0-25` so that any integer (positive, negative, or large) produces predictable results.

### Decryption

Decryption applies the **inverse shift**. If the encryption shift is `s`, the decryption shift is `(26 - s) % 26`, which cleanly reverses the transformation without relying on negative modulo behavior.

---

## Features

- ✅ **Pure Python** — no external dependencies, works with Python 3.6+
- ✅ **Shift normalization** — any integer shift value is handled correctly
- ✅ **Character preservation** — non-alphabetic characters remain untouched
- ✅ **Case preservation** — uppercase and lowercase letters stay in their respective cases
- ✅ **Empty input detection** — gracefully prompts again if no text is entered
- ✅ **Error handling** — invalid shift values default to a shift of `3` with a warning
- ✅ **Clean exit** — option `3` exits the program cleanly

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
git clone https://github.com/Shubham22485/caesar-cipher.git
cd caesar-cipher
```

2. **(Optional) Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate    # Linux / macOS
venv\Scripts\activate       # Windows
```

3. **Run the program**

```bash
python caesar_cipher.py
```

---

## Usage

The program presents an interactive menu:

```
=== Caesar Cipher Encryption & Decryption ===

Options:
  1. Encrypt text
  2. Decrypt text
  3. Exit
```

1. Choose **1** to encrypt or **2** to decrypt
2. Enter the text you want to process
3. Enter an integer shift value
4. View the result

Repeat any number of times, or choose **3** to exit.

---

## Example Run

```
=== Caesar Cipher Encryption & Decryption ===

Options:
  1. Encrypt text
  2. Decrypt text
  3. Exit

Enter your choice (1/2/3): 1
Enter the text: Hello, World!
Enter shift value (integer): 5

Original:  Hello, World!
Encrypted: Mjqqt, Btwqi!

Options:
  1. Encrypt text
  2. Decrypt text
  3. Exit

Enter your choice (1/2/3): 2
Enter the text: Mjqqt, Btwqi!
Enter shift value (integer): 5

Encrypted:  Mjqqt, Btwqi!
Decrypted:  Hello, World!

Options:
  1. Encrypt text
  2. Decrypt text
  3. Exit

Enter your choice (1/2/3): 3
Goodbye!
```

---

## Project Structure

```
caesar-cipher/
├── caesar_cipher.py       # Main program — encryption logic + CLI
├── README.md              # This file
└── LICENSE                # MIT License
```

### Single-file design

The entire implementation lives in one file (`caesar_cipher.py`). This keeps the project minimal and easy to understand — ideal for learning and code review.

---

## Algorithm Details

### `encrypt(text, shift)`

```python
def encrypt(text, shift):
    normalized_shift = shift % 26
    result = []
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + normalized_shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + normalized_shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)
```

**Step-by-step:**

1. **Normalize** the shift to `0-25` using `shift % 26`
2. For each character:
   - Check if it's uppercase, lowercase, or non-alphabetic
   - Convert to a numeric index (`0-25`) by subtracting the base ASCII value
   - Add the normalized shift
   - Apply modulo `26` to wrap around the alphabet
   - Convert back to a character by adding the base ASCII value
3. Return the joined result as a string

---

### `decrypt(text, shift)`

```python
def decrypt(text, shift):
    normalized_shift = shift % 26
    inverse_shift = 26 - normalized_shift if normalized_shift != 0 else 0
    return encrypt(text, inverse_shift)
```

**Step-by-step:**

1. Normalize the shift to `0-25`
2. Compute the **inverse shift**: `(26 - normalized_shift) % 26`
3. Call `encrypt()` with the inverse shift

This approach is cleaner and more explicit than passing a negative shift value.

---

## Edge Cases Handled

| Scenario | Behavior |
|---|---|
| Shift = 0 | Text remains unchanged (identity transformation) |
| Shift = 26 | Text remains unchanged (full wrap-around) |
| Large shift (e.g., 1000) | Shift is normalized to 0–25; works correctly |
| Negative shift | Normalized to positive equivalent (e.g., -5 → 21) |
| Empty string input | User is prompted to enter text again |
| Non-integer shift | Defaults to shift = 3 with a warning message |
| Mixed content (letters, numbers, symbols) | Letters are shifted; everything else is preserved |
| Uppercase / lowercase mixing | Case is preserved independently |

---

## Possible Extensions

Once you're comfortable with the basics, here are ways to extend the project:

| Extension | Description |
|---|---|
| **Brute-force decryption** | Try all 25 possible shifts and display each result so the user can spot the original message |
| **File I/O** | Read plaintext from a file and write ciphertext to a file (or vice versa) |
| **Custom alphabet** | Include digits, punctuation, or a shuffled alphabet for a stronger cipher |
| **Vigenère cipher** | Use a keyword instead of a single shift — each letter gets a different shift |
| **ROT13** | A special case of Caesar cipher with shift = 13 (its own inverse) |
| **Frequency analysis** | Add a tool that analyzes ciphertext letter frequency to automatically break the cipher |
| **GUI version** | Build a simple graphical interface using `tkinter` or a web frontend |
| **Unit tests** | Add a test suite using Python's `unittest` or `pytest` to verify correctness |

---

## Author

**Shubham Kumar** — [Shubham22485](https://github.com/Shubham22485)

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

To get this on GitHub right now:

```bash
# 1. Create a new directory
mkdir caesar-cipher
cd caesar-cipher

# 2. Save the Python code as caesar_cipher.py
# 3. Save the README above as README.md
# 4. Save the MIT License as LICENSE (optional but recommended)

# 5. Initialize git and push
git init
git add .
git commit -m "Initial commit: Caesar cipher encryption/decryption"
git remote add origin https://github.com/Shubham22485/caesar-cipher.git
git push -u origin main
```
