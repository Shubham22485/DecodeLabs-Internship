import re
import math
import hmac


# ---------- 1. Common / Leaked Passwords List ---------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789","1234567890", "qwerty", "abc123",
    "password1", "letmein", "welcome", "admin", "iloveyou",
    "monkey", "dragon", "master", "sunshine", "princess",
}


# ---------- 2. Entropy Calculator ---------------------------
def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.
    Formula: entropy = length * log2(pool_size)
    Pythonic approach: any() for O(n) linear scan (as taught in PDF).
    """
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32  # common symbols

    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)

# ---------- 3. Core Strength Checker ------------------------
def check_password_strength(password: str) -> dict:
    """
    Evaluates password and returns a result dict with:
    - strength  : 'Weak' | 'Medium' | 'Strong'
    - score     : int (0-4)
    - entropy   : float (bits)
    - checks    : dict of individual criteria results
    - tips      : list of improvement suggestions
    """

    # --- Individual criteria (Pythonic any() — PDF page 9) ---
    checks = {
        "length_8"   : len(password) >= 8,
        "length_12"  : len(password) >= 12,
        "has_upper"  : any(c.isupper() for c in password),
        "has_lower"  : any(c.islower() for c in password),
        "has_digit"  : any(c.isdigit() for c in password),
        "has_symbol" : any(not c.isalnum() for c in password),
        "not_common" : password.lower() not in COMMON_PASSWORDS,
    }

    # --- Score calculation ---
    score = 0
    if checks["length_8"]:
        score += 1
    if checks["has_upper"] and checks["has_lower"]:
        score += 1
    if checks["has_digit"]:
        score += 1
    if checks["has_symbol"]:
        score += 1

    # Leaked password overrides everything
    if not checks["not_common"]:
        score = 0

    # --- Strength classification ---
    if score == 0:
        strength = "Weak"
    elif score <= 2:
        strength = "Medium"
    else:
        strength = "Strong"

    # --- Improvement tips ---
    tips = []
    if not checks["length_8"]:
        tips.append("Password must be at least 8 characters long.")
    if not checks["has_upper"]:
        tips.append("Password must contain at least one uppercase letter (A-Z).")
    if not checks["has_lower"]:
        tips.append("Password must contain at least one lowercase letter (a-z).")
    if not checks["has_digit"]:
        tips.append("Password must contain at least one digit (0-9).")
    if not checks["has_symbol"]:
        tips.append("Add one or more symbols (!@#$%^&*).")
    if not checks["not_common"]:
        tips.append("This password is leaked! Use a different password!.")
    if checks["length_8"] and not checks["length_12"]:
        tips.append("A 12+ character password will be even more secure.")

    return {
        "strength" : strength,
        "score"    : score,
        "entropy"  : calculate_entropy(password),
        "checks"   : checks,
        "tips"     : tips,
    }


# ---------- 4. Display Result (formatted output) ------------
def display_result(password: str, result: dict) -> None:
    strength = result["strength"]
    score    = result["score"]
    entropy  = result["entropy"]
    checks   = result["checks"]
    tips     = result["tips"]

    icons = {"Weak": "✗", "Medium": "~", "Strong": "✓"}
    colors = {"Weak": "WEAK", "Medium": "MEDIUM", "Strong": "STRONG"}

    bar_filled = "█" * score
    bar_empty  = "░" * (4 - score)

    print("\n" + "=" * 50)
    print(f"  PASSWORD STRENGTH CHECKER — DecodeLabs")
    print("=" * 50)
    print(f"  Strength  : [{bar_filled}{bar_empty}]  {icons[strength]}  {colors[strength]}")
    print(f"  Score     : {score}/4")
    print(f"  Entropy   : {entropy} bits")
    print("-" * 50)
    print("  Criteria Check:")
    criteria_display = {
        "length_8"   : "8+ characters",
        "length_12"  : "12+ characters",
        "has_upper"  : "Uppercase (A-Z)",
        "has_lower"  : "Lowercase (a-z)",
        "has_digit"  : "Number (0-9)",
        "has_symbol" : "Symbol (!@#$...)",
        "not_common" : "Not a leaked password",
    }
    for key, label in criteria_display.items():
        status = "✓ PASS" if checks[key] else "✗ FAIL"
        print(f"    {status}  {label}")

    if tips:
        print("-" * 50)
        print("  Tips to Improve:")
        for tip in tips:
            print(f"    → {tip}")
    print("=" * 50 + "\n")


# ---------- 5. Secure Comparison (Timing Attack defense) ----
def safe_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison using hmac.compare_digest
    Prevents timing attacks (as taught in PDF page 11).
    """
    return hmac.compare_digest(a.encode(), b.encode())


# ---------- 6. Main Program (Input/Process/Output model) ----
def main():
    print("\n  DecodeLabs — Password Strength Checker")
    print("  Project 1 | Batch 2026\n")

    while True:
        password = input(" Enter password to check (or 'quit' to exit): ")

        # Safe comparison using hmac (timing attack safe)
        if safe_compare(password.lower(), "quit"):
            print("\n  The program is closing. Good luck.!\n")
            break

        if not password:
            print(" Password cannot be empty. Please try again.\n")
            continue

        result = check_password_strength(password)
        display_result(password, result)

if __name__ == "__main__":
    main()