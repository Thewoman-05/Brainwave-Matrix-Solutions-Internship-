import re
import math
from collections import Counter

# Common weak passwords to check against
COMMON_PASSWORDS = {"password", "123456", "123456789", "qwerty", "abc123", "111111", "password1", "12345678"}

def calculate_entropy(password: str) -> float:
    """Calculate the entropy of the password."""
    if not password:
        return 0.0
    
    char_set_size = 0
    if re.search(r"[a-z]", password):
        char_set_size += 26
    if re.search(r"[A-Z]", password):
        char_set_size += 26
    if re.search(r"[0-9]", password):
        char_set_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        char_set_size += 32  # Approximation for special characters

    entropy = len(password) * math.log2(char_set_size) if char_set_size else 0
    return entropy

def password_strength(password: str) -> str:
    """Assess the strength of a given password."""
    if not password:
        return "Very Weak: Password cannot be empty."

    if password.lower() in COMMON_PASSWORDS:
        return "Very Weak: Commonly used password."

    length = len(password)
    entropy = calculate_entropy(password)

    # Criteria checks
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    # Scoring system
    score = sum([has_lower, has_upper, has_digit, has_special])

    # Strength evaluation
    if length < 6 or entropy < 28:
        return "Weak: Too short or low complexity."
    elif length >= 6 and score >= 2 and entropy >= 36:
        return "Moderate: Can be improved."
    elif length >= 8 and score >= 3 and entropy >= 50:
        return "Strong: Good password."
    elif length >= 12 and score == 4 and entropy >= 60:
        return "Very Strong: Excellent password!"
    else:
        return "Weak: Consider adding more complexity."

if __name__ == "__main__":
    while True:
        password = input("Enter a password to check (or 'exit' to quit): ")
        if password.lower() == 'exit':
            break
        print(password_strength(password))
