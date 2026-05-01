"""
utils.py - Phishing Detection Logic
-----------------------------------
Contains core logic for analyzing URLs using a rule-based scoring system.
"""

import re
from urllib.parse import urlparse


def has_ip_address(url: str) -> bool:
    """Check if URL contains an IP address instead of domain."""
    return bool(re.search(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url))


def is_long_url(url: str) -> bool:
    """Check if URL is unusually long."""
    return len(url) > 75


def has_suspicious_words(url: str) -> bool:
    """Check for common phishing keywords."""
    suspicious_keywords = [
        "login", "verify", "update", "secure", "account",
        "bank", "password", "confirm", "signin", "wallet"
    ]
    return any(word in url.lower() for word in suspicious_keywords)


def has_too_many_dots(url: str) -> bool:
    """Check if URL contains too many dots (subdomains)."""
    return url.count('.') > 4


def has_at_symbol(url: str) -> bool:
    """Check for '@' symbol which can obscure real domain."""
    return '@' in url


def analyze_url(url: str) -> dict:
    """Main function to analyze URL and return risk assessment."""
    score = 0
    flags = []

    # Rule 1: IP Address
    if has_ip_address(url):
        score += 2
        flags.append("URL uses IP address instead of domain")

    # Rule 2: Long URL
    if is_long_url(url):
        score += 1
        flags.append("URL is unusually long")

    # Rule 3: Suspicious Keywords
    if has_suspicious_words(url):
        score += 2
        flags.append("Contains suspicious keywords (e.g. login, verify)")

    # Rule 4: Too many dots
    if has_too_many_dots(url):
        score += 1
        flags.append("Too many subdomains detected")

    # Rule 5: '@' symbol
    if has_at_symbol(url):
        score += 2
        flags.append("Contains '@' symbol which can hide real domain")

    # Determine risk level
    if score <= 1:
        level = "safe"
        verdict = "Safe"
        icon = "✅"
    elif score <= 3:
        level = "suspicious"
        verdict = "Suspicious"
        icon = "⚠️"
    else:
        level = "phishing"
        verdict = "Phishing"
        icon = "❌"

    # If no flags found
    if not flags:
        flags.append("No major phishing indicators detected")

    return {
        "url": url,
        "score": score,
        "level": level,
        "verdict": verdict,
        "icon": icon,
        "flags": flags
    }
