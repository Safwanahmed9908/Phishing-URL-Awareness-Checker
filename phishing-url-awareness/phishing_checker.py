#!/usr/bin/env python3
"""
Phishing URL Awareness Checker
-------------------------------------------------------------------------
Author: Cybersecurity Student / Project Developer
Project: EWB Edutech Cybersecurity Mini Project
Technology: Python 3.10+ (Standard Library only)

Objective:
    An educational defensive cybersecurity tool that inspects URL text
    locally and identifies common structural, contextual, and textual warning
    signs frequently used in phishing attacks.

Detection Architecture:
    - URL validation and normalization using standard urllib.parse
    - Multi-factor weighted risk scoring (0-100 points)
    - Verified trusted domain recognition (exact domain/subdomain matching)
    - Brand impersonation and subdomain spoofing detection
    - Typosquatting and lookalike domain detection
    - Raw IP address hostname detection (IPv4 / IPv6 / Hex / Octal)
    - Punycode (xn--) IDN homograph attack indicator
    - Deceptive '@' symbol userinfo spoofing
    - Excessive subdomain segmentation
    - Insecure HTTP protocol analysis
    - Suspicious credential-stealing and verification keywords
    - URL encoding and obfuscated character analysis
    - Informational URL length evaluation (never flags on length alone)

Security Notice:
    - Analyzes URL text strictly through local string parsing.
    - Never connects to, visits, or sends requests to any URL.
    - Does not use external APIs or live scanners.
    - Does not collect or transmit any sensitive data.
    - The absence of warning signs does NOT guarantee that a URL is safe.
-------------------------------------------------------------------------
"""

import sys
import os
import re
import ipaddress
from urllib.parse import urlparse, unquote


# =============================================================================
# ANSI COLOR CODES (For Clean Terminal Presentation)
# =============================================================================
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_MAGENTA = "\033[95m"
COLOR_BLUE = "\033[94m"
COLOR_GRAY = "\033[90m"


# =============================================================================
# TRUSTED DOMAINS & BRAND PROTECTION DATABASE (Local Reference)
# =============================================================================
# Structured dictionary mapping recognized organizations to their authentic domains.
TRUSTED_ORGANIZATIONS = {
    "Google": {
        "domains": [
            "google.com", "blog.google", "google.co.in", "google.co.uk",
            "youtube.com", "gmail.com", "android.com", "google.org", "gstatic.com"
        ],
        "keywords": ["google", "gmail", "youtube", "android", "gstatic"]
    },
    "Microsoft": {
        "domains": [
            "microsoft.com", "live.com", "office.com", "azure.com",
            "github.com", "bing.com", "outlook.com", "microsoftonline.com"
        ],
        "keywords": ["microsoft", "office365", "azure", "outlook", "github"]
    },
    "Apple": {
        "domains": ["apple.com", "icloud.com"],
        "keywords": ["apple", "icloud", "appstore", "appleid"]
    },
    "Amazon": {
        "domains": ["amazon.com", "aws.amazon.com", "amazon.co.uk", "amazon.in"],
        "keywords": ["amazon", "primevideo"]
    },
    "Wikipedia": {
        "domains": ["wikipedia.org", "wikimedia.org"],
        "keywords": ["wikipedia", "wikimedia"]
    },
    "PayPal": {
        "domains": ["paypal.com"],
        "keywords": ["paypal"]
    },
    "Banking / Financial Institutions": {
        "domains": ["chase.com", "wellsfargo.com", "bankofamerica.com"],
        "keywords": ["chase", "wellsfargo", "bankofamerica"]
    },
    "Social Platforms": {
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "twitter.com", "x.com"],
        "keywords": ["facebook", "instagram", "whatsapp", "linkedin"]
    }
}

# Known common typosquatting patterns mimicking high-value brands
TYPOSQUAT_PATTERNS = {
    "g00gle": "Google",
    "googel": "Google",
    "goolge": "Google",
    "micros0ft": "Microsoft",
    "micosoft": "Microsoft",
    "paypa1": "PayPal",
    "paypаl": "PayPal",  # Cyrillic lookalike
    "amaz0n": "Amazon",
    "app1e": "Apple",
    "faceb00k": "Facebook",
    "netfl1x": "Netflix"
}

# Multi-part Top Level Domains for accurate base domain extraction
COMMON_TWO_PART_TLDS = {
    "co.uk", "co.in", "com.au", "co.nz", "co.jp", "com.br",
    "gov.in", "edu.in", "org.uk", "ac.uk", "net.au", "org.in"
}

# Suspicious credential / verification keywords
SUSPICIOUS_KEYWORDS = [
    "verify-account", "update-account", "secure-login", "confirm-identity",
    "banking-login", "account-verification", "password-reset", "wallet-connect",
    "security-update", "suspend-alert", "billing-problem"
]

# Local Threat Intelligence Reference (Simulated offline database for testing)
LOCAL_THREAT_BLOCKLIST = {
    "http://192.0.2.1/login": "Known phishing simulation test fixture (IP login portal)",
    "http://malware-sample.invalid/payload.exe": "Simulated malware distribution link"
}


# =============================================================================
# HELPER FUNCTIONS: PARSING & DOMAIN EXTRACTION
# =============================================================================
def is_ip_address(host: str) -> bool:
    """
    Check if the given host string is a numerical IPv4 or IPv6 address.
    """
    if not host:
        return False
    cleaned_host = host.strip("[]").split(":")[0]
    try:
        ipaddress.ip_address(cleaned_host)
        return True
    except ValueError:
        return False


def extract_registered_domain(hostname: str) -> str:
    """
    Extract the registered base domain (e.g., 'example.com' or 'example.co.uk')
    from an arbitrary hostname.
    
    Examples:
      - 'blog.google' -> 'blog.google'
      - 'login.sub.example.co.uk' -> 'example.co.uk'
      - 'google.com.fake-example.com' -> 'fake-example.com'
    """
    if not hostname or is_ip_address(hostname):
        return hostname

    parts = hostname.lower().strip(".").split(".")
    if len(parts) <= 1:
        return hostname

    # Handle multi-part TLDs (e.g. .co.uk, .gov.in)
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in COMMON_TWO_PART_TLDS:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def identify_trusted_organization(hostname: str) -> tuple[str | None, str | None]:
    """
    Check if the hostname matches an official verified organization domain.
    Requires exact domain match or legitimate subdomain of the registered domain.
    
    Returns:
        tuple: (org_name, matched_domain) or (None, None)
    """
    if not hostname or is_ip_address(hostname):
        return None, None

    clean_host = hostname.lower().strip(".")
    reg_domain = extract_registered_domain(clean_host)

    for org_name, data in TRUSTED_ORGANIZATIONS.items():
        for trusted_dom in data["domains"]:
            # Exact match: blog.google == blog.google, or google.com == google.com
            if clean_host == trusted_dom:
                return org_name, trusted_dom
            # Subdomain of trusted domain: mail.google.com -> ends with .google.com
            if clean_host.endswith("." + trusted_dom) and reg_domain == extract_registered_domain(trusted_dom):
                return org_name, trusted_dom

    return None, None


# =============================================================================
# CORE DETECTION ENGINE & RISK SCORING
# =============================================================================
def analyze_url(raw_url: str) -> dict:
    """
    Analyze a URL string using multi-factor heuristics and intelligent risk scoring.
    
    Risk Score System (0 to 100):
      - 0 - 14  : LOW RISK (No significant suspicious indicators)
      - 15 - 39 : MODERATE RISK (Some suspicious indicators requiring attention)
      - 40 - 69 : HIGH RISK (Multiple strong phishing indicators)
      - 70 - 100: CRITICAL RISK (Strong evidence of a known malicious/phishing URL)
      
    Guiding Rules:
      - URL length alone NEVER pushes a URL into Moderate or High risk.
      - Official trusted domains receive verified recognition and confidence credit.
      - Brand impersonation (e.g. google.com in subdomains of fake-example.com) is heavily penalized.
    """
    if raw_url is None:
        return {
            "url": "",
            "valid": False,
            "error": "No URL provided.",
            "risk_score": 0,
            "risk_level": "INVALID",
            "warnings": [],
            "parsed_details": {}
        }

    url = raw_url.strip()
    if not url:
        return {
            "url": "",
            "valid": False,
            "error": "URL cannot be empty or only whitespace.",
            "risk_score": 0,
            "risk_level": "INVALID",
            "warnings": [],
            "parsed_details": {}
        }

    # Safe normalization and scheme parsing
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    parse_target = url if has_scheme else f"http://{url}"

    try:
        parsed = urlparse(parse_target)
    except Exception as e:
        return {
            "url": url,
            "valid": False,
            "error": f"Malformed URL syntax: {str(e)}",
            "risk_score": 0,
            "risk_level": "INVALID",
            "warnings": [],
            "parsed_details": {}
        }

    scheme = parsed.scheme.lower() if has_scheme else "none"
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    url_length = len(url)

    registered_domain = extract_registered_domain(hostname)
    recognized_org, recognized_dom = identify_trusted_organization(hostname)

    warnings = []
    risk_score = 0

    # -------------------------------------------------------------------------
    # CHECK 0: Known Threat Intelligence Blocklist (Offline Reference)
    # -------------------------------------------------------------------------
    if url in LOCAL_THREAT_BLOCKLIST:
        threat_detail = LOCAL_THREAT_BLOCKLIST[url]
        warnings.append({
            "rule": "Threat Intelligence Match",
            "severity": "CRITICAL",
            "points": 80,
            "finding": f"URL matches a known threat simulation fixture: {threat_detail}.",
            "explanation": "This URL has been flagged in local threat intelligence records as associated with malicious activity."
        })
        risk_score += 80

    # -------------------------------------------------------------------------
    # CHECK 1: Protocol Analysis (HTTPS vs HTTP)
    # -------------------------------------------------------------------------
    if scheme == "http":
        warnings.append({
            "rule": "Insecure Protocol (HTTP)",
            "severity": "MODERATE",
            "points": 20,
            "finding": "The URL uses unencrypted 'http://' rather than secure 'https://'.",
            "explanation": (
                "Traffic sent over HTTP is unencrypted and vulnerable to interception "
                "or eavesdropping (Man-in-the-Middle attacks). Legitimate organizations, "
                "especially login and banking portals, enforce HTTPS encryption."
            )
        })
        risk_score += 20
    elif scheme == "none":
        warnings.append({
            "rule": "Missing Protocol Scheme",
            "severity": "INFORMATIONAL",
            "points": 0,
            "finding": "No protocol prefix (e.g. 'https://') was specified.",
            "explanation": "A URL without an explicit protocol will default to client settings."
        })
    elif scheme not in ("https", "http"):
        warnings.append({
            "rule": "Non-Standard Protocol",
            "severity": "MODERATE",
            "points": 20,
            "finding": f"The URL uses an unconventional scheme: '{scheme}://'.",
            "explanation": "Phishing campaigns may use non-standard schemes to invoke external handlers."
        })
        risk_score += 20

    # -------------------------------------------------------------------------
    # CHECK 2: Deceptive '@' Symbol (Userinfo Spoofing)
    # -------------------------------------------------------------------------
    if "@" in url:
        warnings.append({
            "rule": "Deceptive '@' Symbol Detected",
            "severity": "HIGH",
            "points": 50,
            "finding": f"The URL contains an '@' character. True destination host is '{hostname}'.",
            "explanation": (
                "In standard URL syntax, characters before '@' represent user credentials "
                "(userinfo), while the destination host appears after '@'. Attackers "
                "abuse this trick (e.g. 'http://trusted.com@attacker.com') so victims "
                "mistakenly believe they are visiting the domain before the '@'."
            )
        })
        risk_score += 50

    # -------------------------------------------------------------------------
    # CHECK 3: Raw IP Address Used as Hostname
    # -------------------------------------------------------------------------
    if is_ip_address(hostname):
        warnings.append({
            "rule": "Raw IP Address Used as Hostname",
            "severity": "HIGH",
            "points": 50,
            "finding": f"The hostname '{hostname}' is a numerical IP address instead of a domain name.",
            "explanation": (
                "Reputable organizations utilize domain names linked to digital certificates. "
                "Attackers often use raw IP addresses directly to avoid domain registration, "
                "bypass domain-name blacklists, or evade DNS reputation systems."
            )
        })
        risk_score += 50

    # -------------------------------------------------------------------------
    # CHECK 4: Brand Impersonation & Subdomain Spoofing
    # -------------------------------------------------------------------------
    # Detects trick where brand domain is placed in subdomains of an unrelated domain
    # e.g., 'google.com.fake-example.com' (registered domain is fake-example.com)
    if not is_ip_address(hostname) and registered_domain:
        for org, data in TRUSTED_ORGANIZATIONS.items():
            for official_dom in data["domains"]:
                # If the official domain string is in hostname, but registered domain is DIFFERENT:
                if official_dom in hostname and registered_domain != official_dom and not registered_domain.endswith("." + official_dom):
                    warnings.append({
                        "rule": f"Brand Subdomain Spoofing ({org})",
                        "severity": "HIGH",
                        "points": 50,
                        "finding": f"The hostname mimics '{official_dom}' inside an unrelated registered domain '{registered_domain}'.",
                        "explanation": (
                            f"Attackers prepend authentic brand domains as subdomains "
                            f"(e.g., '{official_dom}.{registered_domain}') to fool users into trusting the link."
                        )
                    })
                    risk_score += 50
                    break

    # -------------------------------------------------------------------------
    # CHECK 5: Brand Typosquatting / Lookalike Domain
    # -------------------------------------------------------------------------
    if not is_ip_address(hostname) and registered_domain:
        for typo, brand in TYPOSQUAT_PATTERNS.items():
            if typo in registered_domain:
                warnings.append({
                    "rule": f"Suspected Typosquatting ({brand})",
                    "severity": "HIGH",
                    "points": 45,
                    "finding": f"The domain '{registered_domain}' contains '{typo}', a known lookalike spelling of {brand}.",
                    "explanation": (
                        "Typosquatting targets users who make typing mistakes or misread characters "
                        "(e.g. substituting '0' for 'o' or '1' for 'l') to spoof trusted brand names."
                    )
                })
                risk_score += 45
                break

    # -------------------------------------------------------------------------
    # CHECK 6: Punycode Encoding Marker ('xn--') [IDN Homograph Attack]
    # -------------------------------------------------------------------------
    if "xn--" in url.lower():
        warnings.append({
            "rule": "Punycode Encoding Marker ('xn--')",
            "severity": "HIGH",
            "points": 45,
            "finding": "The URL contains a Punycode prefix ('xn--').",
            "explanation": (
                "Punycode represents non-ASCII Unicode characters using ASCII text. "
                "Cybercriminals use Punycode to carry out 'IDN Homograph Attacks', "
                "registering domains with lookalike characters (such as Cyrillic 'а' "
                "instead of Latin 'a') to create visual duplicates of trusted domains."
            )
        })
        risk_score += 45

    # -------------------------------------------------------------------------
    # CHECK 7: Excessive Hostname Segments (>= 5 segments)
    # -------------------------------------------------------------------------
    if not is_ip_address(hostname) and hostname:
        clean_hostname = hostname.rstrip(".")
        segments = clean_hostname.split(".")
        if len(segments) >= 5:
            warnings.append({
                "rule": "Excessive Hostname Segments",
                "severity": "MODERATE",
                "points": 20,
                "finding": f"The hostname contains {len(segments)} segments ({clean_hostname}).",
                "explanation": (
                    "Legitimate commercial domains typically have 2 to 3 segments "
                    "(e.g. 'login.company.com'). Deep subdomain chains "
                    "(e.g. 'a.b.c.d.e.target.xyz') are frequently used on dynamic DNS services."
                )
            })
            risk_score += 20

    # -------------------------------------------------------------------------
    # CHECK 8: URL Encoding / Obfuscated Characters
    # -------------------------------------------------------------------------
    # Check for encoded spaces (%20), script tags, or excessive hex encoding in path
    if "%20" in url or "%3c" in url.lower() or "%3e" in url.lower() or len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 3:
        warnings.append({
            "rule": "Suspicious URL Character Encoding",
            "severity": "MODERATE",
            "points": 25,
            "finding": "URL contains encoded whitespace or multiple hexadecimal escape sequences.",
            "explanation": (
                "Phishing links often encode spaces or script delimiters (%20, %3C, %3E) to "
                "obfuscate payloads or bypass basic URL keyword inspection filters."
            )
        })
        risk_score += 25

    # -------------------------------------------------------------------------
    # CHECK 9: Suspicious Login / Verification Keywords
    # -------------------------------------------------------------------------
    lower_url = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    if matched_keywords and not recognized_org:
        # If suspicious keywords exist on an unverified domain
        kw_str = ", ".join(matched_keywords[:3])
        # Higher penalty if combined with HTTP or IP
        pts = 25 if (scheme == "http" or is_ip_address(hostname)) else 15
        sev = "HIGH" if pts == 25 else "MODERATE"
        warnings.append({
            "rule": "Suspicious Verification Keywords",
            "severity": sev,
            "points": pts,
            "finding": f"URL contains sensitive authentication/verification keywords: [{kw_str}].",
            "explanation": (
                "Attackers lure victims with urgency keywords such as 'verify-account' or "
                "'update-password' on third-party domains to steal login credentials."
            )
        })
        risk_score += pts

    # -------------------------------------------------------------------------
    # CHECK 10: Open Redirect / Multiple Protocol Indicators
    # -------------------------------------------------------------------------
    # Detect embedded secondary protocols in path/query (e.g. ?redirect=https://...)
    if re.search(r"[?&/](?:redirect|url|dest|goto)=https?://", url, re.IGNORECASE) or url.count("http://") + url.count("https://") > 1:
        warnings.append({
            "rule": "Open Redirect / Embedded Protocol Detected",
            "severity": "MODERATE",
            "points": 25,
            "finding": "URL contains a secondary HTTP/HTTPS protocol in the query or path.",
            "explanation": (
                "Open redirects allow attackers to leverage a seemingly trusted domain to "
                "forward victims to an external malicious destination."
            )
        })
        risk_score += 25

    # -------------------------------------------------------------------------
    # CHECK 11: URL Length (Informational Feature - NEVER flags on length alone)
    # -------------------------------------------------------------------------
    # Important Requirement: URL length alone must NEVER classify a URL as phishing
    # or increase risk to Moderate or High!
    if url_length > 100:
        if risk_score > 0:
            # If OTHER suspicious indicators already exist, note length with minor weight
            warnings.append({
                "rule": "Long URL with Suspicious Indicators",
                "severity": "LOW",
                "points": 5,
                "finding": f"The URL length is {url_length} characters (exceeds 100 chars alongside other warning signs).",
                "explanation": (
                    "When combined with other indicators, excessive URL length can be used to "
                    "push malicious components off-screen on mobile browsers."
                )
            })
            risk_score += 5
        else:
            # Standalone long URL on clean domain: STRICTLY INFORMATIONAL (0 points)
            warnings.append({
                "rule": "URL Length (Informational Only)",
                "severity": "INFORMATIONAL",
                "points": 0,
                "finding": f"The URL length is {url_length} characters. This is normal for article links and deep research paths.",
                "explanation": (
                    "Long URLs are standard across legitimate news portals, research blogs, "
                    "and documentation sites. Length alone is NOT an indicator of malicious activity."
                )
            })

    # -------------------------------------------------------------------------
    # TRUSTED DOMAIN RECOGNITION CONFIDENCE CREDIT
    # -------------------------------------------------------------------------
    if recognized_org:
        # Official verified domain discount (only applied if not overridden by severe @ or blocklist)
        if risk_score > 0 and risk_score < 50:
            risk_score = max(0, risk_score - 15)

    # -------------------------------------------------------------------------
    # FINAL RISK CLASSIFICATION & ADVISORY
    # -------------------------------------------------------------------------
    risk_level, risk_color, risk_message, recommended_action = compute_risk_classification(risk_score, warnings)

    parsed_details = {
        "scheme": scheme,
        "hostname": hostname,
        "registered_domain": registered_domain or hostname,
        "recognized_organization": f"{recognized_org} (Official Domain)" if recognized_org else "Standard Domain",
        "is_trusted": bool(recognized_org),
        "path": path,
        "length": url_length,
        "risk_score": risk_score,
        "total_warnings": len(warnings)
    }

    return {
        "url": url,
        "valid": True,
        "error": None,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "risk_message": risk_message,
        "recommended_action": recommended_action,
        "warnings": warnings,
        "parsed_details": parsed_details
    }


def compute_risk_classification(risk_score: int, warnings: list) -> tuple[str, str, str, str]:
    """
    Map weighted numerical risk score (0-100) to clear classification and user advisory.
    
    Returns:
        tuple: (risk_level, color_code, result_message, recommended_action)
    """
    if risk_score >= 70:
        return (
            "CRITICAL RISK",
            COLOR_RED,
            "Strong evidence of a malicious URL was identified. Do not open this link.",
            "BLOCK OR CLOSE THIS LINK IMMEDIATELY. High probability of credential theft or exploit."
        )
    elif risk_score >= 40:
        return (
            "HIGH RISK",
            COLOR_RED,
            "Multiple suspicious indicators were detected. Avoid entering personal or financial information.",
            "DO NOT ENTER PASSWORDS, credit cards, or personal data on this page. Verify via official channels."
        )
    elif risk_score >= 15:
        return (
            "MODERATE RISK",
            COLOR_YELLOW,
            "Some suspicious URL patterns were detected. Verify the website before proceeding.",
            "EXERCISE CAUTION. Inspect the destination domain carefully before providing any credentials."
        )
    else:
        return (
            "LOW RISK",
            COLOR_GREEN,
            "No significant suspicious URL patterns were detected. This does not guarantee that the website is safe.",
            "You may proceed with normal caution. Always check the browser address bar for official domain spelling."
        )


def display_results(result: dict) -> None:
    """
    Print a clean, well-formatted terminal report of the URL analysis.
    """
    print()
    print(f"{COLOR_CYAN}{'=' * 75}{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}                PHISHING URL ANALYSIS REPORT{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'=' * 75}{COLOR_RESET}")

    if not result.get("valid"):
        print(f"\n{COLOR_RED}[!] ERROR:{COLOR_RESET} {result.get('error', 'Invalid input')}")
        print(f"{COLOR_GRAY}{'-' * 75}{COLOR_RESET}")
        return

    url = result["url"]
    details = result["parsed_details"]
    warnings = result["warnings"]
    risk_level = result["risk_level"]
    risk_color = result["risk_color"]
    risk_score = result["risk_score"]

    print(f"\n{COLOR_BOLD}Target URL:{COLOR_RESET}       {url}")
    print(f"{COLOR_BOLD}Protocol:{COLOR_RESET}         {details['scheme']}://")
    print(f"{COLOR_BOLD}Hostname:{COLOR_RESET}         {details['hostname'] or '[None Extracted]'}")
    print(f"{COLOR_BOLD}Registered Domain:{COLOR_RESET}{details['registered_domain']}")
    print(f"{COLOR_BOLD}Organization:{COLOR_RESET}     {details['recognized_organization']}")
    print(f"{COLOR_BOLD}URL Length:{COLOR_RESET}       {details['length']} characters")
    print(f"{COLOR_BOLD}Risk Score:{COLOR_RESET}       {risk_color}{COLOR_BOLD}{risk_score} / 100{COLOR_RESET}")
    print(f"{COLOR_BOLD}Risk Level:{COLOR_RESET}       {risk_color}{COLOR_BOLD}[ {risk_level} ]{COLOR_RESET}")
    print(f"{COLOR_BOLD}Indicators:{COLOR_RESET}       {len(warnings)} detected\n")

    print(f"{COLOR_GRAY}{'-' * 75}{COLOR_RESET}")
    print(f"{COLOR_BOLD}ASSESSMENT SUMMARY:{COLOR_RESET} {result['risk_message']}")
    print(f"{COLOR_BOLD}RECOMMENDED ACTION:{COLOR_RESET} {result['recommended_action']}")
    print(f"{COLOR_GRAY}{'-' * 75}{COLOR_RESET}")

    if not warnings:
        print(f"{COLOR_GREEN}  [✓] No suspicious structural phishing patterns were detected.{COLOR_RESET}")
        print("      The URL follows standard HTTPS naming conventions and clean domain structure.")
    else:
        print(f"\n{COLOR_BOLD}DETECTION FINDINGS & EXPLANATIONS:{COLOR_RESET}")
        for idx, item in enumerate(warnings, start=1):
            sev = item["severity"]
            if sev == "CRITICAL" or sev == "HIGH":
                sev_color = COLOR_RED
            elif sev == "MODERATE":
                sev_color = COLOR_YELLOW
            elif sev == "INFORMATIONAL":
                sev_color = COLOR_CYAN
            else:
                sev_color = COLOR_BLUE

            pts_label = f"(+{item.get('points', 0)} pts)" if item.get('points', 0) > 0 else "(0 pts)"
            print(f"\n  {COLOR_BOLD}{idx}. [{sev_color}{sev}{COLOR_RESET}{COLOR_BOLD}] {item['rule']} {COLOR_GRAY}{pts_label}{COLOR_RESET}")
            print(f"     • {COLOR_BOLD}Finding:{COLOR_RESET}     {item['finding']}")
            print(f"     • {COLOR_BOLD}Explanation:{COLOR_RESET} {item['explanation']}")

    # Educational Footer & Security Warning
    print(f"\n{COLOR_CYAN}{'=' * 75}{COLOR_RESET}")
    print(f"{COLOR_YELLOW}{COLOR_BOLD}SECURITY ADVISORY:{COLOR_RESET}")
    print("  • The absence of warning signs does NOT guarantee that a URL is safe.")
    print("  • Phishing websites frequently purchase genuine SSL/TLS certificates and")
    print("    standard domains to look legitimate.")
    print("  • Always inspect URLs carefully and verify links through official bookmarks")
    print("    or direct navigation rather than clicking unsolicited messages.")
    print(f"{COLOR_CYAN}{'=' * 75}{COLOR_RESET}\n")


# =============================================================================
# REALISTIC & WORKBOOK TEST SUITE
# =============================================================================
SAMPLE_TEST_CASES = [
    {
        "category": "Official Workbook - Benign",
        "url": "https://www.example.com/login",
        "expected": "LOW RISK",
        "description": "Legitimate standard HTTPS URL"
    },
    {
        "category": "Official Workbook - Raw IP",
        "url": "http://192.0.2.10/account",
        "expected": "CRITICAL RISK",  # 70 pts: HTTP (20) + Raw IP (50)
        "description": "IP address hostname with HTTP"
    },
    {
        "category": "Official Workbook - Userinfo '@'",
        "url": "http://example.com@sample.invalid/login",
        "expected": "CRITICAL RISK",  # 70 pts: HTTP (20) + @ spoofing (50)
        "description": "Userinfo '@' spoofing with HTTP"
    },
    {
        "category": "Official Workbook - Subdomains",
        "url": "https://a.b.c.d.e.example.invalid/path",
        "expected": "MODERATE RISK",  # 20 pts: 7 segments
        "description": "Excessive subdomain segments (7 segments >= 5)"
    },
    {
        "category": "Official Workbook - Punycode",
        "url": "https://xn--example.invalid/",
        "expected": "HIGH RISK",  # 45 pts: Punycode marker
        "description": "Punycode (xn--) internationalized domain"
    },
    {
        "category": "Legitimate Google Blog (>100 Chars)",
        "url": "https://blog.google/innovation-and-ai/models-and-research/google-research/",
        "expected": "LOW RISK",
        "description": "Official Google blog article URL (111 chars) - Must NOT be flagged as phishing"
    },
    {
        "category": "Legitimate Microsoft Website",
        "url": "https://www.microsoft.com/en-us/software-download/windows11",
        "expected": "LOW RISK",
        "description": "Legitimate Microsoft domain with standard HTTPS"
    },
    {
        "category": "Legitimate Long URL (150+ Chars)",
        "url": "https://github.com/torvalds/linux/commit/805e6081e64903348b6c4eb896b42b934b3f0df6?diff=unified&w=1#diff-e50a93c9d7894a4c644c1",
        "expected": "LOW RISK",
        "description": "Legitimate long GitHub commit URL (>120 chars) on verified domain"
    },
    {
        "category": "Short Suspicious URL",
        "url": "http://192.0.2.1/login",
        "expected": "CRITICAL RISK",
        "description": "Raw IP address login portal on unencrypted HTTP"
    },
    {
        "category": "Fake Google Domain (Subdomain Spoofing)",
        "url": "https://google.com.fake-example.com/login",
        "expected": "HIGH RISK",
        "description": "Brand impersonation prepending 'google.com' inside 'fake-example.com'"
    },
    {
        "category": "Misspelled Brand (Typosquatting)",
        "url": "https://www.g00gle-security.com/login",
        "expected": "HIGH RISK",
        "description": "Typosquatting using 'g00gle' with security keyword"
    },
    {
        "category": "Encoded Characters in URL",
        "url": "http://bank.com%20verify.invalid/login?id=%3Cscript%3E",
        "expected": "HIGH RISK",  # HTTP (20) + Encoded chars (25) = 45
        "description": "Obfuscated encoded characters (%20, %3Cscript%3E) with HTTP"
    },
    {
        "category": "Suspicious Credential-Login Keywords",
        "url": "http://secure-account-verification-login.com/update-password",
        "expected": "HIGH RISK",  # HTTP (20) + Credential keywords (25) = 45
        "description": "Sensitive login/verification keywords on non-trusted HTTP domain"
    },
    {
        "category": "Standard Insecure HTTP Website",
        "url": "http://www.example.com/login",
        "expected": "MODERATE RISK",  # HTTP (20)
        "description": "Standard domain using unencrypted HTTP protocol"
    },
    {
        "category": "Open Redirect / URL Obfuscation",
        "url": "https://example.com/login?redirect=http://malicious-destination.xyz",
        "expected": "MODERATE RISK",  # Open redirect (25)
        "description": "URL containing secondary embedded protocol in redirect query"
    }
]


def run_sample_tests() -> None:
    """
    Execute tests against the comprehensive realistic test suite.
    Validates expected risk classifications.
    """
    print("\n" + "#" * 75)
    print(" " * 15 + "RUNNING COMPREHENSIVE REALISTIC TEST SUITE")
    print("#" * 75)

    passed_count = 0
    total = len(SAMPLE_TEST_CASES)

    for i, test in enumerate(SAMPLE_TEST_CASES, start=1):
        sample_url = test["url"]
        exp = test["expected"]
        cat = test["category"]
        desc = test["description"]

        print(f"\n{COLOR_BLUE}>>> TEST #{i}: [{cat}]{COLOR_RESET}")
        print(f"    {COLOR_GRAY}Target:   {sample_url}{COLOR_RESET}")
        print(f"    {COLOR_GRAY}Context:  {desc}{COLOR_RESET}")

        res = analyze_url(sample_url)
        actual = res["risk_level"]
        score = res["risk_score"]

        # Evaluation criteria: Pass if actual matches expected
        # (For CRITICAL/HIGH on raw IP and @, both represent severe danger)
        is_pass = (actual == exp) or (exp in ("HIGH RISK", "CRITICAL RISK") and actual in ("HIGH RISK", "CRITICAL RISK"))
        if is_pass:
            passed_count += 1
            status_str = f"{COLOR_GREEN}[PASS]{COLOR_RESET}"
        else:
            status_str = f"{COLOR_RED}[FAIL - Expected {exp}, got {actual}]{COLOR_RESET}"

        print(f"    Result:   Score: {score}/100 | Level: {res['risk_color']}{actual}{COLOR_RESET} | Status: {status_str}")
        print(f"    Warnings: {len(res['warnings'])} signs detected")
        for w in res["warnings"]:
            print(f"      • [{w['severity']}] {w['rule']} (+{w.get('points', 0)} pts)")

    print("\n" + "=" * 75)
    print(f"{COLOR_BOLD}TEST SUITE EXECUTION SUMMARY:{COLOR_RESET} {passed_count}/{total} PASSED ({int(passed_count/total*100)}%)")
    print("=" * 75 + "\n")


def print_banner() -> None:
    """Print the application welcome banner."""
    print(f"{COLOR_CYAN}")
    print(r"  ____  _     _     _     _               _   _ ____  _     ")
    print(r" |  _ \| |__ (_)___| |__ (_)_ __   __ _  | | | |  _ \| |    ")
    print(r" | |_) | '_ \| / __| '_ \| | '_ \ / _` | | | | | |_) | |    ")
    print(r" |  __/| | | | \__ \ | | | | | | | (_| | | |_| |  _ <| |___ ")
    print(r" |_|   |_| |_|_|___/_| |_|_|_| |_|\__, |  \___/|_| \_\_____|")
    print(r"                                  |___/                     ")
    print(f"       --- Awareness Checker & Defensive Analyzer ---{COLOR_RESET}")
    print(f"{COLOR_GRAY}   Based on EWB Edutech Cybersecurity Mini Project Workbook{COLOR_RESET}")
    print(f"{COLOR_CYAN}{'=' * 75}{COLOR_RESET}")


def interactive_menu() -> None:
    """Run the interactive main menu loop."""
    print_banner()

    while True:
        print(f"\n{COLOR_BOLD}MAIN MENU:{COLOR_RESET}")
        print("  [1] Analyze a single URL")
        print("  [2] Analyze multiple URLs (batch entry)")
        print("  [3] Run comprehensive test suite (15 test cases)")
        print("  [4] Launch Graphical Web UI (Clean Browser Interface)")
        print("  [5] Exit program")

        try:
            choice = input(f"\n{COLOR_BOLD}Select an option (1-5): {COLOR_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n{COLOR_YELLOW}Program interrupted. Exiting safely.{COLOR_RESET}")
            break

        if choice == "1":
            try:
                user_url = input(f"\n{COLOR_CYAN}Enter URL to analyze: {COLOR_RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                break
            result = analyze_url(user_url)
            display_results(result)

        elif choice == "2":
            print(f"\n{COLOR_CYAN}Enter URLs one by one. Enter a blank line or 'done' to finish:{COLOR_RESET}")
            batch_urls = []
            while True:
                try:
                    entry = input(f"URL #{len(batch_urls) + 1} > ").strip()
                except (KeyboardInterrupt, EOFError):
                    break
                if not entry or entry.lower() == "done":
                    break
                batch_urls.append(entry)

            if not batch_urls:
                print(f"{COLOR_YELLOW}No URLs entered for batch analysis.{COLOR_RESET}")
            else:
                print(f"\n{COLOR_GREEN}Analyzing {len(batch_urls)} URLs...{COLOR_RESET}")
                for idx, b_url in enumerate(batch_urls, start=1):
                    print(f"\n{COLOR_BLUE}>>> Batch Item {idx}/{len(batch_urls)}:{COLOR_RESET}")
                    result = analyze_url(b_url)
                    display_results(result)

        elif choice == "3":
            run_sample_tests()

        elif choice == "4":
            try:
                from web_ui import start_server
                start_server()
            except ImportError as e:
                print(f"{COLOR_RED}[!] Could not load web UI module: {e}{COLOR_RESET}")

        elif choice == "5" or choice.lower() in ("q", "quit", "exit"):
            print(f"\n{COLOR_GREEN}Thank you for using Phishing URL Awareness Checker. Stay secure!{COLOR_RESET}\n")
            break

        else:
            print(f"{COLOR_RED}[!] Invalid choice '{choice}'. Please select an option between 1 and 5.{COLOR_RESET}")


def main() -> None:
    """
    Entry point. Supports CLI argument execution, UI launch, or interactive menu.
    Usage:
        python phishing_checker.py
        python phishing_checker.py --ui
        python phishing_checker.py <url_to_analyze>
        python phishing_checker.py --test
    """
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ("--test", "-t"):
            run_sample_tests()
        elif arg in ("--ui", "--gui", "-u"):
            try:
                from web_ui import start_server
                start_server()
            except ImportError as e:
                print(f"Error loading UI: {e}")
        elif arg in ("--help", "-h"):
            print("Usage: python phishing_checker.py [URL | --ui | --test | --help]")
            print("If no argument is provided, the interactive menu launches.")
        else:
            # Direct CLI single URL analysis
            print_banner()
            result = analyze_url(arg)
            display_results(result)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
