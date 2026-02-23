#!/usr/bin/env python3
"""Core Phishing Analyzer — combines all detection methods"""

import json
import sys
from datetime import datetime
from .url_features import extract_features, resolve_domain

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def risk_color(score: int) -> str:
    if score >= 70:
        return Colors.RED
    elif score >= 40:
        return Colors.YELLOW
    return Colors.GREEN


def risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    elif score >= 20:
        return "LOW RISK"
    return "SAFE"


def risk_bar(score: int, width: int = 30) -> str:
    filled = int((score / 100) * width)
    bar = '█' * filled + '░' * (width - filled)
    color = risk_color(score)
    return f"{color}{bar}{Colors.RESET} {score}/100"


def analyze_url(url: str, verbose: bool = False) -> dict:
    """Perform comprehensive URL analysis"""
    result = {
        'url': url,
        'timestamp': datetime.utcnow().isoformat(),
        'features': {},
        'warnings': [],
        'risk_score': 0,
        'verdict': 'SAFE'
    }

    # Extract features
    features = extract_features(url)
    result['features'] = features
    result['risk_score'] = features.get('risk_score', 0)
    result['verdict'] = risk_label(result['risk_score'])

    # Generate warnings
    warnings = []
    if not features.get('is_https'):
        warnings.append("No HTTPS — connection is not encrypted")
    if features.get('has_ip_address'):
        warnings.append("URL uses raw IP address instead of domain name")
    if features.get('is_punycode'):
        warnings.append("Domain uses Punycode (internationalized) — possible homograph attack")
    if features.get('suspicious_tld'):
        warnings.append(f"Suspicious TLD commonly used in phishing campaigns")
    if features.get('targeted_brand'):
        warnings.append(f"Possible impersonation of '{features['targeted_brand']}' — domain doesn't match official site")
    if features.get('has_homoglyphs'):
        warnings.append("Domain contains homoglyph characters — visual spoofing attempt")
    if features.get('has_at_sign'):
        warnings.append("URL contains '@' sign — may redirect to different host")
    if features.get('url_length', 0) > 75:
        warnings.append(f"Unusually long URL ({features['url_length']} chars) — common in phishing")
    if features.get('num_subdomains', 0) > 3:
        warnings.append(f"Excessive subdomains ({features['num_subdomains']}) — domain obfuscation")
    if features.get('domain_entropy', 0) > 4.0:
        warnings.append(f"High domain entropy ({features['domain_entropy']}) — randomly generated domain")
    if features.get('has_login_path'):
        warnings.append("URL path contains login/authentication keywords")
    if features.get('has_suspicious_params'):
        warnings.append("Query parameters contain sensitive field names (password, token, etc.)")
    if features.get('has_port'):
        warnings.append("URL uses non-standard port")
    if features.get('has_suspicious_extension'):
        warnings.append("URL points to suspicious file type")

    result['warnings'] = warnings
    return result


def print_report(result: dict, verbose: bool = False):
    """Print a formatted analysis report"""
    score = result['risk_score']
    c = risk_color(score)

    print(f"\n{Colors.BOLD}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  🎣 RedPhish — URL Analysis Report{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 60}{Colors.RESET}\n")

    print(f"  {Colors.CYAN}Target:{Colors.RESET}  {result['url']}")
    print(f"  {Colors.CYAN}Time:{Colors.RESET}    {result['timestamp']}")
    print()

    # Risk meter
    print(f"  {Colors.BOLD}Risk Level:{Colors.RESET}  {c}{Colors.BOLD}{result['verdict']}{Colors.RESET}")
    print(f"  {Colors.BOLD}Score:{Colors.RESET}      {risk_bar(score)}")
    print()

    # Features summary
    f = result['features']
    print(f"  {Colors.BOLD}── Domain Analysis ──{Colors.RESET}")
    print(f"  Domain:       {f.get('domain', 'N/A')}")
    print(f"  HTTPS:        {'✅ Yes' if f.get('is_https') else '❌ No'}")
    print(f"  Subdomains:   {f.get('num_subdomains', 0)}")
    print(f"  Punycode:     {'⚠️  Yes' if f.get('is_punycode') else '✅ No'}")
    print(f"  IP Address:   {'⚠️  Yes' if f.get('has_ip_address') else '✅ No'}")
    print(f"  Entropy:      {f.get('domain_entropy', 0)}")
    print()

    if f.get('targeted_brand'):
        print(f"  {Colors.RED}{Colors.BOLD}⚠️  BRAND IMPERSONATION: {f['targeted_brand']}{Colors.RESET}")
        print()

    # Warnings
    if result['warnings']:
        print(f"  {Colors.BOLD}── Warnings ({len(result['warnings'])}) ──{Colors.RESET}")
        for w in result['warnings']:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET}  {w}")
        print()

    if verbose:
        print(f"  {Colors.BOLD}── Raw Features ──{Colors.RESET}")
        for k, v in sorted(f.items()):
            print(f"  {Colors.DIM}{k}: {v}{Colors.RESET}")
        print()

    print(f"{Colors.BOLD}{'═' * 60}{Colors.RESET}\n")


def batch_analyze(urls: list) -> list:
    """Analyze multiple URLs"""
    results = []
    for url in urls:
        results.append(analyze_url(url))
    return results


def print_batch_summary(results: list):
    """Print summary table for batch analysis"""
    print(f"\n{Colors.BOLD}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}  🎣 RedPhish — Batch Analysis Summary{Colors.RESET}")
    print(f"{Colors.BOLD}{'═' * 70}{Colors.RESET}\n")
    print(f"  {'URL':<40} {'Score':>6}  {'Verdict':<12}")
    print(f"  {'─' * 40} {'─' * 6}  {'─' * 12}")

    for r in sorted(results, key=lambda x: x['risk_score'], reverse=True):
        url_short = r['url'][:38] + '..' if len(r['url']) > 40 else r['url']
        c = risk_color(r['risk_score'])
        print(f"  {url_short:<40} {c}{r['risk_score']:>5}{Colors.RESET}  {c}{r['verdict']:<12}{Colors.RESET}")

    print(f"\n  Total: {len(results)} URLs analyzed")
    high = sum(1 for r in results if r['risk_score'] >= 70)
    med = sum(1 for r in results if 40 <= r['risk_score'] < 70)
    if high:
        print(f"  {Colors.RED}🚨 {high} HIGH RISK URLs detected{Colors.RESET}")
    if med:
        print(f"  {Colors.YELLOW}⚠️  {med} MEDIUM RISK URLs detected{Colors.RESET}")
    print()
