#!/usr/bin/env python3
"""URL Feature Extraction for Phishing Detection"""

import re
import math
import socket
from urllib.parse import urlparse, parse_qs
from collections import Counter

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
    '.work', '.date', '.racing', '.win', '.bid', '.stream',
    '.download', '.loan', '.click', '.link', '.info', '.online'
}

# Legitimate brands commonly targeted
TARGET_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'usps', 'fedex', 'dhl',
    'outlook', 'office365', 'icloud', 'yahoo', 'ebay', 'spotify'
]

# Common homoglyph substitutions
HOMOGLYPHS = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],
    'e': ['è', 'é', 'ê', 'ë', 'ε', 'е'],
    'i': ['ì', 'í', 'î', 'ï', 'і'],
    'o': ['ò', 'ó', 'ô', 'õ', 'ö', 'о', '0'],
    'l': ['1', '|', 'ι', 'ɩ'],
    'c': ['ç', 'с'],
    'n': ['ñ', 'п'],
    'g': ['ɡ'],
    's': ['ş', 'ѕ'],
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def extract_features(url: str) -> dict:
    """Extract all phishing-relevant features from a URL"""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
    except Exception:
        return {"error": "Invalid URL"}

    domain = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = parsed.scheme or 'http'

    features = {}

    # === Basic URL Properties ===
    features['url_length'] = len(url)
    features['domain'] = domain
    features['path'] = path
    features['scheme'] = scheme
    features['is_https'] = scheme == 'https'

    # === Domain Analysis ===
    features['domain_length'] = len(domain)
    features['num_subdomains'] = max(0, domain.count('.') - 1)
    features['has_ip_address'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

    # Check for punycode (internationalized domain names)
    features['is_punycode'] = 'xn--' in domain
    features['has_port'] = parsed.port is not None and parsed.port not in (80, 443)

    # === Entropy ===
    features['domain_entropy'] = calculate_entropy(domain)
    features['path_entropy'] = calculate_entropy(path)
    features['url_entropy'] = calculate_entropy(url)

    # === Suspicious Patterns ===
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = domain.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_at_signs'] = url.count('@')
    features['has_at_sign'] = '@' in url
    features['num_digits_in_domain'] = sum(c.isdigit() for c in domain)
    features['digit_ratio_domain'] = round(features['num_digits_in_domain'] / max(len(domain), 1), 4)

    # === Query String ===
    params = parse_qs(query)
    features['num_params'] = len(params)
    features['has_suspicious_params'] = any(
        k.lower() in ('password', 'passwd', 'pwd', 'token', 'session', 'redirect', 'url', 'next', 'return')
        for k in params
    )

    # === Path Analysis ===
    features['path_length'] = len(path)
    features['has_double_slash'] = '//' in path
    path_lower = path.lower()
    features['has_login_path'] = any(w in path_lower for w in ['login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm'])
    features['has_suspicious_extension'] = any(path_lower.endswith(ext) for ext in ['.exe', '.zip', '.scr', '.bat', '.php', '.cgi'])

    # === TLD Check ===
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    features['suspicious_tld'] = tld.lower() in SUSPICIOUS_TLDS

    # === Brand Impersonation ===
    domain_lower = domain.lower().replace('-', '').replace('.', '')
    features['targeted_brand'] = None
    for brand in TARGET_BRANDS:
        if brand in domain_lower:
            # Check if it's the real domain
            legit_patterns = [f'{brand}.com', f'{brand}.org', f'{brand}.net', f'{brand}.io']
            if not any(domain.lower().endswith(p) for p in legit_patterns):
                features['targeted_brand'] = brand
                break

    # === Homoglyph Detection ===
    features['has_homoglyphs'] = False
    for char_map in HOMOGLYPHS.values():
        if any(c in domain for c in char_map):
            features['has_homoglyphs'] = True
            break

    # === Risk Score ===
    features['risk_score'] = _calculate_risk_score(features)

    return features


def _calculate_risk_score(features: dict) -> int:
    """Calculate a risk score from 0-100"""
    score = 0

    if not features.get('is_https'):
        score += 10
    if features.get('has_ip_address'):
        score += 25
    if features.get('is_punycode'):
        score += 20
    if features.get('suspicious_tld'):
        score += 15
    if features.get('targeted_brand'):
        score += 25
    if features.get('has_homoglyphs'):
        score += 20
    if features.get('has_at_sign'):
        score += 15
    if features.get('url_length', 0) > 75:
        score += 10
    if features.get('num_subdomains', 0) > 3:
        score += 10
    if features.get('domain_entropy', 0) > 4.0:
        score += 10
    if features.get('has_login_path'):
        score += 10
    if features.get('has_suspicious_params'):
        score += 10
    if features.get('num_hyphens', 0) > 3:
        score += 10
    if features.get('num_digits_in_domain', 0) > 4:
        score += 5
    if features.get('has_port'):
        score += 10

    return min(score, 100)


def resolve_domain(domain: str) -> dict:
    """Resolve domain to IP and check basic DNS info"""
    result = {'domain': domain, 'resolved': False}
    try:
        ip = socket.gethostbyname(domain)
        result['ip'] = ip
        result['resolved'] = True
        try:
            result['reverse_dns'] = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            result['reverse_dns'] = None
    except socket.gaierror:
        result['ip'] = None
    return result
