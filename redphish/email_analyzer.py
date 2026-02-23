#!/usr/bin/env python3
"""Email Header Analyzer for Phishing Detection"""

import re
import email
from email import policy
from typing import Optional


class EmailAnalyzer:
    """Analyze email headers for phishing indicators"""

    SUSPICIOUS_HEADERS = {
        'x-mailer': ['PHPMailer', 'swiftmailer', 'King Phisher'],
        'x-originating-ip': [],  # any value is noteworthy
    }

    def __init__(self, raw_email: str):
        self.msg = email.message_from_string(raw_email, policy=policy.default)
        self.headers = dict(self.msg.items())
        self.warnings = []
        self.risk_score = 0

    def analyze(self) -> dict:
        """Run all email checks"""
        result = {
            'subject': self.msg.get('Subject', ''),
            'from': self.msg.get('From', ''),
            'to': self.msg.get('To', ''),
            'date': self.msg.get('Date', ''),
            'return_path': self.msg.get('Return-Path', ''),
            'message_id': self.msg.get('Message-ID', ''),
            'warnings': [],
            'indicators': {},
            'risk_score': 0
        }

        self._check_spf(result)
        self._check_dkim(result)
        self._check_dmarc(result)
        self._check_sender_mismatch(result)
        self._check_reply_to(result)
        self._check_received_chain(result)
        self._check_suspicious_headers(result)
        self._check_urgency(result)
        self._check_links_in_body(result)

        result['warnings'] = self.warnings
        result['risk_score'] = min(self.risk_score, 100)
        result['verdict'] = self._verdict(result['risk_score'])

        return result

    def _check_spf(self, result):
        spf = self.msg.get('Received-SPF', '') or self.msg.get('Authentication-Results', '')
        if 'fail' in spf.lower() or 'softfail' in spf.lower():
            self.warnings.append("SPF check failed — sender may be spoofed")
            self.risk_score += 20
            result['indicators']['spf'] = 'fail'
        elif 'pass' in spf.lower():
            result['indicators']['spf'] = 'pass'
        else:
            result['indicators']['spf'] = 'missing'
            self.risk_score += 5

    def _check_dkim(self, result):
        auth = self.msg.get('Authentication-Results', '')
        if 'dkim=fail' in auth.lower():
            self.warnings.append("DKIM signature verification failed")
            self.risk_score += 15
            result['indicators']['dkim'] = 'fail'
        elif 'dkim=pass' in auth.lower():
            result['indicators']['dkim'] = 'pass'
        else:
            result['indicators']['dkim'] = 'missing'

    def _check_dmarc(self, result):
        auth = self.msg.get('Authentication-Results', '')
        if 'dmarc=fail' in auth.lower():
            self.warnings.append("DMARC policy check failed")
            self.risk_score += 15
            result['indicators']['dmarc'] = 'fail'
        elif 'dmarc=pass' in auth.lower():
            result['indicators']['dmarc'] = 'pass'

    def _check_sender_mismatch(self, result):
        from_addr = self.msg.get('From', '')
        return_path = self.msg.get('Return-Path', '')

        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_path)

        if from_domain and return_domain and from_domain != return_domain:
            self.warnings.append(
                f"Sender mismatch: From='{from_domain}' vs Return-Path='{return_domain}'"
            )
            self.risk_score += 15

    def _check_reply_to(self, result):
        reply_to = self.msg.get('Reply-To', '')
        from_addr = self.msg.get('From', '')

        reply_domain = self._extract_domain(reply_to)
        from_domain = self._extract_domain(from_addr)

        if reply_domain and from_domain and reply_domain != from_domain:
            self.warnings.append(
                f"Reply-To domain differs from sender: '{reply_domain}' vs '{from_domain}'"
            )
            self.risk_score += 10

    def _check_received_chain(self, result):
        received = self.msg.get_all('Received', [])
        result['indicators']['received_hops'] = len(received)

        if len(received) > 8:
            self.warnings.append(f"Unusually long received chain ({len(received)} hops)")
            self.risk_score += 5

    def _check_suspicious_headers(self, result):
        for header, suspicious_values in self.SUSPICIOUS_HEADERS.items():
            value = self.msg.get(header, '')
            if value:
                if not suspicious_values:
                    result['indicators'][header] = value
                else:
                    for sv in suspicious_values:
                        if sv.lower() in value.lower():
                            self.warnings.append(f"Suspicious {header}: {value}")
                            self.risk_score += 10

    def _check_urgency(self, result):
        subject = (self.msg.get('Subject', '') or '').lower()
        urgency_words = [
            'urgent', 'immediate', 'action required', 'verify your',
            'suspend', 'locked', 'unauthorized', 'expire',
            'confirm your identity', 'unusual activity', 'security alert'
        ]
        found = [w for w in urgency_words if w in subject]
        if found:
            self.warnings.append(f"Urgency/fear keywords in subject: {', '.join(found)}")
            self.risk_score += 15

    def _check_links_in_body(self, result):
        body = self._get_body()
        if not body:
            return

        urls = re.findall(r'https?://[^\s<>"\']+', body)
        result['indicators']['urls_in_body'] = len(urls)

        shortened = [u for u in urls if any(s in u for s in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'is.gd', 'buff.ly'])]
        if shortened:
            self.warnings.append(f"Shortened URLs found in body: {len(shortened)}")
            self.risk_score += 10

    def _get_body(self) -> str:
        if self.msg.is_multipart():
            for part in self.msg.walk():
                ct = part.get_content_type()
                if ct in ('text/plain', 'text/html'):
                    try:
                        return part.get_content()
                    except Exception:
                        pass
        else:
            try:
                return self.msg.get_content()
            except Exception:
                return ''
        return ''

    def _extract_domain(self, addr: str) -> Optional[str]:
        match = re.search(r'@([\w.-]+)', addr)
        return match.group(1).lower() if match else None

    def _verdict(self, score: int) -> str:
        if score >= 60:
            return "LIKELY PHISHING"
        elif score >= 30:
            return "SUSPICIOUS"
        return "PROBABLY LEGITIMATE"
