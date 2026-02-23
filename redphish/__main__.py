#!/usr/bin/env python3
"""RedPhish CLI Entry Point"""

import argparse
import sys
import json
from .analyzer import analyze_url, print_report, batch_analyze, print_batch_summary
from .email_analyzer import EmailAnalyzer
from .utils import load_urls_from_file, export_json, export_csv, print_banner


def main():
    parser = argparse.ArgumentParser(
        prog='redphish',
        description='🎣 RedPhish — Advanced Phishing Detection & URL Analyzer'
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # URL analysis
    url_parser = subparsers.add_parser('url', help='Analyze a single URL')
    url_parser.add_argument('target', help='URL to analyze')
    url_parser.add_argument('-v', '--verbose', action='store_true', help='Show all features')
    url_parser.add_argument('--json', action='store_true', help='Output as JSON')

    # Batch analysis
    batch_parser = subparsers.add_parser('batch', help='Analyze URLs from file')
    batch_parser.add_argument('file', help='File containing URLs (one per line)')
    batch_parser.add_argument('-o', '--output', help='Export results (json/csv)')
    batch_parser.add_argument('-v', '--verbose', action='store_true')

    # Email analysis
    email_parser = subparsers.add_parser('email', help='Analyze email headers')
    email_parser.add_argument('file', help='Email file (.eml) to analyze')
    email_parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.command == 'url':
        print_banner()
        result = analyze_url(args.target, verbose=args.verbose)
        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            print_report(result, verbose=args.verbose)

    elif args.command == 'batch':
        print_banner()
        urls = load_urls_from_file(args.file)
        if not urls:
            print("No URLs found in file.", file=sys.stderr)
            sys.exit(1)

        results = batch_analyze(urls)
        print_batch_summary(results)

        if args.output:
            if args.output.endswith('.json'):
                export_json(results, args.output)
            elif args.output.endswith('.csv'):
                export_csv(results, args.output)
            else:
                export_json(results, args.output + '.json')

    elif args.command == 'email':
        print_banner()
        try:
            with open(args.file, 'r') as f:
                raw = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

        analyzer = EmailAnalyzer(raw)
        result = analyzer.analyze()

        if args.json:
            print(json.dumps(result, indent=2, default=str))
        else:
            _print_email_report(result)


def _print_email_report(result: dict):
    """Print formatted email analysis report"""
    from .analyzer import Colors, risk_color, risk_bar

    score = result['risk_score']
    c = risk_color(score)

    print(f"\n{'═' * 60}")
    print(f"  📧 RedPhish — Email Analysis Report")
    print(f"{'═' * 60}\n")

    print(f"  Subject:     {result.get('subject', 'N/A')}")
    print(f"  From:        {result.get('from', 'N/A')}")
    print(f"  To:          {result.get('to', 'N/A')}")
    print(f"  Date:        {result.get('date', 'N/A')}")
    print()
    print(f"  Verdict:     {c}{result['verdict']}{Colors.RESET}")
    print(f"  Risk Score:  {risk_bar(score)}")
    print()

    indicators = result.get('indicators', {})
    if indicators:
        print(f"  ── Authentication ──")
        print(f"  SPF:    {indicators.get('spf', 'N/A')}")
        print(f"  DKIM:   {indicators.get('dkim', 'N/A')}")
        print(f"  DMARC:  {indicators.get('dmarc', 'N/A')}")
        print(f"  Hops:   {indicators.get('received_hops', 'N/A')}")
        print()

    if result['warnings']:
        print(f"  ── Warnings ({len(result['warnings'])}) ──")
        for w in result['warnings']:
            print(f"  ⚠  {w}")
        print()

    print(f"{'═' * 60}\n")


if __name__ == '__main__':
    main()
