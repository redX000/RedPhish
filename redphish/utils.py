#!/usr/bin/env python3
"""Utility functions for RedPhish"""

import json
import csv
import sys
from pathlib import Path
from typing import List


def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from a text file (one per line)"""
    path = Path(filepath)
    if not path.exists():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    urls = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                urls.append(line)
    return urls


def export_json(results: list, filepath: str):
    """Export results to JSON"""
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results exported to: {filepath}")


def export_csv(results: list, filepath: str):
    """Export results to CSV"""
    if not results:
        return

    fields = ['url', 'risk_score', 'verdict', 'domain', 'is_https',
              'targeted_brand', 'num_warnings']

    with open(filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = {
                'url': r['url'],
                'risk_score': r['risk_score'],
                'verdict': r['verdict'],
                'domain': r['features'].get('domain', ''),
                'is_https': r['features'].get('is_https', False),
                'targeted_brand': r['features'].get('targeted_brand', ''),
                'num_warnings': len(r.get('warnings', []))
            }
            writer.writerow(row)
    print(f"Results exported to: {filepath}")


def print_banner():
    """Print RedPhish banner"""
    banner = """
\033[91m
    ██████╗ ███████╗██████╗ ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║  ██║██║██╔════╝██║  ██║
    ██████╔╝█████╗  ██║  ██║██████╔╝███████║██║███████╗███████║
    ██╔══██╗██╔══╝  ██║  ██║██╔═══╝ ██╔══██║██║╚════██║██╔══██║
    ██║  ██║███████╗██████╔╝██║     ██║  ██║██║███████║██║  ██║
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝
\033[0m
    \033[93m🎣 Advanced Phishing Detection & URL Analyzer v1.0.0\033[0m
    \033[90mBy Yassine Lasraoui (redX000)\033[0m
"""
    print(banner)
