"""Command-line interface for Batman Bug Hunter."""
import argparse
import sys
from pathlib import Path

from .core import ScanError, report_json, scan_target


def main():
    parser = argparse.ArgumentParser(description="Batman Bug Hunter — passive-first authorized web checks")
    parser.add_argument("target", help="HTTP(S) URL you own or are authorized to assess")
    parser.add_argument("--i-am-authorized", action="store_true", help="Confirm written permission and scope")
    parser.add_argument("--allow-private", action="store_true", help="Allow private/lab IPs; use only for systems you control")
    parser.add_argument("--json", metavar="FILE", help="Save the full JSON report to a file")
    args = parser.parse_args()

    if not args.i_am_authorized:
        parser.error("Scanning requires --i-am-authorized and permission from the system owner.")
    if args.allow_private:
        print("[!] Private-network scanning enabled. Confirm this is your own lab.")
    try:
        report = scan_target(args.target, allow_private=args.allow_private)
    except ScanError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(f"\nBATMAN BUG HUNTER — {report['target']}")
    print(f"Requests: {report['requests_made']}")
    print("Findings:")
    if not report["findings"]:
        print("  No findings from the enabled passive checks.")
    for item in report["findings"]:
        print(f"  [{item['severity'].upper():6}] {item['title']} — {item['evidence']}")
    print("\nSummary:", report["summary"])
    if args.json:
        Path(args.json).write_text(report_json(report) + "\n", encoding="utf-8")
        print(f"JSON report saved to {args.json}")
    print("\nReminder: manually validate all results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
