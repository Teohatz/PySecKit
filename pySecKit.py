#!/usr/bin/env python3

import argparse
import sys
import os
import logging

# Ensure modules are found regardless of where the script is called from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from Hash_cracker.hash_cracker import run_hash_cracker
from Password_manager.password_manager import run_password_manager
from Password_tool.password_tool import run_password_tool
from Phishing_URL_Detector.phishing_detector import run_phishing_detector
from Port_scanner.port_scanner import run_port_scanner

BANNER = r"""
  ____        ____            _  ___ _
 |  _ \ _   _/ ___|  ___  ___| |/ (_) |_
 | |_) | | | \___ \ / _ \/ __| ' /| | __|
 |  __/| |_| |___) |  __/ (__| . \| | |_
 |_|    \__, |____/ \___|\___|_|\_\_|\__|
         |___/

 Python Security Toolkit v1.0
 For authorized use only.
 Use responsibly and only on systems you own or have explicit permission to test.
"""

TOOLS = {
    "portscan":  "Scan open ports on a target host",
    "hashcrack": "Crack a hash using wordlist or brute-force",
    "phishing":  "Analyze a URL for phishing indicators",
    "passcheck": "Check password strength or generate a strong password",
    "vault":     "Encrypted password manager (interactive)",
}


def print_banner():
    print(BANNER)


def print_tool_list():
    print("  Available tools:\n")
    for i, (name, desc) in enumerate(TOOLS.items(), 1):
        print(f"  [{i}] {name:<12} {desc}")
    print("\n  Usage  : python pySecKit.py <tool> --help")
    print("  Example: python pySecKit.py portscan --help\n")


def setup_logging(level: str):
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="[%(levelname)s] %(message)s",
        level=numeric,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pySecKit",
        description="PySecKit - Python Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'python pySecKit.py <tool> --help' for tool-specific options.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging verbosity (default: INFO)",
    )

    subparsers = parser.add_subparsers(dest="tool", metavar="<tool>")

    # ---- Port Scanner ----
    ps = subparsers.add_parser("portscan", help=TOOLS["portscan"])
    ps.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    ps.add_argument("-p", "--ports", default="1-1024", help="Port range, e.g. 20-80 (default: 1-1024)")
    ps.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    ps.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds (default: 2.0)")
    ps.add_argument("-o", "--output", help="Save results to file (.json or .csv)")

    # ---- Hash Cracker ----
    hc = subparsers.add_parser("hashcrack", help=TOOLS["hashcrack"])
    hc.add_argument("-H", "--hash", required=True, help="Hash value to crack")
    hc.add_argument("-a", "--algo", required=True,
                    help="Hash algorithm (md5, sha1, sha256, sha512, ...)")
    mode = hc.add_mutually_exclusive_group(required=True)
    mode.add_argument("-w", "--wordlist", help="Path to wordlist file")
    mode.add_argument("-b", "--brute", action="store_true", help="Use brute-force mode")
    hc.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789",
                    help="Character set for brute-force (default: lowercase + digits)")
    hc.add_argument("--min-len", type=int, default=1, help="Minimum password length (brute-force)")
    hc.add_argument("--max-len", type=int, default=6, help="Maximum password length (brute-force)")
    hc.add_argument("--threads", type=int, default=4, help="Threads for wordlist mode (default: 4)")
    hc.add_argument("-o", "--output", help="Save result to file (.json or .txt)")

    # ---- Phishing Detector ----
    ph = subparsers.add_parser("phishing", help=TOOLS["phishing"])
    ph.add_argument("-u", "--url", help="Single URL to analyze")
    ph.add_argument("-f", "--file", help="File with one URL per line")
    ph.add_argument("-o", "--output", help="Save results to file (.json or .csv)")
    ph.add_argument("--retrain", action="store_true", help="Force retrain the detection model")

    # ---- Password Tool ----
    pt = subparsers.add_parser("passcheck", help=TOOLS["passcheck"])
    action = pt.add_mutually_exclusive_group(required=True)
    action.add_argument("-p", "--password", help="Password to analyze")
    action.add_argument("-g", "--generate", action="store_true", help="Generate a strong password")
    pt.add_argument("--length", type=int, default=16, help="Length for generated password (default: 16)")
    pt.add_argument("--retrain", action="store_true", help="Force retrain the strength model")

    # ---- Vault ----
    subparsers.add_parser("vault", help=TOOLS["vault"])

    return parser


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        print_banner()
        print_tool_list()
        sys.exit(0)

    args = parser.parse_args()
    setup_logging(args.log_level)

    if args.tool is None:
        parser.print_help()
        sys.exit(1)

    print_banner()

    if args.tool == "portscan":
        run_port_scanner(args)
    elif args.tool == "hashcrack":
        run_hash_cracker(args)
    elif args.tool == "phishing":
        run_phishing_detector(args)
    elif args.tool == "passcheck":
        run_password_tool(args)
    elif args.tool == "vault":
        run_password_manager()


if __name__ == "__main__":
    main()
