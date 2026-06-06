import socket
import concurrent.futures
import ipaddress
import os
import csv
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")

DISCLAIMER = """
  IMPORTANT: Only scan hosts you own or have explicit written permission to test.
  Unauthorized port scanning may be illegal in your jurisdiction.
"""


# ---------- Core scanning ----------

def _scan_port(target: str, port: int, timeout: float, retries: int = 2) -> int | None:
    for _ in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    return port
        except (socket.timeout, OSError):
            continue
    return None


def scan_ports(target: str, start: int, end: int, threads: int, timeout: float) -> list[int]:
    open_ports = []
    total      = end - start + 1
    logger.info("Scanning %s | ports=%d-%d | threads=%d | timeout=%.1fs",
                target, start, end, threads, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_scan_port, target, port, timeout): port
            for port in range(start, end + 1)
        }
        done = 0
        for future in concurrent.futures.as_completed(futures):
            done += 1
            try:
                result = future.result()
                if result is not None:
                    open_ports.append(result)
                    logger.debug("Port %d open", result)
            except Exception as e:
                port = futures[future]
                logger.debug("Error scanning port %d: %s", port, e)

            if done % 500 == 0 or done == total:
                print(f"  Progress: {done}/{total} ports scanned", end="\r")

    print()
    return sorted(open_ports)


# ---------- Helpers ----------

def _get_service(port: int) -> str:
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"


def _validate_or_resolve(target: str) -> str | None:
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(target)
        logger.info("Resolved '%s' to %s", target, resolved)
        return resolved
    except socket.gaierror:
        return None


def _parse_port_range(port_range: str) -> tuple[int, int]:
    if "-" in port_range:
        parts = port_range.split("-")
        start, end = int(parts[0]), int(parts[1])
    else:
        start = end = int(port_range)
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise ValueError(f"Invalid port range: {port_range}")
    return start, end


def _save_results(target, start, end, threads, open_ports, output_path):
    ext = os.path.splitext(output_path)[1].lower()
    rows = [{"port": p, "service": _get_service(p)} for p in open_ports]

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        if ext == ".json":
            json.dump({
                "target":     target,
                "port_range": f"{start}-{end}",
                "threads":    threads,
                "timestamp":  datetime.now().isoformat(),
                "open_ports": rows,
            }, f, indent=2)
        else:
            writer = csv.DictWriter(f, fieldnames=["port", "service"])
            writer.writeheader()
            writer.writerows(rows)

    logger.info("Results saved to %s", output_path)


# ---------- Entry point ----------

def run_port_scanner(args):
    print(DISCLAIMER)

    target = _validate_or_resolve(args.target)
    if not target:
        logger.error("Cannot resolve target: %s", args.target)
        return

    try:
        start, end = _parse_port_range(args.ports)
    except ValueError as e:
        logger.error("%s", e)
        return

    threads = args.threads
    timeout = args.timeout

    print(f"  Target      : {target}")
    print(f"  Port range  : {start}-{end}")
    print(f"  Threads     : {threads}")
    print(f"  Timeout     : {timeout}s")
    print(f"  Started at  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    open_ports = scan_ports(target, start, end, threads, timeout)

    if open_ports:
        print(f"\n  Open ports on {target}:\n")
        print(f"  {'PORT':<8} {'SERVICE'}")
        print(f"  {'-'*8} {'-'*15}")
        for port in open_ports:
            print(f"  {port:<8} {_get_service(port)}")
    else:
        print("  No open ports found in the specified range.")

    logger.info("Scan complete. %d open port(s) found.", len(open_ports))

    output = getattr(args, "output", None)
    if output:
        os.makedirs(DATA_DIR, exist_ok=True)
        _save_results(target, start, end, threads, open_ports, output)
