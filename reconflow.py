#!/usr/bin/env python3
"""ReconFlow - lightweight, sequential reconnaissance workflow.

Created by reixxhaxx. Use only against domains you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "0.2.1"
AUTHOR = "reixxhaxx"
BANNER = r"""
 ____                      ______ _
|  _ \ ___  ___ ___  _ __  |  ____| | _____      __
| |_) / _ \/ __/ _ \| '_ \ | |__  | |/ _ \ \ /\ / /
|  _ <  __/ (_| (_) | | | ||  __| | | (_) \ V  V /
|_|\_\___|\___\___/|_| |_||_|    |_|\___/ \_/\_/
"""

WARNINGS: list[str] = []
SILENT = False


def info(message: str) -> None:
    if not SILENT:
        print(f"[INFO] {message}")


def warning(message: str) -> None:
    WARNINGS.append(message)
    print(f"[WARN] {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"[ERROR] {message}", file=sys.stderr)


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    pattern = (
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}"
    )
    return re.fullmatch(pattern, domain) is not None


def run_command(command: list[str], timeout: int = 180) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=timeout,
            check=False, encoding="utf-8", errors="replace"
        )
    except FileNotFoundError:
        warning(f"Required executable not found: {command[0]}")
    except subprocess.TimeoutExpired:
        warning(f"{command[0]} timed out after {timeout} seconds.")
    except OSError as exc:
        warning(f"Could not run {command[0]}: {exc}")
    return None


def read_lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    except FileNotFoundError:
        return []
    except OSError as exc:
        warning(f"Could not read {path}: {exc}")
        return []


def write_text(path: Path, content: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return True
    except OSError as exc:
        error(f"Could not write {path}: {exc}")
        return False


def save_lines(path: Path, lines: Iterable[str]) -> bool:
    values = list(lines)
    return write_text(path, "\n".join(values) + ("\n" if values else ""))


def check_dependencies(dns_mode: str) -> bool:
    required = ["subfinder", "findomain", "dig", "httpx"]
    if dns_mode in ("udp", "auto"):
        required.append("dnsx")
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        error("Missing tools: " + ", ".join(missing))
        error("Install them and ensure they are available in PATH.")
        return False

    httpx_help = run_command(["httpx", "-h"], timeout=10)
    help_text = ""
    if httpx_help:
        help_text = (httpx_help.stdout or "") + (httpx_help.stderr or "")
    if "-status-code" not in help_text or "-json" not in help_text:
        error("The 'httpx' executable does not look like ProjectDiscovery httpx.")
        error("Check that ProjectDiscovery httpx is first in PATH (not Python HTTPX).")
        return False
    return True


def discover_subfinder(domain: str, work: Path) -> list[str]:
    info("Running Subfinder...")
    output = work / "subfinder.txt"
    result = run_command(["subfinder", "-d", domain, "-silent", "-o", str(output)], timeout=240)
    hosts = read_lines(output)
    if result is None or result.returncode != 0:
        warning("Subfinder failed or returned a non-zero exit code; keeping any partial output.")
    info(f"Subfinder entries: {len(hosts)}")
    return hosts


def discover_findomain(domain: str, work: Path) -> list[str]:
    info("Running Findomain...")
    output = work / "findomain.txt"
    result = run_command(["findomain", "-t", domain, "-u", str(output), "-q"], timeout=240)
    hosts = read_lines(output)
    if result is None or result.returncode != 0:
        warning("Findomain failed or returned a non-zero exit code; keeping any partial output.")
    info(f"Findomain entries: {len(hosts)}")
    return hosts


def discover_crtsh(domain: str) -> list[str]:
    info("Querying crt.sh...")
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={"User-Agent": f"ReconFlow/{VERSION}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
        if not isinstance(data, list):
            raise ValueError("unexpected JSON structure")
        hosts: list[str] = []
        for entry in data:
            if isinstance(entry, dict):
                names = entry.get("name_value", "")
                if isinstance(names, str):
                    hosts.extend(names.splitlines())
        info(f"crt.sh entries: {len(hosts)}")
        return hosts
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
        warning(f"crt.sh unavailable: {exc}. Continuing with other sources.")
        return []


def normalize_hosts(hosts: Iterable[str], domain: str) -> list[str]:
    scoped: set[str] = set()
    for raw in hosts:
        if not isinstance(raw, str):
            continue
        host = raw.strip().lower()
        if host.startswith("*."):
            host = host[2:]
        if "*" in host or any(char.isspace() for char in host):
            continue
        host = host.rstrip(".")
        if not valid_domain(host):
            continue
        if host == domain or host.endswith("." + domain):
            scoped.add(host)
    return sorted(scoped)


def dig_response(output: str, returncode: int) -> tuple[str, list[str]]:
    """Return DNS status and validated A records from ANSWER SECTION only."""
    if returncode == 9 or re.search(
        r"connection timed out|communications error|no servers could be reached|network is unreachable",
        output, re.IGNORECASE
    ):
        return "TIMEOUT", []

    match = re.search(r"status:\s*([A-Z]+)", output, re.IGNORECASE)
    if not match:
        return "ERROR", []
    status = match.group(1).upper()
    if status != "NOERROR":
        return status, []

    answer_match = re.search(
        r";; ANSWER SECTION:\s*(.*?)(?=\n\s*;;|\Z)",
        output, re.IGNORECASE | re.DOTALL
    )
    ips: set[str] = set()
    if answer_match:
        for line in answer_match.group(1).splitlines():
            fields = line.split()
            for index in range(len(fields) - 2):
                if fields[index].upper() == "IN" and fields[index + 1].upper() == "A":
                    try:
                        address = ipaddress.ip_address(fields[index + 2])
                        if address.version == 4:
                            ips.add(str(address))
                    except ValueError:
                        pass
    return ("RESOLVED", sorted(ips)) if ips else ("NODATA", [])


def resolve_tcp(hosts: list[str], resolver: str, timeout: int, retry: int, work: Path) -> tuple[list[str], dict[str, int]]:
    info(f"Resolving {len(hosts)} hosts sequentially over DNS/TCP via {resolver}...")
    resolved: list[str] = []
    stats = {key: 0 for key in ("resolved", "timeout", "nxdomain", "nodata", "servfail", "refused", "other")}
    for host in hosts:
        result = run_command(
            ["dig", "+tcp", f"@{resolver}", host, "A", f"+time={timeout}", f"+tries={retry}"],
            timeout=timeout * retry + 5
        )
        if result is None:
            stats["timeout"] += 1
            continue
        status, _ips = dig_response((result.stdout or "") + "\n" + (result.stderr or ""), result.returncode)
        if status == "RESOLVED":
            resolved.append(host)
            stats["resolved"] += 1
        elif status == "TIMEOUT":
            stats["timeout"] += 1
        elif status == "NXDOMAIN":
            stats["nxdomain"] += 1
        elif status == "NODATA":
            stats["nodata"] += 1
        elif status == "SERVFAIL":
            stats["servfail"] += 1
        elif status == "REFUSED":
            stats["refused"] += 1
        else:
            stats["other"] += 1
    return sorted(set(resolved)), stats


def udp_probe(domain: str, resolver: str, timeout: int) -> bool:
    result = run_command(
        ["dig", f"@{resolver}", domain, "A", f"+time={timeout}", "+tries=1"],
        timeout=timeout + 4
    )
    if result is None:
        return False
    status, _ = dig_response((result.stdout or "") + "\n" + (result.stderr or ""), result.returncode)
    return status in {"RESOLVED", "NODATA", "NXDOMAIN", "SERVFAIL", "REFUSED"}


def resolve_udp(hosts: list[str], resolver: str, timeout: int, retry: int, work: Path) -> tuple[list[str], bool]:
    source = work / "dns_input.txt"
    output = work / "dns_resolved.txt"
    if not save_lines(source, hosts):
        return [], False
    result = run_command(
        ["dnsx", "-l", str(source), "-r", resolver, "-retry", str(retry),
         "-timeout", str(timeout), "-silent", "-o", str(output)],
        timeout=max(60, len(hosts) * timeout * retry + 10)
    )
    if result is None or result.returncode != 0:
        warning("dnsx UDP resolution failed; transport may be unavailable.")
        return [], False
    # Accept only exact hostnames supplied to dnsx; never trust out-of-scope output.
    allowed = set(hosts)
    resolved = sorted({line.strip().lower().rstrip(".") for line in read_lines(output)} & allowed)
    return resolved, True


def resolve_hosts(hosts: list[str], domain: str, args: argparse.Namespace, work: Path) -> tuple[list[str], dict[str, int], str]:
    empty_stats = {key: 0 for key in ("resolved", "timeout", "nxdomain", "nodata", "servfail", "refused", "other")}
    if not hosts:
        warning("No in-scope hosts were discovered; skipping DNS resolution.")
        return [], empty_stats, "not run"

    if args.dns_mode == "tcp":
        resolved, stats = resolve_tcp(hosts, args.resolver, args.timeout, args.retry, work)
        return resolved, stats, "TCP (dig)"

    if args.dns_mode == "udp":
        resolved, ok = resolve_udp(hosts, args.resolver, args.timeout, args.retry, work)
        stats = dict(empty_stats)
        stats["resolved"] = len(resolved)
        stats["other"] = max(0, len(hosts) - len(resolved)) if ok else len(hosts)
        return resolved, stats, "UDP (dnsx; non-resolved results unclassified)"

    info(f"Auto mode: checking UDP DNS reachability to {args.resolver}...")
    if not udp_probe(domain, args.resolver, args.timeout):
        warning("UDP DNS probe failed; switching to direct DNS-over-TCP.")
        resolved, stats = resolve_tcp(hosts, args.resolver, args.timeout, args.retry, work)
        return resolved, stats, "TCP fallback (UDP probe failed)"

    resolved, ok = resolve_udp(hosts, args.resolver, args.timeout, args.retry, work)
    if not ok:
        warning("dnsx failed after UDP probe; switching to direct DNS-over-TCP.")
        resolved, stats = resolve_tcp(hosts, args.resolver, args.timeout, args.retry, work)
        return resolved, stats, "TCP fallback (dnsx failed)"

    stats = dict(empty_stats)
    stats["resolved"] = len(resolved)
    stats["other"] = max(0, len(hosts) - len(resolved))
    return resolved, stats, "UDP (dnsx; non-resolved results unclassified)"


def probe_http(hosts: list[str], work: Path) -> list[str]:
    if not hosts:
        info("No DNS-resolved hosts; skipping HTTP probing.")
        return []
    source = work / "http_input.txt"
    output = work / "httpx.jsonl"
    if not save_lines(source, hosts):
        return []
    info(f"Probing {len(hosts)} hosts with ProjectDiscovery httpx...")
    result = run_command(
        ["httpx", "-l", str(source), "-silent", "-status-code", "-title",
         "-tech-detect", "-web-server", "-ip", "-json", "-o", str(output)],
        timeout=max(120, len(hosts) * 8)
    )
    if result is None or result.returncode != 0:
        warning("ProjectDiscovery httpx did not complete successfully; checking any partial output.")
    live: set[str] = set()
    for line in read_lines(output):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            warning("Skipped a malformed JSON line from httpx output.")
            continue
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        status = item.get("status_code")
        if not isinstance(url, str) or not url or not isinstance(status, int):
            continue
        title = str(item.get("title") or "").replace("\r", " ").replace("\n", " ").strip()
        live.add(f"{status} | {url}" + (f" | {title}" if title else ""))
    info(f"HTTP responsive URLs: {len(live)}")
    return sorted(live)


def make_report(domain: str, counts: dict[str, int], dns_stats: dict[str, int], transport: str, resolver: str, timeout: int, retry: int) -> str:
    lines = [
        "=" * 72,
        "                         ReconFlow Scan Report",
        "=" * 72,
        f"Scan time (UTC):          {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"Version:                  {VERSION}",
        f"Author:                   {AUTHOR}",
        f"Target domain:            {domain}",
        "",
        "1. Passive discovery",
        f"Subfinder entries:        {counts['subfinder']}",
        f"Findomain entries:        {counts['findomain']}",
        f"crt.sh entries:           {counts['crtsh']}",
        f"Unique entries:           {counts['unique']}",
        f"In-scope hostnames:       {counts['scoped']}",
        "",
        "2. DNS resolution",
        f"Resolver:                 {resolver}",
        f"Transport:                {transport}",
        f"Timeout / retries:        {timeout}s / {retry}",
        f"Resolved:                 {dns_stats['resolved']}",
        f"Timeouts:                 {dns_stats['timeout']}",
        f"NXDOMAIN:                 {dns_stats['nxdomain']}",
        f"NODATA:                   {dns_stats['nodata']}",
        f"SERVFAIL:                 {dns_stats['servfail']}",
        f"REFUSED:                  {dns_stats['refused']}",
        f"Other / unclassified:     {dns_stats['other']}",
        "",
        "3. HTTP probing",
        f"Responsive HTTP URLs:     {counts['live']}",
        "",
        "4. Warnings",
    ]
    lines.extend([f"- {item}" for item in WARNINGS] if WARNINGS else ["None."])
    lines.extend(["", "Note: HTTP responsiveness does not establish vulnerability or permission for further testing.",
                  "Only scan assets you own or are explicitly authorized to assess.", "=" * 72])
    return "\n".join(lines) + "\n"


class ReconArgumentParser(argparse.ArgumentParser):
    def format_help(self) -> str:
        return BANNER + "\n" + super().format_help()


def build_parser() -> argparse.ArgumentParser:
    parser = ReconArgumentParser(
        prog="reconflow",
        description="Lightweight, sequential reconnaissance automation.",
        epilog="Only scan domains you own or are explicitly authorized to assess."
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="output", metavar="DIR", help="Base output directory (default: output)")
    parser.add_argument("-s", "-silent", "--silent", action="store_true", help="Suppress informational messages; warnings remain visible")
    parser.add_argument("--dns-mode", choices=("auto", "udp", "tcp"), default="auto", help="DNS transport mode (default: auto)")
    parser.add_argument("--resolver", default="8.8.8.8", help="DNS resolver IP address (default: 8.8.8.8)")
    parser.add_argument("--timeout", type=positive_int, default=3, help="Per-query timeout in seconds (default: 3)")
    parser.add_argument("--retry", type=positive_int, default=1, help="DNS retry count (default: 1)")
    parser.add_argument("-v", "--version", action="version", version=f"{BANNER}\nReconFlow v{VERSION} | Created by {AUTHOR}\nhttps://github.com/reixxhaxx-code/ReconFlow\n")
    return parser


def main() -> int:
    global SILENT
    parser = build_parser()
    args = parser.parse_args()
    SILENT = args.silent
    WARNINGS.clear()

    domain = args.domain.strip().lower().rstrip(".")
    if not valid_domain(domain):
        error("Invalid domain format. Supply a valid fully-qualified domain name.")
        return 2
    try:
        ipaddress.ip_address(args.resolver)
    except ValueError:
        error("--resolver must be an IPv4 or IPv6 address (not a hostname).")
        return 2
    if not check_dependencies(args.dns_mode):
        return 1

    target_dir = Path(args.output).expanduser() / domain
    live_path = target_dir / "live.txt"
    report_path = target_dir / "report.txt"
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        # Remove stale results so a failed run cannot leave old data looking current.
        for old_file in (live_path, report_path):
            old_file.unlink(missing_ok=True)
    except OSError as exc:
        error(f"Cannot prepare output directory: {exc}")
        return 1

    if not SILENT:
        print(BANNER)
        info(f"ReconFlow v{VERSION} | target: {domain} | DNS: {args.dns_mode}")

    counts = {"subfinder": 0, "findomain": 0, "crtsh": 0, "unique": 0, "scoped": 0, "live": 0}
    dns_stats = {key: 0 for key in ("resolved", "timeout", "nxdomain", "nodata", "servfail", "refused", "other")}
    transport = "not run"

    with tempfile.TemporaryDirectory(prefix="reconflow_") as temp:
        work = Path(temp)
        subfinder_hosts = discover_subfinder(domain, work)
        findomain_hosts = discover_findomain(domain, work)
        crtsh_hosts = discover_crtsh(domain)
        counts["subfinder"] = len(subfinder_hosts)
        counts["findomain"] = len(findomain_hosts)
        counts["crtsh"] = len(crtsh_hosts)

        discovered = sorted(set(subfinder_hosts + findomain_hosts + crtsh_hosts))
        counts["unique"] = len(discovered)
        scoped = normalize_hosts(discovered, domain)
        counts["scoped"] = len(scoped)
        info(f"Unique entries: {len(discovered)} | in-scope: {len(scoped)}")

        resolved, dns_stats, transport = resolve_hosts(scoped, domain, args, work)
        live = probe_http(resolved, work)
        counts["live"] = len(live)

    if not save_lines(live_path, live):
        return 1
    report = make_report(domain, counts, dns_stats, transport, args.resolver, args.timeout, args.retry)
    if not write_text(report_path, report):
        return 1

    info(f"Scan complete. Results: {target_dir}")
    info(f"  live.txt:   {live_path}")
    info(f"  report.txt: {report_path}")
    if not SILENT:
        print("\n========== Live HTTP Results ==========")
        print("\n".join(live) if live else "No responsive HTTP URLs found.")
        print(f"\nReport saved to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
