#!/usr/bin/env python3
"""ReconFlow: lightweight recon workflow. Created by reixxhaxx."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

VERSION = "0.1.0"
AUTHOR = "reixxhaxx"
REQUIRED_TOOLS = ("subfinder", "findomain", "dnsx", "httpx")
SILENT = False

BANNER = r"""
 ____                        _____ _
|  _ \ ___  ___ ___  _ __   |  ___| | _____      __
| |_) / _ \/ __/ _ \| '_ \  | |_  | |/ _ \ \ /\ / /
|  _ <  __/ (_| (_) | | | | |  _| | | (_) \ V  V /
|_| \_\___|\___\___/|_| |_| |_|   |_|\___/ \_/\_/

"""


def info(message):
    if not SILENT:
        print(f"[INFO] {message}")


def warning(message):
    print(f"[WARN] {message}", file=sys.stderr)


def error(message):
    print(f"[ERROR] {message}", file=sys.stderr)


def valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    pattern = (
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}"
    )
    return re.fullmatch(pattern, domain) is not None


def check_dependencies():
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        error("Missing required tools: " + ", ".join(missing))
        error("Install the missing tools and run ReconFlow again.")
        return False
    info("All required tools are installed.")
    return True


def run_command(command, timeout=180):
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=timeout, check=False
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            if detail:
                warning(
                    f"{command[0]} returned an error: "
                    f"{detail.splitlines()[0][:200]}"
                )
        return result
    except FileNotFoundError:
        warning(f"Tool not found: {command[0]}")
    except subprocess.TimeoutExpired:
        warning(f"{command[0]} timed out after {timeout} seconds.")
    except Exception as exc:
        warning(f"{command[0]} failed: {exc}")
    return None


def read_lines(file_path):
    path = Path(file_path)
    if not path.exists():
        return []
    try:
        return [
            line.strip()
            for line in path.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines()
            if line.strip()
        ]
    except OSError as exc:
        warning(f"Could not read {path}: {exc}")
        return []


def save_lines(file_path, lines):
    path = Path(file_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(lines)
        path.write_text(
            content + ("\n" if lines else ""), encoding="utf-8"
        )
        return True
    except OSError as exc:
        error(f"Could not write {path}: {exc}")
        return False


def discover_subfinder(domain, work_dir):
    info("Starting Subfinder...")
    output_file = work_dir / "subfinder.txt"
    result = run_command([
        "subfinder", "-d", domain, "-silent", "-o", str(output_file)
    ])
    if result is None or result.returncode != 0:
        warning("Subfinder did not return results.")
        return []
    hosts = read_lines(output_file)
    info(f"Subfinder: {len(hosts)} results.")
    return hosts


def discover_findomain(domain, work_dir):
    info("Starting Findomain...")
    output_file = work_dir / "findomain.txt"
    result = run_command([
        "findomain", "-t", domain, "-u", str(output_file)
    ])
    if result is None or result.returncode != 0:
        warning("Findomain did not return results.")
        return []
    hosts = read_lines(output_file)
    info(f"Findomain: {len(hosts)} results.")
    return hosts


def discover_crtsh(domain):
    """Optional source: retry once, then continue if crt.sh is unavailable."""
    info("Querying crt.sh (optional source)...")
    query = urllib.parse.urlencode({
        "q": f"%.{domain}", "output": "json"
    })
    url = f"https://crt.sh/?{query}"

    for attempt in range(2):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": f"ReconFlow/{VERSION}"}
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                data = json.loads(response.read().decode("utf-8"))

            hosts = []
            for entry in data:
                name_value = entry.get("name_value", "")
                if isinstance(name_value, str):
                    hosts.extend(name_value.splitlines())

            info(f"crt.sh: {len(hosts)} results.")
            return hosts

        except (
            urllib.error.URLError, urllib.error.HTTPError,
            TimeoutError, json.JSONDecodeError, OSError, ValueError
        ) as exc:
            if attempt == 0:
                info("crt.sh request failed; retrying once...")
            else:
                warning(
                    f"crt.sh unavailable ({exc}). Continuing without it."
                )
    return []


def run_discovery(domain, work_dir):
    info("Running passive discovery sources in parallel...")
    with ThreadPoolExecutor(max_workers=3) as executor:
        subfinder_job = executor.submit(discover_subfinder, domain, work_dir)
        findomain_job = executor.submit(discover_findomain, domain, work_dir)
        crtsh_job = executor.submit(discover_crtsh, domain)

        subfinder_hosts = subfinder_job.result()
        findomain_hosts = findomain_job.result()
        crtsh_hosts = crtsh_job.result()

    unique_hosts = sorted(set(
        subfinder_hosts + findomain_hosts + crtsh_hosts
    ))
    info(f"Discovery complete: {len(unique_hosts)} unique entries.")
    return unique_hosts


def normalize_hosts(hosts, domain):
    clean_hosts = set()
    for host in hosts:
        if not isinstance(host, str):
            continue
        host = host.strip().lower().rstrip(".").removeprefix("*.")
        if not valid_domain(host):
            continue
        if host == domain or host.endswith("." + domain):
            clean_hosts.add(host)
    return sorted(clean_hosts)


def resolve_dns(hosts, work_dir):
    if not hosts:
        warning("No in-scope hosts to resolve.")
        return []

    info(f"Resolving {len(hosts)} hosts with dnsx...")
    input_file = work_dir / "scoped.txt"
    output_file = work_dir / "resolved.txt"

    if not save_lines(input_file, hosts):
        return []

    result = run_command([
        "dnsx", "-l", str(input_file), "-silent",
        "-o", str(output_file)
    ])
    if result is None or result.returncode != 0:
        warning("DNS resolution did not complete successfully.")
        return []

    resolved = read_lines(output_file)
    info(f"DNS resolution: {len(resolved)} hosts.")
    return resolved


def probe_http(hosts, work_dir):
    if not hosts:
        warning("No DNS-resolved hosts to probe.")
        return []

    info(f"Probing {len(hosts)} hosts with ProjectDiscovery httpx...")
    input_file = work_dir / "resolved.txt"
    json_file = work_dir / "httpx.json"

    if not save_lines(input_file, hosts):
        return []

    result = run_command([
        "httpx", "-l", str(input_file), "-silent",
        "-status-code", "-title", "-tech-detect",
        "-web-server", "-ip", "-json", "-o", str(json_file)
    ], timeout=240)

    if result is None or result.returncode != 0:
        warning("HTTP probing did not complete successfully.")
        return []

    live_results = []
    for line in read_lines(json_file):
        try:
            item = json.loads(line)
            url = item.get("url", "")
            status = item.get("status_code")
            if not url or not isinstance(status, int):
                continue
            title = str(item.get("title") or "")
            title = title.replace("\n", " ").replace("\r", " ").strip()
            live_results.append(f"{status} | {url} | {title}")
        except json.JSONDecodeError:
            continue

    live_results = sorted(set(live_results))
    info(f"HTTP probing: {len(live_results)} live URLs.")
    return live_results


def generate_report(domain, discovered, scoped, resolved, live):
    return [
        "========== ReconFlow Scan Report ==========",
        "",
        f"Version: {VERSION}",
        f"Target: {domain}",
        "",
        f"Unique discovered entries: {len(discovered)}",
        f"In-scope hostnames: {len(scoped)}",
        f"DNS-resolved hosts: {len(resolved)}",
        f"HTTP live URLs: {len(live)}",
        "",
        "========== Live Results ==========",
        "",
        *(live or ["No HTTP live results found."]),
        "",
        "========== End of Report =========="
    ]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="reconflow",
        description="ReconFlow - Lightweight reconnaissance workflow"
    )
    parser.add_argument(
        "-d", "--domain", required=True,
        help=(
            "Target domain (only scan systems you own "
            "or are authorized to assess)"
        )
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save live HTTP results to a file"
    )
    parser.add_argument(
        "-or", nargs="?", const=True, default=None,
        dest="report", metavar="REPORT_FILE",
        help="Print the report, or save it when a filename is supplied"
    )
    parser.add_argument(
        "-s", "-silent", "--silent", action="store_true",
        dest="silent",
        help="Hide progress messages (warnings and errors remain visible)"
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version=(
            BANNER
            + f"\n  ReconFlow v{VERSION}\n"
            + "  Lightweight recon. Clear results. No noise.\n"
            + f"  Created by {AUTHOR}\n"
            + "  https://github.com/reixxhaxx-code/ReconFlow\n"
        )
    )
    return parser


def main():
    global SILENT
    args = build_parser().parse_args()
    SILENT = args.silent
    domain = args.domain.lower().rstrip(".")

    if not valid_domain(domain):
        error("Invalid domain format.")
        sys.exit(2)
    if not check_dependencies():
        sys.exit(1)

    print()
    info(f"ReconFlow v{VERSION} starting for {domain}")
    print()

    with tempfile.TemporaryDirectory(prefix="reconflow_") as temp_dir:
        work_dir = Path(temp_dir)
        discovered_hosts = run_discovery(domain, work_dir)
        scoped_hosts = normalize_hosts(discovered_hosts, domain)
        info(f"In-scope hosts: {len(scoped_hosts)}")
        resolved_hosts = resolve_dns(scoped_hosts, work_dir)
        live_results = probe_http(resolved_hosts, work_dir)

    if args.report is not None:
        report = generate_report(
            domain, discovered_hosts, scoped_hosts,
            resolved_hosts, live_results
        )
        if args.report is True:
            print("\n".join(report))
        elif save_lines(args.report, report):
            info(f"Report saved to {args.report}")

    if args.output:
        if save_lines(args.output, live_results):
            info(f"Live results saved to {args.output}")
    elif args.report is not True:
        print("\n========== ReconFlow Live Results ==========")
        if live_results:
            for result in live_results:
                print(result)
        else:
            print("No HTTP live results found.")

    info("ReconFlow scan completed.")


if __name__ == "__main__":
    main()
