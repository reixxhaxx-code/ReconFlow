# ReconFlow

**Lightweight recon. Clear results. No noise.**

ReconFlow is a beginner-friendly, sequential reconnaissance workflow that combines passive subdomain discovery, DNS resolution, and HTTP service discovery.

Built by **[reixxhaxx](https://github.com/reixxhaxx-code)** as a hands-on cybersecurity learning project.

> Use only on domains you own or have explicit permission to assess. Passive discovery does not authorize active DNS or HTTP probing.

## Features

- Passive subdomain discovery with [Subfinder](https://github.com/projectdiscovery/subfinder)
- Additional discovery with [Findomain](https://github.com/Findomain/Findomain)
- Certificate Transparency lookup through [crt.sh](https://crt.sh/)
- Hostname normalization, deduplication, and strict in-scope filtering
- DNS resolution with selectable `auto`, `udp`, and `tcp` modes
- In `auto` mode, checks UDP DNS first and falls back to direct DNS-over-TCP when the UDP probe or dnsx fails
- HTTP/HTTPS probing with [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx)
- Temporary intermediate files; only final result files are retained
- Sequential execution: no threads, multiprocessing, or async workers

## Requirements

- Linux (Kali or Parrot recommended)
- Python 3.9+
- Subfinder
- Findomain
- dig (usually provided by dnsutils or bind utilities)
- dnsx (required for `auto` and `udp` modes)
- ProjectDiscovery httpx
- Internet access for discovery sources

Make sure ProjectDiscovery's `httpx` is installed, not the unrelated Python HTTPX package. All external executables must be available in your `PATH`.

## Installation

```bash
git clone https://github.com/reixxhaxx-code/ReconFlow.git
cd ReconFlow
chmod +x reconflow.py
python3 reconflow.py -h
```

ReconFlow uses only Python's standard library; no `pip install` step is required.

## Usage

Show help:

```bash
python3 reconflow.py -h
```

Show logo and version:

```bash
python3 reconflow.py -v
```

Basic scan (auto DNS mode):

```bash
python3 reconflow.py -d example.com
```

Choose DNS transport:

```bash
python3 reconflow.py -d example.com --dns-mode auto
python3 reconflow.py -d example.com --dns-mode tcp
python3 reconflow.py -d example.com --dns-mode udp
```

Use a different resolver, timeout, or retry count:

```bash
python3 reconflow.py -d example.com --resolver 8.8.8.8 --timeout 3 --retry 1
```

Choose an output base directory:

```bash
python3 reconflow.py -d example.com -o results
```

Suppress informational progress messages:

```bash
python3 reconflow.py -d example.com -s
```

## DNS modes

| Mode | Behavior |
|---|---|
| `auto` | Tests UDP DNS reachability. Uses dnsx when reachable; falls back to sequential `dig +tcp` when UDP probing or dnsx fails. |
| `udp` | Uses dnsx over UDP. Unresolved results are reported as unclassified because dnsx output does not provide per-host DNS status classification here. |
| `tcp` | Resolves hosts sequentially using `dig +tcp`. |

The TCP fallback is a code-side transport choice. ReconFlow does not modify Kali's resolver configuration. Discovery tools and the crt.sh HTTPS request may still use the system's normal name-resolution/network path.

## Output

Each run creates a target-specific directory, for example:

```text
output/
└── example.com/
    ├── live.txt
    └── report.txt
```

- **live.txt** — HTTP-responsive URLs, including their status codes and available page titles.
- **report.txt** — discovery counts, DNS transport and resolution statistics, and warnings.

Intermediate files are stored in a temporary directory and automatically cleaned up.

## Workflow

```text
Subfinder
   |
Findomain
   |
crt.sh
   |
Merge + deduplicate
   |
Normalize + enforce target scope
   |
DNS resolution (auto / UDP / TCP)
   |
ProjectDiscovery httpx
   |
live.txt + report.txt
```

## Important notes and limitations

- ReconFlow is an early-stage learning project, not a production-grade scanner.
- Passive discovery sources can be incomplete or temporarily unavailable.
- DNS and HTTP results depend on resolver behavior, network policy, and target availability.
- A host responding over HTTP does not mean it is vulnerable.
- HTTP status codes such as 401, 403, and 404 are still valid responsive-service observations.
- ReconFlow performs discovery and HTTP service probing; it does not perform vulnerability testing or exploitation.
- TCP fallback applies to ReconFlow's explicit DNS-resolution stage. It does not force every third-party discovery tool or HTTPS client to use TCP DNS.
- The default resolver is 8.8.8.8; choose a resolver appropriate for your environment if needed.

## Responsible use

Only scan domains and systems you own or have explicit permission to assess. Confirm the authorized scope and rules before running active DNS resolution or HTTP probing. You are responsible for complying with applicable laws and program policies.

## Project

This is a learning project created to practice Python, Linux, subprocess handling, DNS, HTTP probing, and security-tool automation. Feedback and bug reports are welcome through GitHub Issues.

---

**ReconFlow v0.2.1 — created by reixxhaxx.**
