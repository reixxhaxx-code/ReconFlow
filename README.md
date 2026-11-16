# ReconFlow

**Lightweight recon. Clear results. No noise.**

ReconFlow is a small command-line reconnaissance workflow I built to make the first steps of recon simple and understandable.

It brings a few useful tools together, runs passive discovery sources at the same time, checks which discovered hosts resolve in DNS, and then finds HTTP services.

I built this project while learning Python and cybersecurity. The goal is not to replace big recon frameworks. I wanted something lightweight that I can understand, use, improve, and keep learning from.

**Created by [reixxhaxx](https://github.com/reixxhaxx-code)**

---

## What it does

- Finds subdomains with **Subfinder**
- Finds subdomains with **Findomain**
- Gets certificate transparency results from **crt.sh** (optional)
- Runs the three discovery sources in parallel
- Cleans, deduplicates, and keeps results inside the target domain
- Resolves discovered hosts with **dnsx**
- Checks HTTP/HTTPS services with **ProjectDiscovery httpx**
- Shows status codes and page titles
- Can save live results or a scan report
- Uses temporary files for intermediate data, then cleans them up

## Tools used

| Tool | What ReconFlow uses it for |
|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery |
| [Findomain](https://github.com/Findomain/Findomain) | Subdomain discovery |
| [crt.sh](https://crt.sh/) | Certificate transparency lookup |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing |

## Requirements

- Linux is recommended (Kali or Parrot works)
- Python 3.9+
- Subfinder
- Findomain
- dnsx
- ProjectDiscovery httpx
- Internet connection for online discovery sources

The external tools must be installed and available in your system PATH.

> Make sure ProjectDiscovery's httpx is installed, not the Python HTTPX package.

## Installation

Clone the repository:

~~~bash
git clone https://github.com/reixxhaxx-code/ReconFlow.git
cd ReconFlow
~~~

Make sure the required tools are installed and available:

~~~bash
subfinder -version
findomain --help
dnsx -version
httpx -version
~~~

Run ReconFlow:

~~~bash
python3 reconflow.py -h
~~~

No extra Python packages are required. ReconFlow uses Python's standard library.

## Usage

Basic scan:

~~~bash
python3 reconflow.py -d example.com
~~~

Show the logo and version:

~~~bash
python3 reconflow.py -v
~~~

Hide progress messages:

~~~bash
python3 reconflow.py -d example.com -s
~~~

Save live HTTP results:

~~~bash
python3 reconflow.py -d example.com -o live.txt
~~~

Print a detailed report:

~~~bash
python3 reconflow.py -d example.com -or
~~~

Save the report:

~~~bash
python3 reconflow.py -d example.com -or report.txt
~~~

Save both live results and the report:

~~~bash
python3 reconflow.py -d example.com -o live.txt -or report.txt
~~~

## How the workflow runs

~~~text
                 ReconFlow
                     |
          +----------+----------+
          |          |          |
       Subfinder  Findomain   crt.sh
          |          |          |
          +----------+----------+
                     |
             Merge + deduplicate
                     |
              Scope filtering
                     |
                   dnsx
                     |
          ProjectDiscovery httpx
                     |
              Live HTTP results
                     |
                Report / file
~~~

Discovery runs in parallel. DNS resolution and HTTP probing run in order because HTTP probing needs the DNS-resolved hosts.

## crt.sh note

crt.sh is an optional source and can sometimes fail because of DNS, network, rate limits, or service availability. ReconFlow retries once and continues with the other discovery sources if crt.sh is unavailable.

A crt.sh failure does not mean the entire scan has failed.

## Example output

~~~text
========== ReconFlow Live Results ==========
200 | https://www.example.com | Example Domain
301 | https://old.example.com |
403 | https://private.example.com | Forbidden
~~~

The output above is only an example.

## Important limitations

- This is an early learning project, not a production-grade scanner.
- Results depend on the tools, data sources, DNS, and network conditions.
- Passive discovery cannot find every subdomain.
- A host responding over HTTP does not mean it is vulnerable.
- HTTP status codes such as 401, 403, and 404 are still useful responses.
- ReconFlow does not perform vulnerability testing or exploitation.
- Only basic error handling and source fallback are included.

## Responsible use

Use ReconFlow only on domains and systems you own or have explicit permission to assess.

Passive discovery does not give permission to actively probe a website. Make sure you have authorization before running DNS resolution or HTTP probing against a target.

You are responsible for following the target's rules, scope, and applicable laws.

## Why I made it

I made ReconFlow as a hands-on project to learn Python, Linux, subprocesses, automation, reconnaissance, and how security tools work together.

It is a small project, and I plan to improve it based on actual use and feedback instead of adding features just for the sake of it.

If you try it and find a bug or have a useful suggestion, feel free to open an issue.

---

**ReconFlow v0.1.0 — made by reixxhaxx.**
