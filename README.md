# DNSReaper
  ____  _   _ ____  ____                            
 |  _ \| \ | / ___||  _ \ ___  __ _ _ __   ___ _ __ 
 | | | |  \| \___ \| |_) / _ \/ _` | '_ \ / _ \ '__|
 | |_| | |\  |___) |  _ <  __/ (_| | |_) |  __/ |   
 |____/|_| \_|____/|_| \_\___|\__,_| .__/ \___|_|   
                                    |_|              
                                        by saifxcode

DNSReaper is a minimal, interactive Python tool for passive subdomain discovery during authorized security assessments. Enter a domain, and it collects public hostname data, validates DNS resolution, sorts valid subdomains, and saves them automatically.

> **Authorization required:** Use DNSReaper only against domains you own or have explicit permission to assess.

## Features

- Simple interactive workflow — no command-line flags
- Passive discovery from free, public sources
- Certificate Transparency collection via crt.sh and Cert Spotter
- Public hostname-index fallback when a CT source is unavailable
- Duplicate removal and domain-scoped hostname cleaning
- DNS validation for A and AAAA records
- Alphabetically sorted results
- Automatic output file: `<domain>-subdomains.txt`
- Graceful handling of invalid domains, network errors, DNS failures, rate limits, and timeouts
- No API keys, port scanning, vulnerability scanning, exploitation, or login testing

## Requirements

- Windows
- Python 3.13 or later

## Installation

Clone the repository and install the dependency:

```powershell
git clone https://github.com/saifxcode/DNSReaper.git
cd DNSReaper
py -m pip install -r requirements.txt
```

## Usage

Start DNSReaper:

```powershell
py dnsreaper.py
```

Enter only the target domain when prompted:

```text
Enter domain: example.com
```

Example output:

```text
Scanning example.com...

[+] mail.example.com
[+] portal.example.com
[+] www.example.com

Found 3 valid subdomains.
Results saved to example.com-subdomains.txt
```

## How it works

1. Retrieves candidate hostnames from public passive sources.
2. Removes wildcard entries, duplicates, unrelated domains, and malformed names.
3. Resolves each candidate through the system DNS resolver.
4. Displays and saves only names that resolve to an IPv4 or IPv6 address.

Results depend on the public data available at scan time. A source can be temporarily unavailable or rate-limited; DNSReaper continues with remaining sources.

## Scope and safety

DNSReaper is intentionally limited to passive hostname collection and DNS resolution. It does **not** include:

- Port or service scanning
- Vulnerability scanning
- Exploitation
- Login or credential testing
- Active brute-force enumeration

## Educational use

DNSReaper is provided for learning and authorized security testing only. You are responsible for obtaining permission before assessing any domain.
