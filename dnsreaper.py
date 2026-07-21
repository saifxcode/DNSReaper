"""DNSReaper - passive subdomain discovery for authorized assessments only."""

from __future__ import annotations

import concurrent.futures
import re
import socket
import time
from pathlib import Path
from typing import Iterable

import requests


BANNER = r"""
  ____  _   _ ____  ____                            
 |  _ \| \ | / ___||  _ \ ___  __ _ _ __   ___ _ __ 
 | | | |  \| \___ \| |_) / _ \/ _` | '_ \ / _ \ '__|
 | |_| | |\  |___) |  _ <  __/ (_| | |_) |  __/ |   
 |____/|_| \_|____/|_| \_\___|\__,_| .__/ \___|_|   
                                    |_|              
                                        by saifxcode

"""

REQUEST_TIMEOUT = 10
REQUEST_RETRIES = 2
MAX_WORKERS = 8
DOMAIN_PATTERN = re.compile(
    r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalise_domain(value: str) -> str | None:
    """Return a safe, lower-case domain name or None when invalid."""
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    return domain if DOMAIN_PATTERN.fullmatch(domain) else None


def clean_names(names: Iterable[str], domain: str) -> set[str]:
    """Keep only fully-qualified hostnames belonging to domain."""
    suffix = f".{domain}"
    results: set[str] = set()
    for name in names:
        candidate = name.strip().lower().rstrip(".")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if candidate.endswith(suffix) and all(part for part in candidate.split(".")):
            results.add(candidate)
    return results


def get_with_retries(url: str, *, params: dict[str, str] | None = None) -> requests.Response:
    """Request a public source with small retry delays for transient failures."""
    last_error: requests.RequestException | None = None
    for attempt in range(REQUEST_RETRIES):
        try:
            response = requests.get(
                url,
                params=params,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": "DNSReaper/1.0 (authorized passive discovery)"},
            )
            if response.status_code not in {429} and response.status_code < 500:
                response.raise_for_status()
                return response
            last_error = requests.HTTPError(
                f"{response.status_code} Server Error: {response.reason} for url: {response.url}"
            )
        except requests.RequestException as exc:
            last_error = exc
        if attempt < REQUEST_RETRIES - 1:
            time.sleep(1 + attempt)
    raise last_error or requests.RequestException("Public source request failed")


def fetch_crtsh(domain: str) -> set[str]:
    """Collect DNS names published in crt.sh certificate transparency logs."""
    response = get_with_retries("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    records = response.json()
    names: list[str] = []
    for record in records:
        names.extend(record.get("name_value", "").splitlines())
        names.extend(record.get("common_name", "").splitlines())
    return clean_names(names, domain)


def fetch_certspotter(domain: str) -> set[str]:
    """Collect names from Cert Spotter's public certificate API."""
    response = get_with_retries(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    )
    names = [name for record in response.json() for name in record.get("dns_names", [])]
    return clean_names(names, domain)


def fetch_hackertarget(domain: str) -> set[str]:
    """Collect publicly indexed hostnames from HackerTarget's host search."""
    response = get_with_retries("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    if response.text.lower().startswith(("error", "api count exceeded")):
        raise requests.RequestException(response.text.strip())
    names = (line.partition(",")[0] for line in response.text.splitlines())
    return clean_names(names, domain)


def discover(domain: str) -> set[str]:
    sources = (
        ("crt.sh", fetch_crtsh),
        ("Cert Spotter", fetch_certspotter),
        ("HackerTarget", fetch_hackertarget),
    )
    discovered: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sources)) as executor:
        futures = {executor.submit(source, domain): label for label, source in sources}
        while futures:
            done, _ = concurrent.futures.wait(
                futures, timeout=0.2, return_when=concurrent.futures.FIRST_COMPLETED
            )
            print("\rSearching public certificate logs...", end="", flush=True)
            for future in done:
                label = futures.pop(future)
                try:
                    discovered.update(future.result())
                except (requests.RequestException, ValueError) as exc:
                    print(f"\n[!] {label} unavailable: {exc}")
    print("\rCollecting and resolving results...     ")
    return discovered


def resolves(hostname: str) -> bool:
    """Return whether the Windows/system DNS resolver finds an A or AAAA address."""
    try:
        return bool(
            socket.getaddrinfo(
                hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        )
    except (socket.gaierror, OSError):
        return False


def resolve_all(hostnames: Iterable[str]) -> list[str]:
    candidates = sorted(hostnames)
    valid: list[str] = []
    if not candidates:
        return valid
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(resolves, hostname): hostname for hostname in candidates}
        total = len(futures)
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            hostname = futures[future]
            try:
                if future.result():
                    valid.append(hostname)
            except Exception:
                pass
            print(f"\rResolving DNS: {completed}/{total}", end="", flush=True)
    print()
    return sorted(valid)


def save_results(domain: str, subdomains: list[str]) -> Path:
    output = Path(f"{domain}-subdomains.txt")
    output.write_text("\n".join(subdomains) + ("\n" if subdomains else ""), encoding="utf-8")
    return output


def main() -> int:
    print(BANNER)
    print("Use only on domains you own or are authorized to assess.\n")
    domain = normalise_domain(input("Enter domain: "))
    if domain is None:
        print("[!] Enter a valid domain name, for example: example.com")
        return 1

    print(f"\nScanning {domain}...\n")
    started = time.monotonic()
    try:
        candidates = discover(domain)
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
        return 130

    valid = resolve_all(candidates)
    for hostname in valid:
        print(f"[+] {hostname}")
    output = save_results(domain, valid)
    print(f"\nFound {len(valid)} valid subdomains.")
    print(f"Results saved to {output.name}")
    print(f"Completed in {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Scan cancelled.")
        raise SystemExit(130)
