"""Passive subdomain discovery via Certificate Transparency.

This module finds subdomains of one or more domains WITHOUT doing any DNS
resolution or brute-forcing.  It queries public certificate-transparency
logs (crt.sh) over plain HTTP(S) and collects the hostnames that appear in
issued certificates.  Because it is HTTP-based, it keeps working behind a VPN
such as Mullvad, where DNS enumeration is unreliable.

Only the hostnames found here are used; the actual HTTP requests to each host
are still made by the crawler.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
from urllib.parse import urlparse

import requests

# crt.sh endpoint; override with SECRET_HUNTER_CRT_SH_URL (useful for tests or
# a self-hosted CT-log frontend).  The {domain} placeholder is replaced.
CRT_SH_URL = os.environ.get("SECRET_HUNTER_CRT_SH_URL",
                            "https://crt.sh/?q=%25.{domain}&output=json")

# crt.sh sometimes returns huge responses; keep a sane cap per domain.
MAX_SUBDOMAINS_PER_DOMAIN = 500
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


def _query_crtsh(domain: str, timeout: float, proxy: str | None) -> list[str]:
    """Return subdomain hostnames for *domain* from crt.sh, or [] on failure."""
    url = CRT_SH_URL.format(domain=domain)
    headers = {"User-Agent": UA, "Accept": "application/json"}
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, proxies=proxies)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []

    found: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        # name_value is a newline-separated list of SANs; common_name is a
        # single name.  Collect both, then normalize.
        for raw in (entry.get("name_value"), entry.get("common_name")):
            if not raw:
                continue
            for name in str(raw).splitlines():
                found.update(_normalize_names(name, domain))
    return sorted(found)[:MAX_SUBDOMAINS_PER_DOMAIN]


def _normalize_names(value: str, domain: str) -> set[str]:
    """Clean a CT-log name into usable subdomain hostnames under *domain*."""
    out: set[str] = set()
    for name in re.split(r"[\s,]+", value):
        name = name.strip().lower().strip(".")
        if name.startswith("*."):
            # Wildcards only tell us a label exists; keep the concrete part.
            name = name.lstrip("*.")
        if not name or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
            continue
        if name.endswith("." + domain):
            out.add(name)
        elif name == domain:
            out.add(name)
    return out


def discover_subdomains(domains: list[str], timeout: float = 20.0,
                        concurrency: int = 8, proxy: str | None = None) -> dict[str, list[str]]:
    """Discover subdomains for a list of domains concurrently.

    Returns a mapping {domain: [subdomain, ...]}.  A domain that could not be
    queried (offline, no entries) simply maps to an empty list.
    """
    normalized = [_normalize_domain(d) for d in domains if _normalize_domain(d)]
    results: dict[str, list[str]] = {d: [] for d in normalized}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {pool.submit(_query_crtsh, d, timeout, proxy): d for d in normalized}
        for fut in concurrent.futures.as_completed(futures):
            d = futures[fut]
            try:
                results[d] = fut.result()
            except Exception:  # noqa: BLE001
                results[d] = []
    return results


def _normalize_domain(domain: str) -> str:
    """Normalize a domain string, stripping scheme/path/port if present."""
    parsed = urlparse(domain.strip().lower())
    host = parsed.netloc or parsed.path or domain
    host = host.split(":")[0].strip(".")
    return host if re.fullmatch(r"[a-z0-9][a-z0-9.-]*", host) else ""


def read_domains_file(path: str) -> list[str]:
    """Read a newline/whitespace-separated list of domains from a text file."""
    domains: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host = _normalize_domain(line)
                if host:
                    domains.append(host)
    except OSError as exc:
        raise ValueError(f"Could not read domains file {path}: {exc}") from exc
    return domains
