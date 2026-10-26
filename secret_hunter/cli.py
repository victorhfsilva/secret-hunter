"""secret-hunter -- web secret / credential hunter for authorized security testing.

A simplified, HTTP-only rewrite of a larger Rust security scanner.  It crawls
web pages and JavaScript, extracts candidate secrets with a regex catalog,
optionally enriches them with an LLM (Verboo, OpenRouter or Ollama) and emits
a JSON + human-readable report.

It deliberately performs NO DNS enumeration (no dnsx-style subdomain
discovery), which makes it reliable behind a VPN such as Mullvad.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from . import __version__
from .classifier import classify_fallback
from .crawler import Crawler
from .patterns import extract_candidates
from .providers import ProviderConfig, LlmClient, ProviderError
from .report import build_report, render_text, write_json
from .validators import validate_token


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret-hunter",
        description="HTTP-only web secret/credential hunter for authorized testing.",
        epilog="No DNS enumeration is performed, so it works behind a VPN such as Mullvad.",
    )
    p.add_argument("targets", nargs="+",
                   help="Seed URL(s) or bare hostname(s) to scan (e.g. https://example.com or example.com).")
    p.add_argument("--provider", choices=("verboo", "openrouter", "ollama"),
                   help="LLM provider for enrichment. Default from SECRET_HUNTER_PROVIDER or 'ollama'.")
    p.add_argument("--base-url", help="Override the provider base URL (scheme+host).")
    p.add_argument("--api-key", help="Override the provider API key.")
    p.add_argument("--model", help="Override the provider model name.")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip LLM classification; regex + entropy only.")
    p.add_argument("--validate", action="store_true",
                   help="Optionally validate a few token types against live APIs (read-only).")
    p.add_argument("--depth", type=int, default=2, help="Crawl depth (default 2).")
    p.add_argument("--max-urls", type=int, default=200, help="Max URLs to fetch (default 200).")
    p.add_argument("--concurrency", type=int, default=8, help="Parallel fetches (default 8).")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds.")
    p.add_argument("--same-root", action="store_true",
                   help="Allow crawling sibling subdomains sharing the same registrable domain.")
    p.add_argument("--no-sourcemaps", action="store_true",
                   help="Do not fetch referenced .js.map source maps.")
    p.add_argument("--user-agent", help="Custom User-Agent string.")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="Extra request header in 'Name: value' form (repeatable).")
    p.add_argument("--cookie", help="Cookie string sent with every request.")
    p.add_argument("--proxy", help="HTTP(S) proxy URL for all requests.")
    p.add_argument("-o", "--output", help="Write JSON report to this path.")
    p.add_argument("--quiet", action="store_true", help="Suppress the console summary.")
    return p


def _parse_headers(items: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items:
        if ":" in item:
            name, value = item.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # ---- Crawl -----------------------------------------------------------
    headers = _parse_headers(args.header)
    if args.user_agent:
        headers["User-Agent"] = args.user_agent
    crawler = Crawler(
        targets=args.targets,
        depth=args.depth,
        max_urls=args.max_urls,
        concurrency=args.concurrency,
        timeout=args.timeout,
        headers=headers,
        same_root=args.same_root,
        fetch_sourcemaps=not args.no_sourcemaps,
        cookies=args.cookie,
        proxy=args.proxy,
    )
    try:
        result = crawler.crawl()
    except Exception as exc:  # noqa: BLE001
        print(f"[!] Crawl failed: {exc}", file=sys.stderr)
        return 1

    # ---- Extract ---------------------------------------------------------
    candidates: list[Any] = []
    for source, text in result.all_text():
        candidates.extend(extract_candidates(text, source))

    # ---- LLM classification ---------------------------------------------
    provider_name = args.provider
    config: ProviderConfig | None = None
    client: LlmClient | None = None
    if not args.no_llm:
        try:
            config = ProviderConfig.from_env(
                provider=args.provider, base_url=args.base_url,
                api_key=args.api_key, model=args.model,
            )
            client = LlmClient(config)
            provider_name = config.name
        except (ValueError, ProviderError) as exc:
            print(f"[!] LLM disabled: {exc}", file=sys.stderr)
            provider_name = None

    analyses: dict[str, dict] = {}
    if client and candidates:
        for cand in candidates:
            key = f"{cand.label}::{cand.value}"
            try:
                analyses[key] = classify_fallback(client, cand).to_dict()
            except Exception as exc:  # noqa: BLE001
                analyses[key] = {"criticality": "Informational",
                                 "score": 0.0, "reportable": False,
                                 "impact": f"classification error: {exc}"}

    # ---- Optional live validation ----------------------------------------
    if args.validate:
        for cand in candidates:
            key = f"{cand.label}::{cand.value}"
            validation = validate_token(cand.label, cand.value, timeout=args.timeout)
            analyses.setdefault(key, {"criticality": "Informational", "score": 0.0,
                                      "reportable": False})["validation"] = validation

    candidate_dicts = [c.to_dict() for c in candidates]
    report = build_report(
        candidate_dicts, analyses, args.targets, len(result.pages),
        result.errors, provider_name,
    )

    if args.output:
        try:
            write_json(report, args.output)
            if not args.quiet:
                print(f"[+] JSON report written to {args.output}")
        except OSError as exc:
            print(f"[!] Could not write report: {exc}", file=sys.stderr)
            return 1

    if not args.quiet:
        print(render_text(report))
    return 0
