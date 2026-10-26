"""Scope-aware HTTP crawler.

Secret Hunter is deliberately NOT a DNS enumeration tool.  It does not
resolve or brute-force subdomains; it only makes plain HTTP(S) requests to
the seed targets and follows links and JavaScript references *within scope*.
This keeps it friendly to use behind a VPN such as Mullvad, where DNS-based
enumeration is often unreliable, while still collecting the pages and JS that
a secret scan needs.

Scope is determined purely from the URL string (scheme + registrable domain),
never from a DNS query.
"""

from __future__ import annotations

import concurrent.futures
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from .patterns import extract_candidates

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/123.0 Safari/537.36",
]

LINK_RE = re.compile(
    r"""(?:href|src|action|data-src|poster)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Common registrable-domain helpers for scope matching (no DNS involved).
_TWO_PART_TLDS = {
    "co.uk", "org.uk", "com.au", "com.br", "com.mx", "co.jp", "com.tr",
    "com.sg", "com.cn", "com.hk", "co.in", "net.au", "org.au", "co.nz",
}


def registrable_domain(host: str) -> str:
    """Best-effort root domain from a hostname (no DNS resolution)."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in _TWO_PART_TLDS:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@dataclass
class Page:
    url: str
    status: int
    content_type: str
    text: str
    is_js: bool
    is_sourcemap: bool = False


@dataclass
class CrawlResult:
    pages: list[Page] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)
    js_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def all_text(self) -> list[tuple[str, str]]:
        """Return (source_label, text) pairs for every fetched document."""
        out: list[tuple[str, str]] = []
        for p in self.pages:
            label = p.url
            if p.is_sourcemap:
                label += " (source map)"
            out.append((label, p.text))
        return out


class Crawler:
    def __init__(self, targets: list[str], depth: int = 2, max_urls: int = 200,
                 concurrency: int = 8, timeout: float = 15.0,
                 headers: dict[str, str] | None = None, same_root: bool = False,
                 fetch_sourcemaps: bool = True, cookies: str | None = None,
                 proxy: str | None = None):
        self.targets = targets
        self.depth = max(0, depth)
        self.max_urls = max(1, max_urls)
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.same_root = same_root
        self.fetch_sourcemaps = fetch_sourcemaps
        self.session = requests.Session()
        self.session.headers.update(self._default_headers(headers))
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if cookies:
            self._load_cookies(cookies)

    def _default_headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        base = {
            "User-Agent": USER_AGENTS[0],
            "Accept": "text/html,application/xhtml+xml,application/json,text/javascript,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if extra:
            base.update(extra)
        return base

    def _load_cookies(self, raw: str) -> None:
        for part in raw.split(";"):
            if "=" in part:
                name, value = part.strip().split("=", 1)
                self.session.cookies.set(name, value)

    # ------------------------------------------------------------------
    def crawl(self) -> CrawlResult:
        result = CrawlResult()
        queue: list[tuple[str, int]] = []
        for t in self.targets:
            if t not in result.visited:
                queue.append((t, 0))

        # Scope seeds.
        self._seed_scope(queue)

        while queue:
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < self.concurrency:
                batch.append(queue.pop(0))
            if not batch:
                break
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
                futures = {pool.submit(self._fetch, url, depth): (url, depth)
                           for url, depth in batch}
                for fut in concurrent.futures.as_completed(futures):
                    url, depth = futures[fut]
                    if url in result.visited:
                        continue
                    result.visited.add(url)
                    try:
                        page = fut.result()
                    except Exception as exc:  # noqa: BLE001
                        result.errors.append(f"{url}: {exc}")
                        continue
                    if page is None:
                        continue
                    result.pages.append(page)
                    if page.is_js:
                        result.js_urls.append(page.url)
                    # Discover more only up to the depth budget.
                    if depth >= self.depth:
                        continue
                    for child in self._discover(page, url):
                        if len(result.visited) >= self.max_urls:
                            break
                        if child not in result.visited:
                            queue.append((child, depth + 1))
                    if len(result.visited) >= self.max_urls:
                        break
        return result

    # ------------------------------------------------------------------
    def _seed_scope(self, queue: list[tuple[str, int]]) -> None:
        for t in self.targets:
            p = urlparse(t)
            if p.scheme and p.netloc:
                continue
            # Treat bare hostnames as https.
            queue.append((f"https://{t}", 0))

    def _fetch(self, url: str, depth: int) -> Page | None:
        resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
        ctype = resp.headers.get("Content-Type", "").lower()
        if resp.status_code >= 400:
            # Still return non-JS error pages sparingly; skip binary.
            if "html" not in ctype:
                return None
        is_js = _is_js_url(url) or "javascript" in ctype
        text = _decode(resp)
        if not is_js and text and self.fetch_sourcemaps:
            text = self._inline_sourcemaps(text, url)
        return Page(
            url=resp.url or url,
            status=resp.status_code,
            content_type=ctype,
            text=text,
            is_js=is_js,
        )

    def _inline_sourcemaps(self, text: str, base_url: str) -> str:
        """Append the text of any referenced source maps so maps get scanned too."""
        urls = re.findall(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\n\r]+)", text)
        combined = text
        for u in urls:
            full = urljoin(base_url, u.strip())
            if not self._in_scope(full):
                continue
            try:
                resp = self.session.get(full, timeout=self.timeout)
                if resp.status_code == 200:
                    combined += "\n\n// ---- source map ----\n" + _decode(resp)
            except requests.RequestException:
                continue
        return combined

    def _discover(self, page: Page, base_url: str) -> list[str]:
        if page.is_js:
            return self._discover_from_js(page.text, base_url)
        return self._discover_from_html(page.text, base_url)

    def _discover_from_html(self, text: str, base_url: str) -> list[str]:
        out: list[str] = []
        for m in LINK_RE.finditer(text):
            raw = m.group(1)
            if raw.startswith(("#", "mailto:", "javascript:", "data:", "tel:")):
                continue
            full = urljoin(base_url, raw)
            if self._in_scope(full):
                out.append(full)
        # Sitemap-driven discovery (no DNS; plain HTTP).
        if base_url:
            sitemap = urljoin(base_url, "sitemap.xml")
            if self._in_scope(sitemap):
                out.append(sitemap)
        return out

    def _discover_from_js(self, text: str, base_url: str) -> list[str]:
        out: list[str] = []
        # Absolute / relative JS + chunk references.
        for m in re.finditer(
            r"""["'`]((?:\.{0,2}/)?(?:static|assets|build|_next|_nuxt|_app|chunks|js|dist)/[A-Za-z0-9_./@~-]+\.m?js)["'`]""",
            text,
        ):
            full = urljoin(base_url, m.group(1))
            if self._in_scope(full):
                out.append(full)
        # import() / require() of local chunks.
        for m in re.finditer(r"""(?:import|require)\s*\(\s*["']((?:\.\.?/)[^"']+\.m?js)["']""", text):
            full = urljoin(base_url, m.group(1))
            if self._in_scope(full):
                out.append(full)
        return out

    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        if not p.scheme or not p.netloc:
            return False
        if p.scheme not in ("http", "https"):
            return False
        seed_domains = {registrable_domain(urlparse(t).netloc) for t in self.targets}
        host = p.netloc.split(":")[0].lower()
        root = registrable_domain(host)
        if self.same_root:
            return root in seed_domains
        return host in {urlparse(t).netloc.split(":")[0].lower() for t in self.targets}


def _is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs", ".jsx", ".ts", ".tsx")) or ".js?" in url


def _decode(resp: requests.Response) -> str:
    """Decode response bytes robustly, handling common charsets."""
    if not resp.content:
        return ""
    encoding = resp.encoding or resp.apparent_encoding or "utf-8"
    try:
        return resp.content.decode(encoding, errors="replace")
    except LookupError:
        return resp.content.decode("utf-8", errors="replace")
