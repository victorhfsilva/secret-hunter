"""Secret detection patterns.

This module holds the compiled regular-expression catalog used to locate
candidate secrets inside crawled HTML, JavaScript, source maps and other
text.  Each pattern carries a human readable type label so downstream
consumers (LLM classification, validation, reporting) can reason about a
candidate without re-inspecting the raw bytes.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Regex catalog
# ---------------------------------------------------------------------------
# Each entry is (label, compiled regex, category hint).  The category hint is
# used by the LLM classifier to select the most appropriate analysis prompt.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Pattern:
    label: str
    regex: re.Pattern
    category: str


def _p(label: str, pattern: str, category: str, flags: int = 0) -> Pattern:
    return Pattern(label=label, regex=re.compile(pattern, flags), category=category)


PATTERNS: list[Pattern] = [
    # ---- Cloud & infrastructure --------------------------------------------
    _p("AWS Access Key",
       r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
       "api_key"),
    _p("AWS Secret Key",
       r"\b[A-Z0-9/+=]{40}\b", "credential"),
    _p("AWS Session Token",
       r"(?i)(aws_session_token|aws_security_token)\s*[:=]\s*['\"]([A-Za-z0-9+/=]{100,})['\"]",
       "credential"),
    _p("AWS ARN", r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9-_/:.]+", "internal_url"),
    _p("AWS Cognito Pool ID",
       r"(?i)(us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]+:[a-f0-9-]{36}", "api_key"),
    _p("AWS S3 Bucket URL",
       r"(?i)(?:s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]|[a-z0-9][a-z0-9.\-]{1,61}\.s3[.\-][a-z0-9\-]+\.amazonaws\.com)",
       "internal_url"),
    _p("GCP API Key", r"AIza[0-9A-Za-z\-_]{35}", "api_key"),
    _p("GCP Service Account",
       r"(?i)(?:project_id|private_key_id|private_key|client_email)[\"']?\s*[:=]\s*[\"'][^\"']+[\"']",
       "credential"),
    _p("Google OAuth Token", r"ya29\.[0-9A-Za-z\-_]+", "api_key"),
    _p("Google Maps API Key", r"AIzaSy[0-9A-Za-z\-_]{33}", "api_key"),
    _p("Azure Client Secret",
       r"(?i)client_secret\s*[:=]\s*['\"]([a-z0-9~_-]{34,})['\"]", "credential"),
    _p("Azure SAS Token", r"(?i)sig=[0-9A-Za-z%]{20,}", "credential"),
    _p("Azure Storage Key", r"(?i)(?:AccountKey|storage_account_key)\s*[:=]\s*['\"][A-Za-z0-9+/=]{40,}['\"]", "credential"),
    _p("DigitalOcean Token", r"dop_v1_[a-f0-9]{64}", "api_key"),
    _p("Cloudflare API Token", r"(?i)cloudflare.{0,20}(?:api_?token|token)\s*[:=]\s*['\"]([A-Za-z0-9_-]{40})['\"]", "api_key"),
    _p("New Relic", r"NRII-[A-Za-z0-9]{20,}", "api_key"),
    _p("Datadog API Key", r"(?i)(?:datadog|dd)[-_]?api[_ -]?key\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "api_key"),
    _p("Heroku API Key", r"(?i)(?:heroku|_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "api_key"),
    _p("Linear API Key", r"lin_api_[0-9a-zA-Z]{40}", "api_key"),
    _p("Notion Token", r"secret_[0-9a-zA-Z]{43}", "api_key"),
    _p("SendGrid Key", r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", "api_key"),
    _p("Mailgun Key", r"key-[0-9a-f]{32}", "api_key"),
    _p("Mailchimp Key", r"[0-9a-f]{32}-us[0-9]{1,2}", "api_key"),
    _p("Sentry DSN", r"(?i)(?:https?://[0-9a-f]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+)", "credential"),
    _p("Twilio SID", r"AC[0-9a-f]{32}", "api_key"),
    _p("Twilio Auth Token", r"(?i)twilio.{0,20}(?:auth[_ -]?token|token)\s*[:=]\s*['\"]([a-f0-9]{32})['\"]", "credential"),
    _p("NPM Token", r"npm_[0-9a-zA-Z]{36}", "api_key"),
    _p("PyPI Token", r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}", "api_key"),
    _p("Vercel Token", r"(?i)vercel.{0,20}(?:token|key)\s*[:=]\s*['\"]([a-z0-9]{24})['\"]", "api_key"),
    _p("Firebase Config", r"(?i)(?:firebase|projectId|databaseURL|storageBucket|messagingSenderId|appId)\s*[:=]\s*['\"][^\"']+['\"]", "credential"),
    _p("AWS MWS Key", r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "api_key"),
    # ---- AI / ML ------------------------------------------------------------
    _p("OpenAI Key", r"sk-(?:proj-|svcacct-|admin-|)[0-9a-zA-Z\-_]{20,}", "api_key"),
    _p("Anthropic Key", r"sk-ant-api03-[0-9a-zA-Z\-_]{20,}", "api_key"),
    _p("Hugging Face", r"hf_[0-9a-zA-Z]{34,}", "api_key"),
    _p("Groq Key", r"gsk_[0-9a-zA-Z]{40}", "api_key"),
    _p("Replicate", r"r8_[0-9a-zA-Z]{30,}", "api_key"),
    _p("Mistral", r"(?i)(?:mistral|mixtral).{0,20}(?:key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    _p("Cohere Key", r"(?i)(?:cohere|co).{0,20}(?:api[_ -]?key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    _p("Together AI Key", r"(?i)(?:together|togetherai).{0,20}(?:key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    _p("Perplexity Key", r"(?i)(?:perplexity|pplx).{0,20}(?:api[_ -]?key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    _p("xAI Key", r"(?i)(?:xai|grok).{0,20}(?:api[_ -]?key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    _p("OpenRouter Key", r"(?i)openrouter.{0,20}(?:api[_ -]?key|token)\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "api_key"),
    # ---- Auth & sessions ----------------------------------------------------
    _p("GitHub PAT", r"gh[pousr]_[0-9a-zA-Z]{36,}", "api_key"),
    _p("GitHub Fine-Grained PAT", r"github_pat_[0-9a-zA-Z_]{82}", "api_key"),
    _p("GitHub Refresh Token", r"ghr_[0-9a-zA-Z]{76}", "api_key"),
    _p("GitLab Token", r"glpat-[0-9a-zA-Z\-_]{20,}", "api_key"),
    _p("GitLab Runner Token", r"(?i)(?:runner|ci)[_-]?token\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "api_key"),
    _p("Slack Bot Token", r"xoxb-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24}", "api_key"),
    _p("Slack User Token", r"xox[psar]-[0-9]{10,}-[0-9]{10,}-[0-9a-zA-Z]{24,}", "api_key"),
    _p("Discord Bot Token", r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}", "api_key"),
    _p("Clerk Key", r"(?:pk|sk)_(?:test|live)_[0-9a-zA-Z]{20,}", "api_key"),
    _p("Supabase Key", r"(?:sb_publishable_|sb_secret_)[0-9a-zA-Z]{20,}", "api_key"),
    _p("Auth0 Key", r"(?i)auth0_.{0,20}(?:secret|key)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "api_key"),
    _p("Okta Token", r"(?i)okta.{0,20}(?:api[_ -]?token|token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{40})['\"]", "api_key"),
    _p("Grafana API Key", r"(?i)grafana.{0,20}(?:api[_ -]?key|token)\s*[:=]\s*['\"]([a-zA-Z0-9\-_]{20,})['\"]", "api_key"),
    # ---- Payments & finance ------------------------------------------------
    _p("Stripe Secret Key", r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}", "credential"),
    _p("Stripe Publishable", r"pk_(?:live|test)_[0-9a-zA-Z]{16,}", "api_key"),
    _p("PayPal Client ID", r"(?i)paypal.{0,20}(?:client[_ -]?id)\s*[:=]\s*['\"]([A-Za-z0-9_-]{30,})['\"]", "api_key"),
    _p("PayPal Secret", r"(?i)paypal.{0,20}(?:secret|client[_ -]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_-]{40,})['\"]", "credential"),
    _p("Square Access Token", r"sq0atp-[0-9A-Za-z\-_]{22}", "api_key"),
    _p("Square OAuth Secret", r"sq0csp-[0-9A-Za-z\-_]{43}", "credential"),
    _p("Adyen Key", r"(?i)adyen.{0,20}(?:key|secret)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "api_key"),
    _p("Braintree Token", r"(?i)(?:braintree|bt).{0,20}(?:token|key)\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]", "api_key"),
    # ---- Databases ----------------------------------------------------------
    _p("MongoDB Connection String", r"mongodb(\+srv)?://[^\s\"']+", "credential"),
    _p("PostgreSQL Connection String", r"postgres(ql)?://[^\s\"']+", "credential"),
    _p("MySQL Connection String", r"mysql://[^\s\"']+", "credential"),
    _p("Redis URL", r"redis://[^\s\"']+", "credential"),
    _p("SQL Server Connection String", r"(?i)(?:Server|Data Source)=[^;]+;.*(?:User ID|UID)=[^;]+;.*(?:Password|PWD)=[^;]+", "credential"),
    # ---- Generic auth / transport ------------------------------------------
    _p("JWT", r"eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}", "credential"),
    _p("Bearer Token", r"(?i)\bbearer\s+[A-Za-z0-9\-_\.]{20,}", "credential"),
    _p("Basic Auth", r"(?i)\bbasic\s+[A-Za-z0-9+/=]{20,}", "credential"),
    _p("Private Key (PEM)", r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----", "credential"),
    _p("Authorization Header", r"(?i)['\"]authorization['\"]\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "credential"),
    _p("Google OAuth Client ID", r"[0-9]{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com", "api_key"),
]

# Patterns that are almost always false positives in a JS bundle / source
# map and are worth filtering before they reach the LLM or the report.
WEAK_MARKERS: list[str] = [
    "your-", "your_", "xxxx", "XXX", "CHANGE_ME", "changeme", "insert_here",
    "<api-key>", "<token>", "TODO", "example", "sample", "demo", "test",
    "placeholder", "abcdef", "000000", "12345678", "anonymous",
]


@dataclass
class Candidate:
    label: str
    category: str
    value: str
    snippet: str
    source: str
    entropy: float
    line: int = 0
    column: int = 0

    def masked(self) -> str:
        return mask_value(self.value)

    def to_dict(self) -> dict:
        return {
            "type": self.label,
            "category": self.category,
            "value": self.value,
            "masked": self.masked(),
            "entropy": round(self.entropy, 2),
            "source": self.source,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet[:500],
        }


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_value(value: str) -> str:
    """Mask a candidate value so the raw secret is not sent to a remote LLM."""
    if len(value) <= 8:
        return value
    visible = min(4, len(value) // 4)
    masked_len = max(0, len(value) - visible * 2)
    block = "\u2588" * min(masked_len, 12)
    return f"{value[:visible]}{block}{value[-visible:]}"


def looks_like_placeholder(value: str) -> bool:
    """Heuristic: treat clearly fake / placeholder tokens as non-secrets."""
    low = value.lower()
    if any(marker in low for marker in WEAK_MARKERS):
        return True
    # Repeated single characters or very low entropy (base64 of static text).
    if len(set(value)) <= 4:
        return True
    if shannon_entropy(value) < 2.5 and len(value) < 64:
        return True
    return False


def extract_candidates(text: str, source: str) -> list[Candidate]:
    """Run the catalog over *text* and return deduplicated candidates."""
    found: dict[tuple[str, str], Candidate] = {}
    lines = text.splitlines()
    for pat in PATTERNS:
        for m in pat.regex.finditer(text):
            value = _pick_value(m)
            if looks_like_placeholder(value):
                continue
            # Compute line/column for reporting.
            start = m.start()
            line_no = text.count("\n", 0, start) + 1
            col = start - (text.rfind("\n", 0, start) + 1)
            snippet = _snippet(lines, line_no, value)
            key = (pat.label, value)
            if key not in found:
                found[key] = Candidate(
                    label=pat.label,
                    category=pat.category,
                    value=value,
                    snippet=snippet,
                    source=source,
                    entropy=shannon_entropy(value),
                    line=line_no,
                    column=col,
                )
    return list(found.values())


def _pick_value(m: re.Match) -> str:
    """Choose the most useful substring for a matched secret.

    Many patterns either match the secret directly (so the full match is
    ideal, e.g. an AWS key) or wrap it in a label assignment such as
    ``client_secret = "..."`` (where the quoted value is ideal).  We prefer the
    last capture group only when the full match clearly contains scaffolding
    (quotes, whitespace or an ``=``), otherwise we keep the whole match.
    """
    full = m.group(0)
    if m.lastindex and m.lastindex >= 1:
        captured = m.group(m.lastindex)
        if captured and any(ch in full for ch in "\"'=\t\n "):
            return captured
    return full


def _snippet(lines: list[str], line_no: int, value: str) -> str:
    if not lines or line_no < 1 or line_no > len(lines):
        return ""
    line = lines[line_no - 1]
    if len(line) > 500:
        line = line[:500] + "..."
    return line
