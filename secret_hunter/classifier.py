"""LLM classification of candidate secrets.

Turns a detected candidate into a structured security judgement.  The model
is asked for criticality, a 0-10 score, whether it is reportable, impact,
remediation, an associated CWE and a short explanation.  Values are masked
before they are sent so a raw secret never leaves the local machine when a
remote provider (Verboo / OpenRouter) is used.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .providers import LlmClient, ProviderError, extract_json

CRITICALITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "FalsePositive"]


@dataclass
class Analysis:
    criticality: str = "Informational"
    score: float = 0.0
    reportable: bool = False
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    explanation: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _category_prompt(category: str) -> str:
    """Return the analysis prompt section tailored to a candidate category."""
    category = (category or "api_key").lower()
    if category == "credential":
        return (
            "You are a security analyst reviewing a potential credential leak found in "
            "application source code, bundles, source maps or HTML.\n\n"
            "FALSE POSITIVE indicators (classify as FalsePositive if ANY match):\n"
            "- Placeholder/default: 'password', '123456', 'admin', 'changeme', 'secret', 'test123'\n"
            "- Test credentials: 'admin:admin', 'root:root'\n"
            "- Connection strings pointing at localhost/127.0.0.1 with no real secret\n"
            "- Env-var placeholders: process.env.X, ${{X}}, import.meta.env.X\n"
            "- Base64 that decodes to non-credential data\n"
            "- Expired JWTs or tokens with only public claims\n"
            "- OAuth client_id without client_secret (public client)\n\n"
            "REAL credential indicators:\n"
            "- Database connection string with a live password in production code\n"
            "- Hardcoded Bearer/Basic token in an API call\n"
            "- Firebase/Supabase service-role key granting full admin access\n"
            "- JWT with admin/superuser claims and a valid expiration"
        )
    if category == "internal_url":
        return (
            "You are a security analyst reviewing a potential internal/staging URL or "
            "infrastructure reference found in application code.\n\n"
            "FALSE POSITIVE (classify as FalsePositive if ANY match):\n"
            "- Generic localhost in an error handler or fallback config\n"
            "- URLs in config templates/examples with placeholder domains\n"
            "- Private IPs in CSP headers (informational only)\n"
            "- Third-party CDN staging URLs (not target infrastructure)\n"
            "- Build-time dev-server URLs (localhost:3000/8080)\n\n"
            "REAL exposure indicators:\n"
            "- Internal API endpoint (api-internal.*, admin.*, staging.*, dev.*) in production code\n"
            "- Private IP/hostname reachable from the internet (SSRF target)\n"
            "- Staging environment with weaker auth than production\n"
            "- Hidden admin panel path or debug route"
        )
    # Default: API keys / auth tokens.
    return (
        "You are a security analyst specialized in finding hardcoded API keys and "
        "tokens leaked in JavaScript bundles, source maps, HTML and config files.\n\n"
        "TOKEN FORMAT VALIDATION (must match to be real):\n"
        "- AWS Access Keys: AKIA/ASIA/AGPA/AIDA/AROA prefix, exactly 20 chars, high entropy\n"
        "- OpenAI: sk-proj-/sk-svcacct-/sk-admin- prefix, 40+ chars\n"
        "- GitHub PAT: ghp_/gho_/ghu_/ghs_/ghr_ prefix\n"
        "- Slack: xoxb-/xoxp-/xoxa-/xoxs- prefix\n"
        "- Stripe: sk_live_/sk_test_/rk_live_/pk_live_ prefix\n"
        "- Discord Bot: three dot-separated Base64 parts\n"
        "- Anthropic: sk-ant-api03- prefix, 95+ chars\n"
        "- Supabase: eyJ prefix, or sb_publishable_/sb_secret_ prefix\n"
        "- Firebase: AIza prefix, 39 chars\n\n"
        "FALSE POSITIVE in bundles (classify as FalsePositive if ANY match):\n"
        "- Placeholder/example: 'your-', 'your_', 'CHANGE_ME', 'xxx', 'test', 'demo', "
        "'sample', 'TODO', 'INSERT_HERE', '<api-key>'\n"
        "- Env-var reference: process.env.*, import.meta.env.*, ${{...}}, getenv()\n"
        "- Webpack artifacts: __webpack_require__ module IDs, chunk hash strings\n"
        "- Build-time constants: __DEV__, __PROD__, NODE_ENV\n"
        "- npm package names, CSS class selectors, HTML IDs resembling tokens\n"
        "- Low entropy (< 3.0): repetitive/sequential strings\n\n"
        "Analyze strictly: is this a REAL hardcoded secret in production code?"
    )


def build_prompt(label: str, category: str, masked_value: str, source: str,
                 entropy: float, snippet: str) -> str:
    context = ""
    if snippet:
        context = f"\n\nCode context:\n```\n{snippet[:500]}\n```"
    entropy_info = (
        f"- Shannon entropy: {entropy:.2f} bits/char "
        "(real secrets typically 4.0-6.0, placeholders/test values < 3.5)"
    )
    return (
        f"{_category_prompt(category)}\n\n"
        f"Finding:\n"
        f"- Type: {label}\n"
        f"- Value: {masked_value}\n"
        f"- Source: {source}\n"
        f"{entropy_info}"
        f"{context}\n\n"
        "IMPORTANT: The 'explanation' field must clearly explain WHY you assigned this "
        "criticality. For Critical/High: explain the specific risk. For FalsePositive: "
        "explain why it is not exploitable.\n\n"
        "Respond with ONLY valid JSON:\n"
        '{"criticality": "Critical|High|Medium|Low|Informational|FalsePositive", '
        '"score": 0.0-10.0, "reportable": true/false, "impact": "brief impact", '
        '"remediation": "brief fix", "cwe": "CWE-XXX", '
        '"explanation": "1-2 sentence explanation"}'
    )


def _normalize_analysis(raw: dict[str, Any]) -> Analysis:
    criticality = str(raw.get("criticality", "Informational"))
    if criticality not in CRITICALITY_ORDER:
        # Map anything unrecognised down to Informational.
        criticality = "Informational"
    try:
        score = float(raw.get("score", 0.0))
    except (TypeError, ValueError):
        score = 0.0
    score = max(0.0, min(10.0, score))
    reportable = bool(raw.get("reportable", False))
    if criticality in ("Critical", "High") and not reportable:
        reportable = True
    return Analysis(
        criticality=criticality,
        score=score,
        reportable=reportable,
        impact=str(raw.get("impact", "")),
        remediation=str(raw.get("remediation", "")),
        cwe=str(raw.get("cwe", "")),
        explanation=str(raw.get("explanation", "")),
        raw=raw,
    )


def classify(client: LlmClient, candidate, mask: bool = False) -> Analysis:
    """Classify a single candidate with the configured provider.

    When *mask* is True the secret value is masked before being sent to the
    provider; otherwise the full value is sent (default).  Pass mask=True only
    if you do not want raw secrets to reach a remote LLM.
    """
    prompt = build_prompt(
        candidate.label,
        candidate.category,
        candidate.masked() if mask else candidate.value,
        candidate.source,
        candidate.entropy,
        candidate.snippet,
    )
    text = client.chat(prompt, max_tokens=1024, temperature=0.1)
    raw = extract_json(text)
    return _normalize_analysis(raw)


def classify_fallback(client: LlmClient, candidate, mask: bool = False) -> Analysis:
    """Best-effort classification; on any provider error return an unclassified
    record so a provider outage never aborts the whole scan."""
    try:
        return classify(client, candidate, mask=mask)
    except (ProviderError, Exception):  # noqa: BLE001
        return Analysis(
            criticality="Informational",
            score=0.0,
            reportable=False,
            impact="LLM classification unavailable",
            explanation="The provider did not return a usable classification for this candidate.",
        )
