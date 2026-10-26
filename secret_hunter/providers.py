"""LLM provider clients.

Secret Hunter enriches findings with an LLM classification pass.  All three
supported providers -- Verboo, OpenRouter and Ollama -- expose an
OpenAI-compatible ``/chat/completions`` endpoint, so a single client is used
and only the endpoint, key and default model change per provider.

Environment variables (all optional, CLI flags win):

    SECRET_HUNTER_PROVIDER   verboo | openrouter | ollama
    SECRET_HUNTER_BASE_URL   base URL (scheme + host, no trailing /v1)
    SECRET_HUNTER_API_KEY    bearer key (Verboo / OpenRouter)
    SECRET_HUNTER_MODEL      model name

Per-provider overrides:

    VERBOO_BASE_URL, VERBOO_API_KEY, VERBOO_MODEL
    OPENROUTER_BASE_URL, OPENROUTER_API_KEY, OPENROUTER_MODEL
    OLLAMA_BASE_URL, OLLAMA_API_KEY, OLLAMA_MODEL
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

import requests

PROVIDERS = ("verboo", "openrouter", "ollama")

DEFAULTS: dict[str, dict[str, str]] = {
    "verboo": {
        "base_url": os.environ.get("VERBOO_BASE_URL", "https://api.verboo.ai/v1"),
        "model": os.environ.get("VERBOO_MODEL", "verboo-3"),
    },
    "openrouter": {
        "base_url": os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        "model": os.environ.get("OPENROUTER_MODEL", "openrouter/auto"),
    },
    "ollama": {
        "base_url": os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        "model": os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b"),
    },
}


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    timeout: float = 120.0
    max_retries: int = 2
    retry_delay: float = 1.5

    @classmethod
    def from_env(cls, provider: str | None = None, base_url: str | None = None,
                 api_key: str | None = None, model: str | None = None,
                 timeout: float | None = None) -> "ProviderConfig":
        name = (provider or os.environ.get("SECRET_HUNTER_PROVIDER") or "ollama").lower()
        if name not in PROVIDERS:
            raise ValueError(f"Unsupported provider '{name}'. Choose from {', '.join(PROVIDERS)}")
        defaults = DEFAULTS[name]

        env_key = name.upper()
        base_url = base_url or os.environ.get("SECRET_HUNTER_BASE_URL") or os.environ.get(
            f"{env_key}_BASE_URL") or defaults["base_url"]
        model = model or os.environ.get("SECRET_HUNTER_MODEL") or os.environ.get(
            f"{env_key}_MODEL") or defaults["model"]
        api_key = api_key or os.environ.get("SECRET_HUNTER_API_KEY") or os.environ.get(
            f"{env_key}_API_KEY")
        # Ollama typically needs no key; OpenRouter / Verboo do.
        if name in ("openrouter", "verboo") and not api_key:
            api_key = ""
        timeout = timeout or float(os.environ.get("SECRET_HUNTER_TIMEOUT", "120"))

        return cls(
            name=name,
            base_url=base_url.rstrip("/"),
            model=model,
            api_key=api_key,
            timeout=timeout,
        )

    @property
    def chat_url(self) -> str:
        return f"{self.base_url}/chat/completions"


class ProviderError(RuntimeError):
    pass


class LlmClient:
    """Thin OpenAI-compatible chat client."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        if config.api_key:
            self.session.headers["Authorization"] = f"Bearer {config.api_key}"

    def chat(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.1) -> str:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Ollama chain-of-thought models otherwise return empty content.
        if self.config.name == "ollama":
            payload["think"] = False

        last_err: Exception | None = None
        for attempt in range(self.config.max_retries + 1):
            try:
                resp = self.session.post(
                    self.config.chat_url,
                    json=payload,
                    timeout=self.config.timeout,
                )
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < self.config.max_retries:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                    continue
                resp.raise_for_status()
                data = resp.json()
                content = data.get("choices", [{}])[0].get("message", {}).get("content")
                if not content:
                    raise ProviderError("LLM returned empty content")
                return content
            except requests.RequestException as exc:
                last_err = exc
                if attempt < self.config.max_retries:
                    time.sleep(self.config.retry_delay * (attempt + 1))
                    continue
                break
        raise ProviderError(f"LLM request failed after retries: {last_err}")

    def health_check(self) -> bool:
        try:
            resp = self.session.get(f"{self.base()}/models", timeout=10)
            return resp.ok
        except requests.RequestException:
            return False

    def base(self) -> str:
        return self.config.base_url


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort extraction of a JSON object from an LLM response."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip markdown code fences.
    if "```" in text:
        cleaned = text.replace("```json", "").replace("```", "").strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    raise ProviderError("Could not parse JSON from LLM response")
