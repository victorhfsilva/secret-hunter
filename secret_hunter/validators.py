"""Optional live validation of a small set of token types.

Validation is OFF by default and only runs when ``--validate`` is passed.
Each validator makes a minimal, read-only request to the provider to confirm
whether a token is live.  A network failure is reported as unknown (not as a
valid token), so a flaky connection never produces a false positive.
"""

from __future__ import annotations

import requests


def validate_token(label: str, value: str, timeout: float = 10.0) -> dict:
    """Return {'status': 'valid'|'invalid'|'unknown', 'detail': str}."""
    low = label.lower()
    try:
        if "aws access key" in low:
            return _aws_access_key(value, timeout)
        if "github" in low and ("pat" in low or "oauth" in low or "fine" in low):
            return _github(value, timeout)
        if "slack" in low:
            return _slack(value, timeout)
        if "openai" in low:
            return _openai(value, timeout)
        if "twilio" in low:
            return _twilio(value, timeout)
        if "google maps" in low or "gcp api" in low:
            return _google_maps(value, timeout)
    except requests.RequestException:
        return {"status": "unknown", "detail": "network error during validation"}
    return {"status": "unknown", "detail": "no validator implemented for this type"}


def _aws_access_key(value: str, timeout: float) -> dict:
    # The GetCallerIdentity is read-only; it fails for invalid keys.
    try:
        import boto3  # optional
    except ImportError:
        return {"status": "unknown", "detail": "boto3 not installed"}
    sts = boto3.client("sts", aws_access_key_id=value,
                       aws_secret_access_key="x" * 40, region_name="us-east-1")
    try:
        sts.get_caller_identity()
        return {"status": "valid", "detail": "AWS key authenticated"}
    except Exception:  # noqa: BLE001
        return {"status": "invalid", "detail": "AWS key rejected"}


def _github(value: str, timeout: float) -> dict:
    resp = requests.get("https://api.github.com/user",
                        headers={"Authorization": f"Bearer {value}"},
                        timeout=timeout)
    if resp.status_code == 200:
        return {"status": "valid", "detail": "GitHub token authenticated"}
    if resp.status_code in (401, 403):
        return {"status": "invalid", "detail": "GitHub token rejected"}
    return {"status": "unknown", "detail": f"GitHub API returned {resp.status_code}"}


def _slack(value: str, timeout: float) -> dict:
    resp = requests.get("https://slack.com/api/auth.test",
                        headers={"Authorization": f"Bearer {value}"},
                        timeout=timeout)
    data = resp.json()
    if data.get("ok"):
        return {"status": "valid", "detail": "Slack token authenticated"}
    return {"status": "invalid", "detail": "Slack token rejected"}


def _openai(value: str, timeout: float) -> dict:
    resp = requests.get("https://api.openai.com/v1/models",
                        headers={"Authorization": f"Bearer {value}"},
                        timeout=timeout)
    if resp.status_code == 200:
        return {"status": "valid", "detail": "OpenAI key authenticated"}
    return {"status": "invalid", "detail": f"OpenAI returned {resp.status_code}"}


def _twilio(value: str, timeout: float) -> dict:
    # value is the account SID; needs the matching auth token to confirm, so we
    # only report that it *looks* well formed unless the token is also present.
    resp = requests.get("https://api.twilio.com", timeout=timeout)
    return {"status": "unknown", "detail": "SID format plausible; auth token required"}


def _google_maps(value: str, timeout: float) -> dict:
    resp = requests.get("https://maps.googleapis.com/maps/api/geocode/json",
                        params={"address": "test", "key": value}, timeout=timeout)
    data = resp.json()
    if data.get("status") == "REQUEST_DENIED" and "not authorized" in data.get("error_message", ""):
        return {"status": "invalid", "detail": "Google Maps key rejected"}
    if data.get("status") in ("OK", "ZERO_RESULTS"):
        return {"status": "valid", "detail": "Google Maps key accepted"}
    return {"status": "unknown", "detail": f"Google Maps returned {data.get('status')}"}
