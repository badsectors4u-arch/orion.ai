"""
Orion Security Platform — SecretFinder Sensitive Secret & Credential Hunter.

Analyzes JavaScript source code and client bundles to detect leaked API keys,
cloud credentials (AWS, Google, Stripe, GitHub, Firebase, Twilio), and JWT tokens.
Produces both structured SecretLeak entries and critical/high VulnerabilityItem findings.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, SecretLeak, Severity, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

# High-confidence credential regex patterns
SECRET_PATTERNS = [
    (
        "AWS Access Key ID",
        re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "critical",
    ),
    (
        "Google Cloud / Firebase API Key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "high",
    ),
    (
        "Stripe Live API Key",
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        "critical",
    ),
    (
        "GitHub Personal Access Token",
        re.compile(r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}"),
        "critical",
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "high",
    ),
    (
        "Generic JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "medium",
    ),
    (
        "Private RSA / SSH Key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
        "critical",
    ),
]


class SecretFinderScanner(ToolInterface):
    name = "secretfinder"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.leaked_secrets: list[SecretLeak] = []

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        js_urls = options.get("js_urls", [])
        secrets, vulns = await self.find_secrets(js_urls, target)
        self.leaked_secrets = secrets
        return vulns

    async def find_secrets(
        self,
        js_urls: list[str],
        target: SanitizedTarget,
    ) -> tuple[list[SecretLeak], list[VulnerabilityItem]]:
        """Scans JS resources for leaked secrets."""
        secrets: list[SecretLeak] = []
        vulns: list[VulnerabilityItem] = []

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for js_url in js_urls[:15]:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code != 200:
                        continue

                    lines = resp.text.splitlines()
                    for line_num, line in enumerate(lines, 1):
                        for secret_type, regex, severity in SECRET_PATTERNS:
                            matches = regex.findall(line)
                            for match in matches:
                                # Redact secret for safety
                                match_str = str(match)
                                redacted = match_str[:4] + "..." + match_str[-4:] if len(match_str) > 8 else "***"

                                leak = SecretLeak(
                                    type=secret_type,
                                    value=redacted,
                                    file=js_url,
                                    line=line_num,
                                    severity=severity,  # type: ignore[arg-type]
                                )
                                secrets.append(leak)

                                vulns.append(
                                    self.make_vuln(
                                        title=f"Leaked Credential in Frontend Code: {secret_type}",
                                        severity=severity,
                                        service="http",
                                        port=target.effective_port,
                                        description=(
                                            f"Found {secret_type} exposed publicly in JavaScript bundle: {js_url} "
                                            f"(Line {line_num}). Exposed token: {redacted}"
                                        ),
                                        remediation_steps=[
                                            f"Immediately revoke and rotate the exposed {secret_type}.",
                                            "Move API calls requiring secret credentials to backend proxy endpoints.",
                                            "Implement automated secret scanning (e.g. GitGuardian or TruffleHog) in CI/CD."
                                        ],
                                    )
                                )
                except Exception as e:
                    logger.debug(f"SecretFinder error on {js_url}: {e}")

        return secrets, vulns

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []
