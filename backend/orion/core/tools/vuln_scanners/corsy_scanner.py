"""
Orion Security Platform — Corsy CORS Misconfiguration Scanner.

Audits Cross-Origin Resource Sharing (CORS) policies on target endpoints.
Detects critical CORS misconfigurations that allow malicious third-party origins
to exfiltrate user session cookies and private API responses.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class CorsyScanner(ToolInterface):
    name = "corsy"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        urls = options.get("urls", [target.url])
        return await self.check_cors(urls, target)

    async def check_cors(self, urls: list[str], target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        domain = target.hostname

        test_origins = [
            ("https://attacker-domain.com", "Arbitrary Origin Reflection"),
            ("null", "Null Origin Trusted"),
            (f"https://{domain}.attacker.com", "Subdomain Suffix Trust Bypass"),
            (f"https://attacker{domain}", "Domain Prefix Trust Bypass"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            for u in urls[:5]:
                for origin, attack_type in test_origins:
                    try:
                        headers = {"Origin": origin}
                        resp = await client.get(u, headers=headers)
                        acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower().strip()

                        # Critical: Reflects attacker origin and allows credentials
                        if acao == origin and acac == "true":
                            vulns.append(
                                self.make_vuln(
                                    title=f"Critical CORS Misconfiguration: {attack_type} with Credentials",
                                    severity="critical",
                                    service="http",
                                    port=target.effective_port,
                                    description=(
                                        f"Endpoint {u} reflects untrusted Origin '{origin}' in Access-Control-Allow-Origin "
                                        f"while setting Access-Control-Allow-Credentials to true. Malicious sites can "
                                        f"read authenticated private responses via JavaScript."
                                    ),
                                    remediation_steps=[
                                        "Do not dynamically reflect the incoming Origin header into Access-Control-Allow-Origin.",
                                        "Maintain a strict server-side whitelist of authorized frontend origins.",
                                        "Never combine 'Access-Control-Allow-Credentials: true' with wildcards or unvalidated origins."
                                    ],
                                )
                            )
                            break  # Found critical on this URL, move to next

                        # Medium: Reflects arbitrary origin without credentials
                        elif acao == origin and attack_type == "Arbitrary Origin Reflection":
                            vulns.append(
                                self.make_vuln(
                                    title="Overly Permissive CORS Origin Reflection",
                                    severity="medium",
                                    service="http",
                                    port=target.effective_port,
                                    description=f"Endpoint {u} reflects arbitrary Origin headers without credential sharing.",
                                    remediation_steps=[
                                        "Implement an explicit origin whitelist instead of reflecting all origins."
                                    ],
                                )
                            )
                            break
                    except Exception:
                        pass

        return vulns

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

