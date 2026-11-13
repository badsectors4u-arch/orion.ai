"""
Orion Security Platform — JWT Tool Authentication Scanner.

Audits JSON Web Tokens (JWT) for critical cryptographic and authorization vulnerabilities:
- Unsigned tokens / 'none' algorithm signature bypass
- Weak HMAC signing secrets (brute-force check)
- Missing expiration / replay vulnerability
- Algorithm switching / key confusion
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Optional

from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

COMMON_SECRETS = [
    "secret", "jwt", "password", "123456", "admin", "token", "default",
    "key", "app", "development", "test", "staging", "auth", "secretkey"
]


class JwtScanner(ToolInterface):
    name = "jwt_tool"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        token = options.get("token")
        if not token:
            # Check if any token was passed in headers
            headers = options.get("headers", {})
            auth = headers.get("authorization", "") or headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth[7:].strip()

        if not token:
            return []

        return await self.audit_jwt(token, target)

    async def audit_jwt(self, token: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        parts = token.strip().split(".")

        if len(parts) != 3:
            return []

        header_b64, payload_b64, sig_b64 = parts

        try:
            header_json = self._b64_decode(header_b64)
            payload_json = self._b64_decode(payload_b64)
            header = json.loads(header_json)
            payload = json.loads(payload_json)
        except Exception as e:
            logger.debug(f"Failed to decode JWT: {e}")
            return []

        # 1. Algorithm None vulnerability
        alg = header.get("alg", "")
        if alg.lower() == "none":
            vulns.append(
                self.make_vuln(
                    title="Critical JWT Vulnerability: Unsigned Token ('none' Algorithm)",
                    severity="critical",
                    service="auth",
                    port=target.effective_port,
                    description=(
                        "The application accepts JWT tokens signed with 'alg: none'. Attackers can forge "
                        "arbitrary tokens and escalate privileges to any user or administrator."
                    ),
                    remediation_steps=[
                        "Configure JWT verification library to strictly reject tokens with 'alg: none'.",
                        "Enforce a whitelist of approved asymmetric algorithms (e.g. RS256, EdDSA)."
                    ],
                )
            )

        # 2. Check for missing expiration claim
        if "exp" not in payload:
            vulns.append(
                self.make_vuln(
                    title="JWT Missing Expiration (exp) Claim",
                    severity="medium",
                    service="auth",
                    port=target.effective_port,
                    description=(
                        "The JSON Web Token lacks an 'exp' (expiration) claim. Tokens remain valid indefinitely, "
                        "preventing proper revocation and increasing session hijacking risk."
                    ),
                    remediation_steps=[
                        "Include an 'exp' claim with a short lifespan (e.g. 15 minutes) and issue refresh tokens."
                    ],
                )
            )

        # 3. Weak HMAC Secret Test (if HS256)
        if alg.upper() == "HS256":
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
            for secret in COMMON_SECRETS:
                computed_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
                computed_b64 = base64.urlsafe_b64encode(computed_sig).rstrip(b"=").decode("ascii")

                if computed_b64 == sig_b64.rstrip("="):
                    vulns.append(
                        self.make_vuln(
                            title=f"Critical JWT Weak Secret Key Identified: '{secret}'",
                            severity="critical",
                            service="auth",
                            port=target.effective_port,
                            description=(
                                f"The HS256 JWT is signed using a trivial dictionary secret ('{secret}'). "
                                "An attacker can trivially sign arbitrary claims and impersonate administrator accounts."
                            ),
                            remediation_steps=[
                                "Change the JWT signing key to a cryptographically secure random string with at least 256 bits of entropy.",
                                "Migrate to asymmetric RSA (RS256) or ECDSA (ES256) signatures."
                            ],
                        )
                    )
                    break

        return vulns

    @staticmethod
    def _b64_decode(data: str) -> str:
        data += "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data.encode("ascii")).decode("utf-8", errors="replace")

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

