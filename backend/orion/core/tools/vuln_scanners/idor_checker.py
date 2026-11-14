"""
Orion Security Platform — IDOR & Broken Access Control Checker.

Detects Insecure Direct Object References (IDOR / BOLA) by analyzing parameterized
endpoints, incrementing/decrementing numeric resource IDs, and verifying whether
unauthorized records are leaked across tenant boundaries.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class IdorChecker(ToolInterface):
    name = "idor"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        candidate_urls = options.get("urls", [])
        return await self.check_idor(candidate_urls, target)

    async def check_idor(self, urls: list[str], target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []

        async with httpx.AsyncClient(verify=False, timeout=6.0) as client:
            for u in urls[:5]:
                parsed = urlparse(u)

                # 1. Path-based IDOR: /api/v1/users/123
                path_match = re.search(r"/(user|order|account|invoice|doc|profile|item)s?/(\d+)", parsed.path, re.I)
                if path_match:
                    resource_type = path_match.group(1)
                    original_id = int(path_match.group(2))
                    tampered_id = original_id + 1

                    tampered_path = parsed.path.replace(f"/{original_id}", f"/{tampered_id}")
                    tampered_url = urlunparse((parsed.scheme, parsed.netloc, tampered_path, parsed.params, parsed.query, parsed.fragment))

                    try:
                        resp_orig = await client.get(u)
                        resp_tamp = await client.get(tampered_url)

                        # If both return 200 and return structured JSON with different content without auth failure
                        if (
                            resp_orig.status_code == 200
                            and resp_tamp.status_code == 200
                            and "application/json" in resp_tamp.headers.get("Content-Type", "")
                            and len(resp_tamp.text) > 20
                            and resp_tamp.text != resp_orig.text
                        ):
                            vulns.append(
                                self.make_vuln(
                                    title=f"Potential Insecure Direct Object Reference (IDOR) on /{resource_type}s",
                                    severity="high",
                                    service="http",
                                    port=target.effective_port,
                                    description=(
                                        f"Modifying resource identifier from {original_id} to {tampered_id} at {tampered_url} "
                                        f"returned valid JSON data without enforcing object-level authorization."
                                    ),
                                    remediation_steps=[
                                        "Implement server-side authorization checks verifying that the requesting user owns the object.",
                                        "Use indirect, unpredictable identifiers (UUIDv4) instead of sequential integers.",
                                        "Enforce Role-Based Access Control (RBAC) at the service layer."
                                    ],
                                )
                            )
                            continue
                    except Exception:
                        pass

                # 2. Query parameter-based IDOR: ?id=100
                qs = parse_qs(parsed.query)
                for id_param in ["id", "user_id", "account_id", "order_id"]:
                    if id_param in qs and qs[id_param][0].isdigit():
                        orig_val = int(qs[id_param][0])
                        tamp_val = orig_val + 1
                        mutated_qs = dict(qs)
                        mutated_qs[id_param] = [str(tamp_val)]
                        new_query = urlencode(mutated_qs, doseq=True)
                        tampered_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                        try:
                            resp_orig = await client.get(u)
                            resp_tamp = await client.get(tampered_url)
                            if (
                                resp_orig.status_code == 200
                                and resp_tamp.status_code == 200
                                and resp_tamp.text != resp_orig.text
                                and len(resp_tamp.text) > 30
                            ):
                                vulns.append(
                                    self.make_vuln(
                                        title=f"Suspected IDOR via Query Parameter '{id_param}'",
                                        severity="high",
                                        service="http",
                                        port=target.effective_port,
                                        description=(
                                            f"Parameter '{id_param}' accepted sequential identifier {tamp_val} returning distinct data."
                                        ),
                                        remediation_steps=[
                                            "Validate current session ownership for the requested object on every API call."
                                        ],
                                    )
                                )
                        except Exception:
                            pass

        return vulns

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

