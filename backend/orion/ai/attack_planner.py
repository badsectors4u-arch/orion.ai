"""
Orion Security Platform — Attack Surface AI Planner (Decision Point #2).

Correlates reconnaissance and discovery intelligence (crawled URLs, forms, JS endpoints,
hidden parameters, leaked secrets) to synthesize a prioritized, high-efficiency AttackPlan
for Phase 4 specialized vulnerability scanners.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import AttackPlan, DiscoveryResult, ReconResult, VulnerabilityItem

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Orion's expert attack surface strategist.
Given Phase 1 reconnaissance and Phase 2 discovery data, synthesize a prioritized,
resource-efficient attack plan targeting the most exploitable endpoints.

Respond with a JSON object containing:
1. "sqlmap_targets": Top 15 URLs most likely susceptible to SQL injection (URLs with database-like params: id, cat, view, user, item, query).
2. "xss_targets": Top 15 URLs most likely susceptible to XSS (search, query, comment, input params).
3. "idor_targets": Top 10 API endpoints featuring sequential numeric IDs.
4. "ffuf_targets": Base domains/paths for fuzzing.
5. "corsy_targets": Base domains for CORS verification.
6. "skip_tools": Array of tool names to omit if no suitable targets exist.

Limit target lists to high-probability candidates to ensure scanning completes in under 90 seconds.
Output ONLY valid JSON.
"""


class AttackPlanner:
    def __init__(self, ai_adapter: UniversalAIAdapter):
        self.ai = ai_adapter

    async def build_plan(
        self,
        recon: ReconResult,
        discovery: DiscoveryResult,
        target_url: str,
        immediate_vulns: list[VulnerabilityItem] | None = None,
    ) -> AttackPlan:
        """Synthesizes AttackPlan using AI with heuristic fallback."""
        # Convert forms to testable URLs with query parameters
        form_urls: list[str] = []
        for f in discovery.forms:
            if f.params:
                target_base = f.url if f.url.startswith("http") else urljoin(target_url, f.url)
                if f.action:
                    target_base = urljoin(target_base, f.action)
                sample_qs = "&".join(f"{p}=test" for p in f.params)
                delim = "&" if "?" in target_base else "?"
                form_urls.append(f"{target_base}{delim}{sample_qs}")

        all_urls = sorted(list(set(discovery.crawled_urls + discovery.archived_urls + form_urls + [target_url])))

        # Determine JWT presence
        jwt_token = None
        for secret in discovery.leaked_secrets:
            if secret.type == "Generic JWT Token":
                jwt_token = secret.value
                break

        user_prompt = (
            f"Target URL: {target_url}\n"
            f"Discovered URLs count: {len(all_urls)}\n"
            f"Sample URLs: {all_urls[:25]}\n"
            f"Discovered Forms: {[f.url + ' (' + ','.join(f.params) + ')' for f in discovery.forms[:10]]}\n"
            f"JS Endpoints: {discovery.js_endpoints[:15]}\n"
            f"Hidden Parameters: {discovery.hidden_params}\n"
        )

        try:
            resp = await self.ai.call(SYSTEM_PROMPT, user_prompt, json_mode=True)
            if resp.ok and isinstance(resp.data, dict):
                data = resp.data
                return AttackPlan(
                    sqlmap_targets=data.get("sqlmap_targets") or self._heuristic_sqlmap_targets(all_urls, target_url),
                    xss_targets=data.get("xss_targets") or self._heuristic_xss_targets(all_urls, target_url),
                    ffuf_targets=data.get("ffuf_targets") or [target_url],
                    nuclei_targets=[target_url] + recon.live_subdomains[:5],
                    nuclei_tags=self._heuristic_nuclei_tags(recon),
                    corsy_targets=[target_url] + [f"https://{s}" for s in recon.live_subdomains[:3]],
                    jwt_enabled=bool(jwt_token or "authorization" in recon.tech_fingerprint.headers),
                    jwt_token=jwt_token,
                    idor_targets=data.get("idor_targets") or self._heuristic_idor_targets(all_urls),
                    skip_tools=data.get("skip_tools") or [],
                    immediate_vulns=immediate_vulns or [],
                )
        except Exception as e:
            logger.warning(f"AttackPlanner AI call failed: {e}")

        # Heuristic fallback plan
        return AttackPlan(
            sqlmap_targets=self._heuristic_sqlmap_targets(all_urls, target_url),
            xss_targets=self._heuristic_xss_targets(all_urls, target_url),
            ffuf_targets=[target_url],
            nuclei_targets=[target_url] + recon.live_subdomains[:5],
            nuclei_tags=self._heuristic_nuclei_tags(recon),
            corsy_targets=[target_url] + [f"https://{s}" for s in recon.live_subdomains[:3]],
            jwt_enabled=bool(jwt_token or "authorization" in recon.tech_fingerprint.headers),
            jwt_token=jwt_token,
            idor_targets=self._heuristic_idor_targets(all_urls),
            skip_tools=[],
            immediate_vulns=immediate_vulns or [],
        )

    @staticmethod
    def _heuristic_sqlmap_targets(urls: list[str], default_target: str) -> list[str]:
        sqli_patterns = [
            r"[?&]id=", r"[?&]user=", r"[?&]cat=", r"[?&]page=", r"[?&]view=", 
            r"[?&]item=", r"[?&]search=", r"[?&]query=", r"[?&]tfSearch=", r"[?&]keyword="
        ]
        matched = [u for u in urls if any(re.search(p, u, re.I) for p in sqli_patterns)]
        if not matched:
            matched = [u for u in urls if "?" in u]
        return matched[:25] if matched else [default_target]

    @staticmethod
    def _heuristic_xss_targets(urls: list[str], default_target: str) -> list[str]:
        xss_patterns = [
            r"[?&]q=", r"[?&]query=", r"[?&]search=", r"[?&]tfSearch=", 
            r"[?&]name=", r"[?&]keyword=", r"[?&]callback=", r"[?&]txt="
        ]
        matched = [u for u in urls if any(re.search(p, u, re.I) for p in xss_patterns)]
        if not matched:
            matched = [u for u in urls if "?" in u]
        return matched[:25] if matched else [default_target]

    @staticmethod
    def _heuristic_idor_targets(urls: list[str]) -> list[str]:
        idor_patterns = [r"/\d+/?$", r"/(?:user|order|account|invoice)s?/\d+", r"[?&]id=\d+"]
        matched = [u for u in urls if any(re.search(p, u, re.I) for p in idor_patterns)]
        return matched[:10]

    @staticmethod
    def _heuristic_nuclei_tags(recon: ReconResult) -> list[str]:
        tags = ["cve", "misconfig", "exposure"]
        cms = (recon.cms_info.cms_name or "").lower()
        if "wordpress" in cms:
            tags.append("wordpress")
        return tags
