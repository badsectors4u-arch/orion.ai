"""
Orion Security Platform — Reconnaissance AI Decision Analyzer (Decision Point #1).

Analyzes Phase 1 reconnaissance intelligence (tech stack, CMS, headers, subdomains)
to guide Phase 2 crawling and select optimal Nuclei vulnerability tags.
Includes a deterministic rule-based fallback when AI is unavailable.
"""
from __future__ import annotations

import logging
from typing import Any

from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import ReconResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are Orion's reconnaissance intelligence analyzer.
Given Phase 1 reconnaissance data (technologies, CMS, server headers, and discovered subdomains),
you must analyze the target's attack surface and respond with a JSON object containing:

1. "live_subdomains": Array of active subdomain strings that should be included in scanning.
2. "nuclei_tags": Array of template tags suited for the detected stack (e.g., ["wordpress", "nginx", "cve", "misconfig"]).
3. "jwt_detected": Boolean indicating if Authorization Bearer tokens or JWT headers are present.
4. "priority_paths": Array of priority URL paths to crawl based on the specific CMS and server technology.

Output ONLY valid JSON without markdown wrapping.
"""


class ReconAnalyzer:
    def __init__(self, ai_adapter: UniversalAIAdapter):
        self.ai = ai_adapter

    async def analyze(self, recon: ReconResult, target_url: str) -> dict[str, Any]:
        """Runs AI analysis on recon data with immediate rule-based fallback."""
        user_prompt = (
            f"Target URL: {target_url}\n"
            f"Technologies: {', '.join(recon.tech_fingerprint.technologies)}\n"
            f"Server Banner: {recon.tech_fingerprint.server}\n"
            f"CMS: {recon.cms_info.cms_name} (Version: {recon.cms_info.cms_version})\n"
            f"Plugins: {', '.join(recon.cms_info.plugins)}\n"
            f"Subdomains: {', '.join(s.subdomain for s in recon.subdomains if s.is_alive)}\n"
            f"Headers: {list(recon.tech_fingerprint.headers.keys())}\n"
        )

        try:
            resp = await self.ai.call(SYSTEM_PROMPT, user_prompt, json_mode=True)
            if resp.ok and isinstance(resp.data, dict):
                return {
                    "live_subdomains": resp.data.get("live_subdomains") or [s.subdomain for s in recon.subdomains if s.is_alive],
                    "nuclei_tags": resp.data.get("nuclei_tags") or self._heuristic_tags(recon),
                    "jwt_detected": bool(resp.data.get("jwt_detected")),
                    "priority_paths": resp.data.get("priority_paths") or self._heuristic_paths(recon),
                    "ai_powered": True,
                }
        except Exception as e:
            logger.warning(f"ReconAnalyzer AI call failed: {e}")

        # Deterministic fallback
        return {
            "live_subdomains": [s.subdomain for s in recon.subdomains if s.is_alive],
            "nuclei_tags": self._heuristic_tags(recon),
            "jwt_detected": "authorization" in recon.tech_fingerprint.headers,
            "priority_paths": self._heuristic_paths(recon),
            "ai_powered": False,
        }

    @staticmethod
    def _heuristic_tags(recon: ReconResult) -> list[str]:
        tags = ["cve", "misconfig", "exposure"]
        cms = (recon.cms_info.cms_name or "").lower()
        if "wordpress" in cms:
            tags.extend(["wordpress", "wp-plugin"])
        elif "drupal" in cms:
            tags.append("drupal")
        elif "joomla" in cms:
            tags.append("joomla")

        server = (recon.tech_fingerprint.server or "").lower()
        if "nginx" in server:
            tags.append("nginx")
        elif "apache" in server:
            tags.append("apache")
        elif "iis" in server:
            tags.append("iis")

        return list(set(tags))

    @staticmethod
    def _heuristic_paths(recon: ReconResult) -> list[str]:
        paths = ["/robots.txt", "/sitemap.xml", "/.env"]
        cms = (recon.cms_info.cms_name or "").lower()
        if "wordpress" in cms:
            paths.extend(["/wp-admin/", "/wp-json/", "/xmlrpc.php"])
        elif "drupal" in cms:
            paths.extend(["/user/login", "/core/"])
        elif "joomla" in cms:
            paths.extend(["/administrator/"])
        return paths

