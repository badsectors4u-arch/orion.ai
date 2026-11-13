"""
Orion Security Platform — LinkFinder JavaScript Endpoint Extractor.

Disassembles JavaScript bundles and inline scripts using regular expressions
and AST matching to discover hidden API endpoints, routes, and paths.
Based on the GerbenJavado LinkFinder project specifications.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

# LinkFinder regex pattern for API endpoints inside JS
LINKFINDER_REGEX = re.compile(
    r"""(?:"|')("""
    r"""((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|"""
    r"""((?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]{1,}[^"'><,;|()]{1,})|"""
    r"""([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"\\']*)?)|"""
    r"""([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"\\']*)?)|"""
    r"""([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|xml|do)(?:[\?|#][^"\\']*)?)"""
    r""")(?:"|')""",
    re.VERBOSE,
)


class LinkFinderScanner(ToolInterface):
    name = "linkfinder"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.endpoints: list[str] = []

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        js_urls = options.get("js_urls", [])
        self.endpoints = await self.extract_endpoints(js_urls)
        return []

    async def extract_endpoints(self, js_urls: list[str]) -> list[str]:
        """Fetches and parses JS files to extract endpoint strings."""
        discovered: set[str] = set()

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            for js_url in js_urls[:15]:  # Analyze top 15 JS files
                try:
                    resp = await client.get(js_url)
                    if resp.status_code == 200:
                        content = resp.text
                        matches = LINKFINDER_REGEX.findall(content)
                        for match in matches:
                            endpoint = match[0].strip()
                            # Filter out noisy or static asset links
                            if endpoint and not endpoint.endswith((".png", ".jpg", ".jpeg", ".css", ".svg", ".woff", ".woff2")):
                                if "/" in endpoint and len(endpoint) < 200:
                                    discovered.add(endpoint)
                except Exception as e:
                    logger.debug(f"Failed to fetch JS {js_url}: {e}")

        return sorted(list(discovered))

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

