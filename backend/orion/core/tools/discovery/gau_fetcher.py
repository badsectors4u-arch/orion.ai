"""
Orion Security Platform — GAU / Wayback URLs Archive Miner.

Fetches known URLs and historical parameters from web archives (Wayback Machine,
Common Crawl, AlienVault OTX) via `gau` or `waybackurls` CLI, with an asynchronous
fallback directly querying the Wayback Machine CDX API.
"""
from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class GauFetcher(ToolInterface):
    name = "gau"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.archived_urls: list[str] = []

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        self.archived_urls = await self.fetch_urls(target, options)
        return []

    async def fetch_urls(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> list[str]:
        """Fetches archived URLs."""
        options = options or {}
        limit = options.get("limit", 100)
        domain = target.hostname

        # 1. Try gau binary
        gau_bin = shutil.which("gau")
        if gau_bin:
            try:
                cmd = [gau_bin, domain, "--subs", "--mc", "200", "--threads", "2"]
                returncode, stdout, _ = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    return self._clean_urls(stdout.splitlines(), limit)
            except Exception as e:
                logger.debug(f"gau execution error: {e}")

        # 2. Try waybackurls binary
        wayback_bin = shutil.which("waybackurls")
        if wayback_bin:
            try:
                cmd = [wayback_bin, domain]
                returncode, stdout, _ = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    return self._clean_urls(stdout.splitlines(), limit)
            except Exception as e:
                logger.debug(f"waybackurls execution error: {e}")

        # 3. Direct CDX API query
        return await self._cdx_fallback(domain, limit)

    async def _cdx_fallback(self, domain: str, limit: int) -> list[str]:
        """Direct query to Wayback Machine CDX Server."""
        urls: set[str] = set()
        try:
            endpoint = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
            )
            async with httpx.AsyncClient(verify=False, timeout=12.0) as client:
                resp = await client.get(endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    # First row is headers: ["original"]
                    for row in data[1:]:
                        if row and isinstance(row, list):
                            urls.add(row[0])
        except Exception as e:
            logger.debug(f"CDX API query failed: {e}")

        return sorted(list(urls))[:limit]

    def _clean_urls(self, raw_lines: list[str], limit: int) -> list[str]:
        cleaned = set()
        for line in raw_lines:
            line = line.strip()
            if line and line.startswith("http"):
                cleaned.add(line)
        return sorted(list(cleaned))[:limit]

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

