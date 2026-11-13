"""
Orion Security Platform — Arjun Hidden Parameter Discovery.

Discovers hidden HTTP GET and POST query parameters on target URLs to expand
injection vectors for SQL injection, XSS, and SSRF.
Wraps the `arjun` tool or executes an asynchronous targeted parameter fuzzer.
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

# Top 30 most common hidden parameters
TOP_PARAMS = [
    "debug", "test", "admin", "redirect", "url", "next", "file", "page",
    "id", "user", "role", "cmd", "exec", "view", "show", "data",
    "token", "api_key", "key", "secret", "action", "callback", "source",
    "env", "config", "mode", "format", "load", "include", "path"
]


class ArjunScanner(ToolInterface):
    name = "arjun"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.hidden_params: dict[str, list[str]] = {}

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        urls = options.get("urls", [target.url])
        self.hidden_params = await self.discover_params(urls, target)

        vulns: list[VulnerabilityItem] = []
        for url, params in self.hidden_params.items():
            if any(p in ["debug", "admin", "cmd", "exec"] for p in params):
                vulns.append(
                    self.make_vuln(
                        title=f"Sensitive Parameter Discovered on {url}",
                        severity="medium",
                        service="http",
                        port=target.effective_port,
                        description=(
                            f"Hidden administrative or debug parameters identified: {', '.join(params)}. "
                            "These parameters may bypass access controls or enable debug functionality in production."
                        ),
                        remediation_steps=[
                            "Disable debug endpoints and parameters in production environments.",
                            "Validate and strictly sanitize all incoming query parameters."
                        ],
                    )
                )
        return vulns

    async def discover_params(
        self,
        urls: list[str],
        target: SanitizedTarget,
    ) -> dict[str, list[str]]:
        """Finds hidden parameters across candidate URLs."""
        results: dict[str, list[str]] = {}
        arjun_bin = shutil.which("arjun")

        # Prioritize top 5 endpoints
        candidate_urls = urls[:5] if urls else [target.url]

        for u in candidate_urls:
            discovered_on_url: list[str] = []

            if arjun_bin:
                try:
                    cmd = [arjun_bin, "-u", u, "-m", "GET", "--json"]
                    returncode, stdout, _ = await self.run_subprocess(cmd, timeout=15.0)
                    if returncode == 0 and stdout.strip():
                        try:
                            data = json.loads(stdout)
                            if isinstance(data, dict):
                                discovered_on_url = list(data.values())[0] if data.values() else []
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"Arjun CLI error on {u}: {e}")

            # Fallback heuristic
            if not discovered_on_url:
                discovered_on_url = await self._heuristic_fuzz(u)

            if discovered_on_url:
                results[u] = discovered_on_url

        return results

    async def _heuristic_fuzz(self, url: str) -> list[str]:
        """Heuristic check comparing response length/status when common params are injected."""
        found: list[str] = []
        try:
            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                baseline_resp = await client.get(url)
                base_len = len(baseline_resp.text)
                base_status = baseline_resp.status_code

                # Send batches of parameters
                params_dict = {p: "1" for p in TOP_PARAMS[:15]}
                test_resp = await client.get(url, params=params_dict)

                # If significant response length or status change occurred
                if abs(len(test_resp.text) - base_len) > 50 or test_resp.status_code != base_status:
                    # Isolate active param
                    for p in ["debug", "admin", "redirect", "url", "test"]:
                        p_resp = await client.get(url, params={p: "true"})
                        if abs(len(p_resp.text) - base_len) > 30:
                            found.append(p)
        except Exception:
            pass

        return found

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

