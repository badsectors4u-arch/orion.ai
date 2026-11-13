"""
Orion Security Platform — Subfinder Passive Subdomain Enumeration.

Discovers subdomains passively via ProjectDiscovery's `subfinder` Go binary.
If absent, queries public Certificate Transparency (crt.sh) logs asynchronously.
Validates liveness and maps active IP addresses.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, SubdomainEntry, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class SubfinderScanner(ToolInterface):
    name = "subfinder"

    def __init__(self, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)
        self.last_subdomains: list[SubdomainEntry] = []

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        subdomains, vulns = await self.enumerate_subdomains(target, options)
        self.last_subdomains = subdomains
        return vulns

    async def enumerate_subdomains(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> tuple[list[SubdomainEntry], list[VulnerabilityItem]]:
        """
        Enumerates subdomains and returns (list[SubdomainEntry], list[VulnerabilityItem]).
        """
        options = options or {}
        subfinder_bin = shutil.which("subfinder")
        domain = target.hostname

        # Skip subdomain enumeration if target is an IP address
        if target.hostname.replace(".", "").isdigit():
            return [], []

        raw_subdomains: list[str] = []

        if subfinder_bin:
            try:
                cmd = [
                    subfinder_bin,
                    "-d", domain,
                    "-silent",
                    "-json",
                ]
                returncode, stdout, stderr = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    for line in stdout.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            host = item.get("host")
                            if host and host not in raw_subdomains:
                                raw_subdomains.append(host)
                        except json.JSONDecodeError:
                            if line and line not in raw_subdomains:
                                raw_subdomains.append(line)
            except Exception as e:
                logger.warning(f"Subfinder CLI execution failed: {e}")

        # Fallback to crt.sh if no subdomains found or tool not installed
        if not raw_subdomains:
            raw_subdomains = await self._crtsh_fallback(domain)

        # Ensure base domain is included
        if domain not in raw_subdomains:
            raw_subdomains.insert(0, domain)

        # Probe subdomains for liveness (top 30 max to stay fast)
        subdomain_entries = await self._probe_liveness(raw_subdomains[:30])

        vulns: list[VulnerabilityItem] = []
        if len(subdomain_entries) > 1:
            vulns.append(
                self.make_vuln(
                    title=f"Subdomains Discovered: {len(subdomain_entries)} Assets",
                    severity="info",
                    service="dns",
                    description=(
                        f"Passive reconnaissance identified {len(subdomain_entries)} related subdomains, "
                        f"expanding the overall attack surface (e.g. {', '.join(s.subdomain for s in subdomain_entries[:5])})."
                    ),
                    remediation_steps=[
                        "Regularly audit external DNS zones, decommission obsolete staging/dev subdomains, and prevent subdomain takeovers."
                    ],
                )
            )

        return subdomain_entries, vulns

    async def _crtsh_fallback(self, domain: str) -> list[str]:
        """Query Certificate Transparency logs on crt.sh."""
        subdomains: set[str] = set()
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if "*" not in sub and sub.endswith(domain):
                                subdomains.add(sub)
        except Exception as e:
            logger.debug(f"crt.sh query failed: {e}")

        return sorted(list(subdomains))

    async def _probe_liveness(self, subdomains: list[str]) -> list[SubdomainEntry]:
        """Probe subdomains concurrently for HTTP/HTTPS responsiveness."""
        results: list[SubdomainEntry] = []

        async def _check_sub(sub: str) -> SubdomainEntry:
            is_alive = False
            status_code = None
            resolved_ip = None

            # Resolve DNS
            try:
                loop = asyncio.get_running_loop()
                addrinfo = await loop.getaddrinfo(sub, None)
                if addrinfo:
                    resolved_ip = addrinfo[0][4][0]
            except Exception:
                pass

            # HTTP probe
            if resolved_ip:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
                        resp = await client.head(f"https://{sub}")
                        status_code = resp.status_code
                        is_alive = True
                except Exception:
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
                            resp = await client.head(f"http://{sub}")
                            status_code = resp.status_code
                            is_alive = True
                    except Exception:
                        pass

            return SubdomainEntry(
                subdomain=sub,
                ip=resolved_ip,
                status_code=status_code,
                is_alive=is_alive,
            )

        tasks = [_check_sub(s) for s in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return results

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []

