"""
Orion Security Platform — Katana Web Crawler & Spider.

Crawls target website to discover internal endpoints, form parameters,
JavaScript bundles, and application paths.
Wraps ProjectDiscovery's `katana` binary with fallback to an asynchronous
pure-Python web crawler seeded with AI priority paths.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
from orion.core.schemas import FormEntry, SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class KatanaCrawler(ToolInterface):
    name = "katana"

    def __init__(self, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)
        self.crawled_urls: list[str] = []
        self.forms: list[FormEntry] = []
        self.js_files: list[str] = []

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        urls, forms, js = await self.crawl(target, options)
        self.crawled_urls = urls
        self.forms = forms
        self.js_files = js

        vulns: list[VulnerabilityItem] = []
        # Flag exposed sensitive paths if crawled
        sensitive_patterns = [
            (r"\.env", "Exposed .env Configuration File", "critical"),
            (r"\.git/", "Exposed .git Source Code Repository", "high"),
            (r"phpinfo\.php", "Exposed PHPInfo Diagnostics Page", "medium"),
            (r"/wp-config\.php\.bak", "Exposed WordPress Config Backup", "critical"),
            (r"/admin/?$", "Exposed Administrative Portal", "info"),
        ]

        for u in urls:
            for pattern, title, severity in sensitive_patterns:
                if re.search(pattern, u, re.IGNORECASE):
                    vulns.append(
                        self.make_vuln(
                            title=title,
                            severity=severity,
                            service="http",
                            port=target.effective_port,
                            description=f"Crawler located sensitive resource accessible directly: {u}",
                            remediation_steps=[
                                "Restrict public access to administrative and internal configuration files.",
                                "Update web server rules to deny requests to hidden dot-files (.env, .git)."
                            ],
                        )
                    )
        return vulns

    async def crawl(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> tuple[list[str], list[FormEntry], list[str]]:
        """
        Executes crawler and returns (urls, forms, js_files).
        """
        options = options or {}
        depth = options.get("depth", 2)
        priority_paths = options.get("priority_paths", [])
        katana_bin = shutil.which("katana")

        if katana_bin:
            try:
                cmd = [
                    katana_bin,
                    "-u", target.url,
                    "-depth", str(depth),
                    "-silent",
                    "-json",
                    "-jc",  # Parse JavaScript endpoints
                ]
                returncode, stdout, stderr = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    return self._parse_katana_json(stdout, target)
            except Exception as e:
                logger.warning(f"Katana CLI failed, switching to python crawler: {e}")

        return await self._python_crawl(target, depth=depth, priority_paths=priority_paths)

    def _parse_katana_json(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> tuple[list[str], list[FormEntry], list[str]]:
        crawled_urls: set[str] = set()
        forms: list[FormEntry] = []
        js_files: set[str] = set()

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                endpoint = data.get("request", {}).get("endpoint") or data.get("url")
                if endpoint:
                    crawled_urls.add(endpoint)
                    if endpoint.endswith(".js"):
                        js_files.add(endpoint)
            except Exception:
                continue

        return sorted(list(crawled_urls)), forms, sorted(list(js_files))

    async def _python_crawl(
        self,
        target: SanitizedTarget,
        depth: int = 2,
        priority_paths: list[str] | None = None,
    ) -> tuple[list[str], list[FormEntry], list[str]]:
        """Asynchronous pure-Python web crawler with AI priority seeding."""
        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(target.url, 0)]
        discovered_urls: set[str] = {target.url}
        discovered_forms: list[FormEntry] = []
        discovered_js: set[str] = set()
        base_domain = target.hostname

        # Seed priority crawl paths recommended by AI Decision Point #1
        for path in (priority_paths or []):
            seed_url = urljoin(target.url, path)
            if seed_url not in discovered_urls:
                discovered_urls.add(seed_url)
                to_visit.append((seed_url, 1))

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            while to_visit and len(visited) < 40:
                current_url, cur_depth = to_visit.pop(0)
                if current_url in visited:
                    continue
                visited.add(current_url)

                try:
                    resp = await client.get(current_url)
                    if resp.status_code != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                        continue

                    html = resp.text

                    # Extract links
                    links = re.findall(r'href=["\'](.*?)["\']', html)
                    for link in links:
                        full_url = urljoin(current_url, link)
                        parsed = urlparse(full_url)
                        if parsed.hostname == base_domain and full_url not in discovered_urls:
                            discovered_urls.add(full_url)
                            if full_url.endswith(".js"):
                                discovered_js.add(full_url)
                            elif cur_depth + 1 <= depth:
                                to_visit.append((full_url, cur_depth + 1))

                    # Extract JS scripts
                    scripts = re.findall(r'src=["\'](.*?)["\']', html)
                    for script in scripts:
                        if script.endswith(".js"):
                            full_js = urljoin(current_url, script)
                            discovered_js.add(full_js)

                    # Extract forms (including action, method, and input parameters)
                    for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.DOTALL | re.I):
                        attrs = fm.group(1)
                        inner = fm.group(2)
                        action_m = re.search(r'action=["\'](.*?)["\']', attrs, re.I)
                        method_m = re.search(r'method=["\'](.*?)["\']', attrs, re.I)
                        action = action_m.group(1).strip() if action_m else None
                        method = method_m.group(1).strip().upper() if method_m else "GET"
                        inputs = re.findall(r'name=["\'](.*?)["\']', inner)
                        
                        # Add resolved action URL to discovered endpoints as well
                        if action:
                            resolved_action = urljoin(current_url, action)
                            parsed_act = urlparse(resolved_action)
                            if parsed_act.hostname == base_domain:
                                discovered_urls.add(resolved_action)

                        discovered_forms.append(
                            FormEntry(
                                url=current_url,
                                method=method,
                                action=action,
                                params=inputs,
                            )
                        )
                except Exception as e:
                    logger.debug(f"Crawler error on {current_url}: {e}")

        return sorted(list(discovered_urls)), discovered_forms, sorted(list(discovered_js))

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        return []
