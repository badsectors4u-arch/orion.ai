"""
Orion Security Platform — WhatWeb CMS & Framework Detection.

Identifies Content Management Systems (WordPress, Drupal, Joomla, Shopify),
installed plugins, themes, and server application frameworks.

Wraps WhatWeb binary with structured JSON logging, or executes an embedded
signature-based Python analyzer when Ruby/WhatWeb is not installed.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from typing import Any, Optional

import httpx
from orion.core.schemas import CMSInfo, SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class WhatWebScanner(ToolInterface):
    name = "whatweb"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.last_cms_info: Optional[CMSInfo] = None

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        cms_info, vulns = await self.detect_cms(target, options)
        self.last_cms_info = cms_info
        return vulns

    async def detect_cms(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> tuple[CMSInfo, list[VulnerabilityItem]]:
        """
        Detects CMS and frameworks, returning (CMSInfo, list[VulnerabilityItem]).
        """
        options = options or {}
        whatweb_bin = shutil.which("whatweb")

        if whatweb_bin:
            try:
                cmd = [
                    whatweb_bin,
                    target.url,
                    "--log-json", "-",
                    "--quiet",
                ]
                returncode, stdout, stderr = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    return self._parse_whatweb_json(stdout, target)
            except Exception as e:
                logger.warning(f"WhatWeb CLI failed, falling back to python signatures: {e}")

        return await self._python_fallback(target)

    def _parse_whatweb_json(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> tuple[CMSInfo, list[VulnerabilityItem]]:
        """Parse WhatWeb JSON output."""
        cms_name: Optional[str] = None
        cms_version: Optional[str] = None
        plugins: list[str] = []
        theme: Optional[str] = None
        vulns: list[VulnerabilityItem] = []

        try:
            data = json.loads(raw_output)
            if isinstance(data, list) and data:
                entry = data[0]
                plugins_data = entry.get("plugins", {})

                for plugin_key, details in plugins_data.items():
                    name_lower = plugin_key.lower()
                    if "wordpress" in name_lower:
                        cms_name = "WordPress"
                        version = details.get("version")
                        if version:
                            cms_version = str(version[0]) if isinstance(version, list) else str(version)
                    elif "drupal" in name_lower:
                        cms_name = "Drupal"
                    elif "joomla" in name_lower:
                        cms_name = "Joomla"
                    elif "shopify" in name_lower:
                        cms_name = "Shopify"
                    elif "magento" in name_lower:
                        cms_name = "Magento"
                    else:
                        plugins.append(plugin_key)

            if cms_name:
                desc = f"Target is running {cms_name}"
                if cms_version:
                    desc += f" version {cms_version}"
                vulns.append(
                    self.make_vuln(
                        title=f"CMS Detected: {cms_name} {cms_version or ''}".strip(),
                        severity="info",
                        service="http",
                        port=target.effective_port,
                        description=desc,
                        remediation_steps=[
                            "Keep CMS core and all third-party plugins regularly updated to their latest security patches."
                        ],
                    )
                )
        except Exception as e:
            logger.warning(f"Error parsing WhatWeb JSON: {e}")

        cms_info = CMSInfo(
            cms_name=cms_name,
            cms_version=cms_version,
            plugins=plugins[:20],
            theme=theme,
        )
        return cms_info, vulns

    async def _python_fallback(
        self,
        target: SanitizedTarget,
    ) -> tuple[CMSInfo, list[VulnerabilityItem]]:
        """Signature-based CMS and plugin detection."""
        cms_name: Optional[str] = None
        cms_version: Optional[str] = None
        plugins: list[str] = []
        theme: Optional[str] = None
        vulns: list[VulnerabilityItem] = []

        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(target.url)
                body = resp.text
                headers = resp.headers

                # WordPress Detection
                if "wp-content" in body or "wp-includes" in body:
                    cms_name = "WordPress"
                    # Try generator meta tag
                    gen_match = re.search(r'<meta name="generator" content="WordPress\s*([\d.]+)"', body, re.I)
                    if gen_match:
                        cms_version = gen_match.group(1)

                    # Extract common plugins
                    matches = re.findall(r"/wp-content/plugins/([a-zA-Z0-9_\-]+)/", body)
                    plugins = list(set(matches))

                    # Extract theme
                    theme_match = re.search(r"/wp-content/themes/([a-zA-Z0-9_\-]+)/", body)
                    if theme_match:
                        theme = theme_match.group(1)

                # Joomla Detection
                elif "joomla" in body.lower() or "/media/jui/" in body:
                    cms_name = "Joomla"

                # Drupal Detection
                elif "Drupal" in headers.get("X-Generator", "") or "drupal.js" in body:
                    cms_name = "Drupal"

                # Next.js / React
                elif "/_next/static/" in body:
                    cms_name = "Next.js"

                # Laravel
                elif "laravel_session" in headers.get("Set-Cookie", ""):
                    cms_name = "Laravel"

                # Django
                elif "csrftoken" in headers.get("Set-Cookie", ""):
                    cms_name = "Django"

                if cms_name:
                    vulns.append(
                        self.make_vuln(
                            title=f"CMS Detected: {cms_name} {cms_version or ''}".strip(),
                            severity="info",
                            service="http",
                            port=target.effective_port,
                            description=f"Identified web application framework/CMS as {cms_name}.",
                            remediation_steps=[
                                "Ensure core framework and modules receive continuous security updates."
                            ],
                        )
                    )
        except Exception as e:
            logger.warning(f"Python CMS detection fallback error: {e}")

        cms_info = CMSInfo(
            cms_name=cms_name,
            cms_version=cms_version,
            plugins=plugins[:20],
            theme=theme,
        )
        return cms_info, vulns

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        _, vulns = self._parse_whatweb_json(raw_output, target)
        return vulns

