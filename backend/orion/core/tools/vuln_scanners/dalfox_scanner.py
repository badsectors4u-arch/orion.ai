"""
Orion Security Platform — DalFox Advanced XSS Scanner & Native Reflection Engine.

Executes `dalfox` when available to detect Reflected, Stored, and DOM XSS.
Provides an Active Python Parameter & Form Reflection Engine Fallback that audits
both GET query strings and POST form fields using multiple HTML/SVG breakout payloads.
"""
from __future__ import annotations

import json
import logging
import shutil
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx
from orion.core.schemas import FormEntry, SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class DalfoxScanner(ToolInterface):
    name = "dalfox"

    def __init__(self, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        dalfox_bin = shutil.which("dalfox")
        urls = options.get("urls", [target.url])
        forms = options.get("forms", [])

        if dalfox_bin:
            all_vulns: list[VulnerabilityItem] = []
            for u in urls[:5]:
                cmd = [
                    dalfox_bin,
                    "url", u,
                    "--format", "json",
                    "--silence",
                    "--skip-bav",
                ]
                try:
                    returncode, stdout, _ = await self.run_subprocess(cmd, timeout=30.0)
                    vulns = await self.parse_output(stdout, target)
                    all_vulns.extend(vulns)
                except Exception as e:
                    logger.debug(f"DalFox error on {u}: {e}")
            if all_vulns:
                return all_vulns

        # Active Native Python XSS Engine Fallback
        return await self._native_xss_test(urls, forms, target)

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []

        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                vuln_type = data.get("type", "XSS")
                param = data.get("param", "unknown")
                poc = data.get("poc", "")
                severity = "high"

                vulns.append(
                    self.make_vuln(
                        title=f"Cross-Site Scripting (XSS) in Parameter: {param}",
                        severity=severity,
                        service="http",
                        port=target.effective_port,
                        cve_id="CWE-79",
                        cvss_score=7.5,
                        description=(
                            f"Identified {vuln_type} vulnerability in parameter '{param}'. "
                            f"Proof of concept payload: {poc}"
                        ),
                        remediation_steps=[
                            "Contextually encode all user-supplied data before rendering into HTML/DOM.",
                            "Implement a robust Content Security Policy (CSP) with strict script-src directives.",
                            "Use modern frontend frameworks (React/Vue/Angular) that perform automatic output escaping."
                        ],
                    )
                )
            except Exception:
                pass

        return vulns

    async def _native_xss_test(
        self,
        urls: list[str],
        forms: list[FormEntry],
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        """Tests parameter and form reflection using HTML and SVG breakout payloads."""
        vulns: list[VulnerabilityItem] = []
        canary = "orionxss773"
        tested_form_targets: set[tuple[str, str]] = set()

        test_payloads = [
            f'"><script>{canary}</script>',
            f'"><img src=x onerror={canary}>',
            f'"><svg/onload={canary}>',
            f'\'"><svg/onload={canary}>',
        ]

        async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
            # 1. Audit Query Parameters
            for u in urls[:15]:
                parsed = urlparse(u)
                qs = parse_qs(parsed.query)
                if not qs:
                    continue

                for param in qs.keys():
                    for payload in test_payloads:
                        mutated_qs = dict(qs)
                        mutated_qs[param] = [payload]
                        new_query = urlencode(mutated_qs, doseq=True)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                        try:
                            resp = await client.get(test_url)
                            if payload in resp.text:
                                vulns.append(
                                    self.make_vuln(
                                        title=f"Reflected Cross-Site Scripting (XSS) in '{param}'",
                                        severity="high",
                                        service="http",
                                        port=target.effective_port,
                                        cve_id="CWE-79",
                                        cvss_score=7.5,
                                        description=(
                                            f"The application reflected an unescaped script tag payload in parameter '{param}'. "
                                            f"Injected URL: {test_url}\nInjected payload: {payload}"
                                        ),
                                        remediation_steps=[
                                            "Contextually HTML-encode user input before reflection.",
                                            "Enforce a Content-Security-Policy header blocking inline scripts."
                                        ],
                                    )
                                )
                                break
                        except Exception:
                            pass

            # 2. Audit HTML Forms (e.g. search boxes, feedback forms)
            for form in forms[:25]:
                base_url = form.url if form.url.startswith("http") else urljoin(target.url, form.url)
                target_form_url = urljoin(base_url, form.action) if form.action else base_url

                for param in form.params:
                    if param.lower() in ["submit", "btn", "__viewstate", "__eventvalidation"]:
                        continue

                    if (target_form_url, param) in tested_form_targets:
                        continue
                    tested_form_targets.add((target_form_url, param))

                    for payload in test_payloads[:2]:
                        form_data = {p: "test" for p in form.params}
                        form_data[param] = payload

                        try:
                            if form.method.upper() == "POST":
                                resp = await client.post(target_form_url, data=form_data)
                            else:
                                resp = await client.get(target_form_url, params=form_data)

                            if payload in resp.text:
                                vulns.append(
                                    self.make_vuln(
                                        title=f"Reflected XSS in Form Field '{param}' ({form.method})",
                                        severity="high",
                                        service="http",
                                        port=target.effective_port,
                                        cve_id="CWE-79",
                                        cvss_score=7.5,
                                        description=(
                                            f"HTML Form at {target_form_url} reflects unescaped script tags via input '{param}'."
                                        ),
                                        remediation_steps=[
                                            "Apply HTML entity encoding to form input reflections.",
                                            "Set Content-Security-Policy: default-src 'self'."
                                        ],
                                    )
                                )
                                break
                        except Exception:
                            pass

        return vulns
