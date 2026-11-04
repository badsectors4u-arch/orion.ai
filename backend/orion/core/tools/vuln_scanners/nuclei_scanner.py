"""
Orion Security Platform — Nuclei Vulnerability Scanner Engine & Native CVE Prober.

Executes ProjectDiscovery's `nuclei` template engine when available.
Provides an Active Python CVE & Misconfiguration Engine Fallback that probes for
exposed administrative consoles, ASP.NET trace handlers (trace.axd), diagnostic
endpoints, framework configuration leaks, and common CVE footprints.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

# High-impact common CVEs, misconfigurations, and sensitive exposure endpoints
HIGH_IMPACT_EXPOSURES = [
    (
        "/trace.axd",
        "ASP.NET Diagnostic Trace Viewer Exposed (trace.axd)",
        "high",
        r"Application Trace|Trace Information|Physical Path",
        "The application exposes the internal ASP.NET trace.axd diagnostic tool. It reveals physical server paths, session IDs, cookies, and internal requests.",
        ["Disable <trace enabled=\"false\" /> in web.config or restrict access to local administrators."],
        "CVE-2007-0038",
        7.5
    ),
    (
        "/elmah.axd",
        "ELMAH Error Log Viewer Exposed",
        "high",
        r"Error Log for|System\.Web\.HttpUnhandledException",
        "The application exposes ELMAH error logging console without authentication, leaking sensitive stack traces and credentials.",
        ["Secure the elmah.axd handler in web.config with strict authorization rules."],
        None,
        7.5
    ),
    (
        "/admin/login.jsp",
        "Exposed Administrative Management Interface",
        "medium",
        r"login|admin|password",
        "Administrative management portal is publicly accessible without IP restrictions or perimeter protection.",
        ["Place administrative interfaces behind VPN or restrict access via IP whitelisting."],
        None,
        5.0
    ),
    (
        "/bank/login.aspx",
        "Administrative Banking Interface Exposed",
        "medium",
        r"login|password|account",
        "Internal banking and administration endpoints are accessible from the public internet.",
        ["Implement multi-factor authentication (MFA) and perimeter firewall controls."],
        None,
        5.0
    ),
    (
        "/.env",
        "Environment Configuration File (.env) Disclosure",
        "critical",
        r"DB_PASSWORD=|APP_KEY=|AWS_SECRET|SECRET_KEY=",
        "Sensitive environment configuration containing database or API credentials was found exposed publicly.",
        ["Remove or block access to .env files in web server configuration immediately."],
        "CWE-200",
        9.1
    ),
    (
        "/.git/config",
        "Exposed Git Repository Configuration",
        "high",
        r"\[core\]|repositoryformatversion",
        "The target exposes its internal git repository configuration, permitting full source code download.",
        ["Restrict web access to the .git directory."],
        "CWE-538",
        7.5
    ),
    (
        "/actuator/health",
        "Spring Boot Actuator Endpoints Exposed",
        "medium",
        r"\"status\":",
        "Internal Spring Boot microservice metrics and health endpoints are accessible without authentication.",
        ["Secure Spring Actuator endpoints using Spring Security and bind only to internal interfaces."],
        None,
        5.3
    ),
    (
        "/web.config",
        "Exposed IIS web.config Configuration File",
        "high",
        r"<configuration>|<system\.webServer>",
        "The target exposes its Microsoft IIS web.config file, disclosing internal server architecture and connection parameters.",
        ["Configure IIS request filtering to deny .config extensions."],
        "CWE-200",
        7.5
    ),
]


class NucleiScanner(ToolInterface):
    name = "nuclei"

    def __init__(self, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        nuclei_bin = shutil.which("nuclei")
        tags = options.get("tags", [])

        if nuclei_bin:
            cmd = [
                nuclei_bin,
                "-u", target.url,
                "-jsonl",
                "-severity", "critical,high,medium",
                "-silent",
                "-duc",
            ]
            if tags:
                cmd.extend(["-tags", ",".join(tags)])

            try:
                returncode, stdout, stderr = await self.run_subprocess(cmd)
                if stdout.strip():
                    return await self.parse_output(stdout, target)
            except Exception as e:
                logger.warning(f"Nuclei execution failed, switching to native CVE prober: {e}")

        # Active Native Python CVE & Exposure Engine Fallback
        return await self._native_cve_checks(target)

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
                info = data.get("info", {})
                template_id = data.get("template-id", "nuclei-rule")
                name = info.get("name") or template_id
                severity = (info.get("severity") or "medium").lower()

                if severity not in ["critical", "high", "medium", "low", "info"]:
                    severity = "medium"

                classification = info.get("classification") or {}
                cve_id = classification.get("cve-id")
                if isinstance(cve_id, list) and cve_id:
                    cve_id = cve_id[0]

                cvss_score = classification.get("cvss-score")
                if cvss_score is not None:
                    try:
                        cvss_score = float(cvss_score)
                    except ValueError:
                        cvss_score = None

                description = info.get("description") or f"Detected via Nuclei template: {template_id}"
                matched_at = data.get("matched-at")
                if matched_at:
                    description += f"\nMatched at: {matched_at}"

                remediation = info.get("remediation")
                remediation_steps = [remediation] if remediation else [
                    "Review vendor advisory and apply the latest software patch or configuration fix."
                ]

                vulns.append(
                    self.make_vuln(
                        title=name,
                        severity=severity,
                        service="http",
                        port=target.effective_port,
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        description=description,
                        remediation_steps=remediation_steps,
                    )
                )
            except Exception as e:
                logger.debug(f"Failed to parse Nuclei JSON line: {e}")

        return vulns

    async def _native_cve_checks(self, target: SanitizedTarget) -> list[VulnerabilityItem]:
        """Probes for critical common misconfigurations, CVEs, and sensitive endpoints."""
        vulns: list[VulnerabilityItem] = []
        base = target.url.rstrip("/")

        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            for path, title, severity, signature, desc, fix, cve, cvss in HIGH_IMPACT_EXPOSURES:
                url = f"{base}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and re.search(signature, resp.text, re.IGNORECASE):
                        vulns.append(
                            self.make_vuln(
                                title=title,
                                severity=severity,
                                service="http",
                                port=target.effective_port,
                                cve_id=cve,
                                cvss_score=cvss,
                                description=f"{desc}\nAccessible URL: {url}",
                                remediation_steps=fix,
                            )
                        )
                except Exception:
                    pass

        return vulns
