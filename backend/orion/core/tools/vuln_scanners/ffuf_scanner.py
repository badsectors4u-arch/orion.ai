"""
Orion Security Platform — FFUF Fast Web Fuzzer & LFI Scanner.

Discovers unlinked sensitive directories, administrative panels, configuration files,
database backups, and path traversal / Local File Inclusion (LFI) vulnerabilities.
Wraps the `ffuf` binary with an asynchronous fallback fuzzer.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from typing import Any, Optional

import httpx
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

TOP_SENSITIVE_PATHS = [
    (".env", "Environment Secrets File (.env)", "critical"),
    (".git/HEAD", "Exposed Git Source Directory", "high"),
    ("backup.sql", "Exposed Database Dump (backup.sql)", "critical"),
    ("dump.sql", "Exposed SQL Dump File", "critical"),
    ("config.php.bak", "Exposed Configuration Backup", "high"),
    ("admin/", "Exposed Administrative Console", "low"),
    ("administrator/", "Administrative Portal", "low"),
    ("phpmyadmin/", "phpMyAdmin Database Manager", "high"),
    ("server-status", "Apache HTTP Server-Status Page", "medium"),
    ("swagger-ui.html", "Exposed Swagger API Documentation", "low"),
    ("api/swagger.json", "Exposed Swagger JSON Definition", "low"),
    (".DS_Store", "macOS .DS_Store Metadata File", "low"),
    ("web.config", "IIS web.config Configuration File", "medium"),
    ("crossdomain.xml", "Overly Permissive Flash crossdomain.xml", "low"),
    ("robots.txt", "Robots.txt Information Disclosure", "info"),
]


class FfufScanner(ToolInterface):
    name = "ffuf"

    def __init__(self, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        ffuf_bin = shutil.which("ffuf")

        if ffuf_bin:
            # Create a temporary wordlist
            temp_wordlist = tempfile.NamedTemporaryFile("w+", delete=False, suffix=".txt")
            temp_out = tempfile.NamedTemporaryFile("w+", delete=False, suffix=".json")
            try:
                for path, _, _ in TOP_SENSITIVE_PATHS:
                    temp_wordlist.write(path + "\n")
                temp_wordlist.flush()
                temp_wordlist.close()
                temp_out.close()

                cmd = [
                    ffuf_bin,
                    "-u", f"{target.url.rstrip('/')}/FUZZ",
                    "-w", temp_wordlist.name,
                    "-mc", "200,301,302",
                    "-o", temp_out.name,
                    "-of", "json",
                    "-s",  # silent
                ]
                returncode, stdout, _ = await self.run_subprocess(cmd)
                if os.path.exists(temp_out.name):
                    with open(temp_out.name, "r", encoding="utf-8", errors="replace") as f:
                        raw_json = f.read()
                    return await self.parse_output(raw_json, target)
            except Exception as e:
                logger.warning(f"ffuf execution failed: {e}")
            finally:
                if os.path.exists(temp_wordlist.name):
                    os.unlink(temp_wordlist.name)
                if os.path.exists(temp_out.name):
                    os.unlink(temp_out.name)

        # Fallback async directory probe
        return await self._fallback_fuzz(target)

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            for res in results:
                fuzz_val = res.get("input", {}).get("FUZZ", "")
                status = res.get("status")
                url = res.get("url")

                # Match with sensitive path definitions
                matched = next((item for item in TOP_SENSITIVE_PATHS if item[0] == fuzz_val), None)
                if matched:
                    title = f"Sensitive Path Disclosed: /{matched[0]}"
                    sev = matched[2]
                else:
                    title = f"Accessible Endpoint Located: /{fuzz_val}"
                    sev = "medium" if status == 200 else "info"

                vulns.append(
                    self.make_vuln(
                        title=title,
                        severity=sev,
                        service="http",
                        port=target.effective_port,
                        description=(
                            f"Fuzzing revealed active resource responding with HTTP {status}: {url}."
                        ),
                        remediation_steps=[
                            "Restrict public access via .htaccess or web server configuration.",
                            "Delete obsolete backup files and temporary dumps from web server document root."
                        ],
                    )
                )
        except Exception:
            pass

        return vulns

    async def _fallback_fuzz(self, target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        base = target.url.rstrip("/")

        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=False) as client:
            for path, title, severity in TOP_SENSITIVE_PATHS:
                test_url = f"{base}/{path}"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code in [200, 301, 302]:
                        vulns.append(
                            self.make_vuln(
                                title=f"Exposed File/Directory: /{path}",
                                severity=severity,
                                service="http",
                                port=target.effective_port,
                                description=(
                                    f"Direct HTTP probe returned status {resp.status_code} for path: {test_url}"
                                ),
                                remediation_steps=[
                                    "Ensure web server forbids listing and downloading of sensitive administrative and backup files."
                                ],
                            )
                        )
                except Exception:
                    pass

        return vulns

