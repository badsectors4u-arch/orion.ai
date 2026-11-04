"""
Orion Security Platform — HTTPX Tech Fingerprinting Scanner.

Wraps ProjectDiscovery's `httpx` Go binary to detect:
- HTTP status code and title
- Web server banners
- Technology stack (-tech-detect)
- CDN providers
- TLS configuration

Provides graceful Python fallback via `httpx` library if the binary is absent.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
from typing import Any, Optional

import httpx as python_httpx
from orion.core.schemas import SanitizedTarget, TechFingerprint, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)


class HttpxScanner(ToolInterface):
    name = "httpx"

    def __init__(self, timeout: float = 30.0) -> None:
        super().__init__(timeout=timeout)
        self.last_fingerprint: Optional[TechFingerprint] = None

    async def _run_impl(
        self,
        target: SanitizedTarget,
        options: dict[str, Any],
    ) -> list[VulnerabilityItem]:
        fingerprint, vulns = await self.fingerprint(target, options)
        self.last_fingerprint = fingerprint
        return vulns

    async def fingerprint(
        self,
        target: SanitizedTarget,
        options: Optional[dict[str, Any]] = None,
    ) -> tuple[TechFingerprint, list[VulnerabilityItem]]:
        """
        Execute httpx and return both the structured TechFingerprint and any
        immediate informational / misconfiguration findings.
        """
        options = options or {}
        httpx_bin = shutil.which("httpx")

        if httpx_bin:
            try:
                cmd = [
                    httpx_bin,
                    "-u", target.url,
                    "-silent",
                    "-json",
                    "-tech-detect",
                    "-status-code",
                    "-title",
                    "-server",
                    "-tls-grab",
                ]
                returncode, stdout, stderr = await self.run_subprocess(cmd)
                if returncode == 0 and stdout.strip():
                    return self._parse_httpx_json(stdout, target)
            except Exception as e:
                logger.warning(f"Binary httpx failed, falling back to python httpx: {e}")

        # Fallback using Python httpx
        return await self._python_fallback(target)

    def _parse_httpx_json(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> tuple[TechFingerprint, list[VulnerabilityItem]]:
        """Parse JSON output from projectdiscovery/httpx."""
        fingerprint = TechFingerprint()
        vulns: list[VulnerabilityItem] = []

        try:
            for line in raw_output.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                data = json.loads(line)

                server = data.get("webserver") or data.get("server")
                technologies = data.get("tech", []) or []
                status_code = data.get("status_code", 0)
                title = data.get("title", "")
                cdn = data.get("cdn_name") or data.get("cdn")
                ip = data.get("host") or target.resolved_ip
                tls = data.get("tls", {})
                tls_version = tls.get("version") if isinstance(tls, dict) else None

                fingerprint = TechFingerprint(
                    server=server,
                    technologies=technologies,
                    cdn=cdn,
                    status_code=status_code,
                    title=title,
                    ip=ip,
                    tls_version=tls_version,
                    headers=data.get("header", {}) if isinstance(data.get("header"), dict) else {},
                )

                # Check for informational vulnerability: Server banner exposure
                if server and re.search(r"/\d+(\.\d+)*", server):
                    vulns.append(
                        self.make_vuln(
                            title=f"Web Server Version Disclosure: {server}",
                            severity="info",
                            service="http",
                            port=target.effective_port,
                            description=(
                                f"The server exposed detailed version information: '{server}'. "
                                "Attackers can use known vulnerabilities targeting this specific build."
                            ),
                            remediation_steps=[
                                "Disable version disclosure in web server configuration (e.g. server_tokens off in Nginx, ServerTokens Prod in Apache)."
                            ],
                        )
                    )
                break
        except Exception as e:
            logger.warning(f"Error parsing httpx JSON: {e}")

        return fingerprint, vulns

    async def _python_fallback(
        self,
        target: SanitizedTarget,
    ) -> tuple[TechFingerprint, list[VulnerabilityItem]]:
        """Pure-Python fingerprinting fallback."""
        vulns: list[VulnerabilityItem] = []
        techs: list[str] = []
        server: Optional[str] = None
        status_code: int = 0
        title: Optional[str] = None
        cdn: Optional[str] = None
        headers_dict: dict[str, str] = {}

        try:
            async with python_httpx.AsyncClient(
                verify=False,
                timeout=10.0,
                follow_redirects=True,
            ) as client:
                resp = await client.get(target.url)
                status_code = resp.status_code
                headers_dict = {k.lower(): v for k, v in resp.headers.items()}
                server = headers_dict.get("server")

                # Detect CDN
                if "cf-ray" in headers_dict or "cloudflare" in (server or "").lower():
                    cdn = "Cloudflare"
                elif "x-amz-cf-id" in headers_dict or "cloudfront" in (server or "").lower():
                    cdn = "Amazon CloudFront"
                elif "x-akamai-transformed" in headers_dict:
                    cdn = "Akamai"

                # Extract title
                body = resp.text
                match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if match:
                    title = match.group(1).strip()

                # Basic Tech detection heuristics
                if "x-powered-by" in headers_dict:
                    techs.append(headers_dict["x-powered-by"])
                if "wp-content" in body or "wp-includes" in body:
                    techs.append("WordPress")
                if "react" in body.lower() or 'id="root"' in body or 'id="__next"' in body:
                    techs.append("React")
                if "vue" in body.lower() or 'id="app"' in body:
                    techs.append("Vue.js")
                if server:
                    techs.append(server.split("/")[0])

                if server and re.search(r"/\d+(\.\d+)*", server):
                    vulns.append(
                        self.make_vuln(
                            title=f"Web Server Version Disclosure: {server}",
                            severity="info",
                            service="http",
                            port=target.effective_port,
                            description=(
                                f"Web server version banner exposed: '{server}'."
                            ),
                            remediation_steps=[
                                "Configure web server to suppress banner tokens."
                            ],
                        )
                    )
        except Exception as e:
            logger.warning(f"Python httpx fallback error: {e}")

        fingerprint = TechFingerprint(
            server=server,
            technologies=list(set(techs)),
            cdn=cdn,
            status_code=status_code,
            title=title,
            ip=target.resolved_ip,
            tls_version="TLS 1.2/1.3" if target.scheme == "https" else None,
            headers=headers_dict,
        )
        return fingerprint, vulns

    async def parse_output(
        self,
        raw_output: str,
        target: SanitizedTarget,
    ) -> list[VulnerabilityItem]:
        _, vulns = self._parse_httpx_json(raw_output, target)
        return vulns

