"""
Orion Security Platform — Custom Web Scanners.

Contains three pure-Python scanners (no external binaries required):
- HeadersAnalyzer: Finds missing security headers (safely follows up to 3 redirects).
- SSLChecker: Validates SSL/TLS certificates manually (parses binary DER).
- XSSScanner: Basic reflected XSS check (non-DOM, non-blind).

SECURITY: Redirects are manually followed and re-validated via sanitize_target
to prevent SSRF bypasses (e.g., public URL -> 169.254.169.254).
"""
from __future__ import annotations

import asyncio
import logging
import os
import socket
import ssl
import tempfile
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import httpx

from orion.core.input_sanitizer import sanitize_target
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

USER_AGENT = "OrionSecurityScanner/1.0 (Vulnerability Assessment)"
COMMON_XSS_PARAMS = ["q", "search", "s", "id", "name", "query", "page"]


# ──────────────────────────────────────────────────────────────────────
# 1. Headers Analyzer (with Safe Redirects)
# ──────────────────────────────────────────────────────────────────────
class HeadersAnalyzer(ToolInterface):
    name = "headers"

    CHECKS = {
        "strict-transport-security": (
            "medium", 
            "Missing HTTP Strict Transport Security (HSTS).",
            ["Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."]
        ),
        "content-security-policy": (
            "high", 
            "Missing Content-Security-Policy (CSP).",
            ["Implement a strict Content-Security-Policy to mitigate XSS and data injection attacks."]
        ),
        "x-frame-options": (
            "medium", 
            "Missing X-Frame-Options (Clickjacking protection).",
            ["Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'."]
        ),
        "x-content-type-options": (
            "low", 
            "Missing X-Content-Type-Options.",
            ["Set 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing attacks."]
        ),
        "referrer-policy": (
            "low", 
            "Missing Referrer-Policy.",
            ["Set 'Referrer-Policy: strict-origin-when-cross-origin'."]
        ),
    }

    async def _run_impl(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        vulns = []
        current_url = target.url
        hops = 0

        # FIX: follow_redirects=False to prevent SSRF, manually follow safe ones.
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False) as client:
            while hops < 3:
                try:
                    resp = await client.get(current_url, headers={"User-Agent": USER_AGENT})
                except httpx.RequestError as e:
                    raise RuntimeError(f"Failed to connect to {current_url}: {e}")

                # Check for redirect
                if 300 <= resp.status_code < 400:
                    hops += 1
                    location = resp.headers.get("location")
                    if not location:
                        break
                    
                    next_url = urljoin(current_url, location)
                    try:
                        # Re-validate redirect target to prevent SSRF
                        new_target = await sanitize_target(next_url)
                        current_url = new_target.url
                    except ValueError as e:
                        vulns.append(self.make_vuln(
                            title="Unsafe Redirect Blocked",
                            severity="info",
                            service=target.scheme,
                            port=target.effective_port,
                            description=f"Target redirected to an unsafe URL ({next_url}). Reason: {e}",
                            remediation_steps=["Review the redirect chain for potential SSRF vulnerabilities."]
                        ))
                        return vulns
                else:
                    break
            else:
                vulns.append(self.make_vuln(
                    title="Too Many Redirects",
                    severity="info",
                    service=target.scheme,
                    port=target.effective_port,
                    description="The target exceeded the maximum of 3 redirects.",
                    remediation_steps=["Review the redirect configuration on the server."]
                ))
                return vulns

            # Analyze headers of the FINAL safe response
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for header, (severity, desc, rem) in self.CHECKS.items():
                if header not in headers_lower:
                    vulns.append(self.make_vuln(
                        title=f"Missing Security Header: {header}",
                        severity=severity,
                        service=target.scheme,
                        port=target.effective_port,
                        description=desc,
                        remediation_steps=rem
                    ))
        return vulns

    async def parse_output(self, raw_output: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        return []


# ──────────────────────────────────────────────────────────────────────
# 2. SSL Checker (with Binary DER Parsing)
# ──────────────────────────────────────────────────────────────────────
class SSLChecker(ToolInterface):
    name = "ssl"

    async def _run_impl(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        if target.scheme != "https":
            return []

        vulns = []
        
        def _get_raw_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            try:
                with socket.create_connection((target.hostname, target.effective_port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target.hostname) as ssock:
                        # FIX: Get the binary cert so we can parse it manually
                        binary_cert = ssock.getpeercert(binary_form=True)
                        if not binary_cert:
                            return None
                        
                        # Parse DER to PEM to Dict
                        pem = ssl.DER_cert_to_PEM_cert(binary_cert)
                        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as f:
                            f.write(pem)
                            tmp_path = f.name
                        try:
                            return ssl._ssl._test_decode_cert(tmp_path)
                        finally:
                            os.unlink(tmp_path)
            except Exception as e:
                raise RuntimeError(f"SSL connection failed: {e}")

        cert = await asyncio.to_thread(_get_raw_cert)
        if not cert:
            return []

        # 1. Check Expiration
        if "notAfter" in cert:
            try:
                expire_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expire_date - datetime.now(timezone.utc)).days
                
                if days_left < 0:
                    vulns.append(self.make_vuln(
                        title="Expired SSL Certificate",
                        severity="critical",
                        service="https",
                        port=target.effective_port,
                        description=f"The certificate expired {abs(days_left)} days ago.",
                        remediation_steps=["Renew the SSL certificate immediately."]
                    ))
                elif days_left < 30:
                    vulns.append(self.make_vuln(
                        title="SSL Certificate Expiring Soon",
                        severity="medium",
                        service="https",
                        port=target.effective_port,
                        description=f"The certificate expires in {days_left} days.",
                        remediation_steps=["Renew the SSL certificate before expiration."]
                    ))
            except ValueError:
                pass

        # 2. Check Self-Signed (Issuer == Subject)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer == subject:
            vulns.append(self.make_vuln(
                title="Self-Signed SSL Certificate",
                severity="high",
                service="https",
                port=target.effective_port,
                description="The certificate is self-signed and not trusted by public CAs.",
                remediation_steps=["Replace the self-signed certificate with one signed by a trusted Certificate Authority."]
            ))

        return vulns

    async def parse_output(self, raw_output: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        return []


# ──────────────────────────────────────────────────────────────────────
# 3. XSS Scanner (Basic Reflected)
# ──────────────────────────────────────────────────────────────────────
class XSSScanner(ToolInterface):
    name = "xss"
    
    PAYLOADS = [
        "orionxss123<script>alert(1)</script>",
        "orionxss123\"><img src=x onerror=alert(1)>",
    ]

    async def _run_impl(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        vulns = []
        parsed = urlparse(target.url)
        existing_params = [k for k, v in parse_qsl(parsed.query)]
        test_params = list(set(existing_params + COMMON_XSS_PARAMS))
        
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False) as client:
            for param in test_params:
                for payload in self.PAYLOADS:
                    try:
                        resp = await client.get(
                            base_url, 
                            params={param: payload},
                            headers={"User-Agent": USER_AGENT}
                        )
                    except httpx.RequestError:
                        continue

                    content_type = resp.headers.get("content-type", "").lower()
                    if "text/html" not in content_type:
                        continue

                    content = resp.text
                    if payload in content:
                        vulns.append(self.make_vuln(
                            title=f"Reflected XSS via '{param}' parameter",
                            severity="high",
                            service=target.scheme,
                            port=target.effective_port,
                            description=f"The payload reflected unescaped in the HTML response. (Note: Basic reflection test).",
                            remediation_steps=[
                                "Encode all user input before rendering it in HTML.",
                                "Implement a strict Content-Security-Policy (CSP)."
                            ]
                        ))
                        break
        return vulns

    async def parse_output(self, raw_output: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        return []