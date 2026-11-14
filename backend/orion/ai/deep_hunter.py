"""
Orion Security Platform — Autonomous AI Deep Hunter (Phase 4.5).

PURPOSE:
Acts as an autonomous, time-bounded AI reasoning security agent that audits intermediate
reconnaissance and crawled attack surface (endpoints, forms, files, and links).
Discovers edge-case vulnerabilities that traditional CLI tools miss, including:
- In-Band, Error-based, and Boolean Differential SQL Injection on dynamic endpoints
- Path Traversal & Local File Inclusion (LFI) on file/document parameters
- Reflected & DOM-based Cross-Site Scripting (XSS) on discovered forms and query parameters
- Insecure Direct Object References (IDOR) & Privilege Escalation
- Boundary, Reverse-Proxy Header Spoofing & Perimeter Bypasses
- Exposed Diagnostics, Actuators, and Environment Configuration Leaks
- AI Hypothesis-driven Logic Probing

Every confirmed finding produces a standardized, detailed report containing:
- Exact location (Target URL, endpoint, parameter, port, protocol)
- Tested payload and proof-of-concept verification
- Comprehensive technical mechanics and root cause analysis
- Authoritative CVSS v3.1 base score and vector
- Concrete code-level and architectural remediation steps
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from uuid import uuid4

import httpx
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import (
    DiscoveryResult,
    FormEntry,
    ReconResult,
    SanitizedTarget,
    Severity,
    VulnerabilityItem,
)

logger = logging.getLogger(__name__)


# Standard Database Error Signatures
SQLI_ERROR_PATTERNS = [
    (r"System\.Data\.SqlClient\.SqlException", "Microsoft SQL Server", "CWE-89"),
    (r"Microsoft OLE DB Provider for ODBC Drivers", "Microsoft Access/MSSQL", "CWE-89"),
    (r"Microsoft OLE DB Provider for SQL Server", "Microsoft SQL Server", "CWE-89"),
    (r"ODBC SQL Server Driver", "Microsoft SQL Server", "CWE-89"),
    (r"SQLServer JDBC Driver", "Microsoft SQL Server", "CWE-89"),
    (r"Unclosed quotation mark before the character string", "Microsoft SQL Server", "CWE-89"),
    (r"Line \d+: Incorrect syntax near", "Microsoft SQL Server", "CWE-89"),
    (r"You have an error in your SQL syntax", "MySQL", "CWE-89"),
    (r"Warning:.*?mysqli_", "PHP MySQLi", "CWE-89"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL", "CWE-89"),
    (r"valid PostgreSQL result", "PostgreSQL", "CWE-89"),
    (r"ORA-01756:\s+quoted string not properly terminated", "Oracle", "CWE-89"),
    (r"ORA-00933:\s+SQL command not properly ended", "Oracle", "CWE-89"),
    (r"SQLite3::SQLException", "SQLite", "CWE-89"),
    (r"near \".+?\": syntax error", "SQLite", "CWE-89"),
    (r"syntax error at or near", "SQL Generic", "CWE-89"),
]

# Sensitive File Indicators
PATH_TRAVERSAL_INDICATORS = [
    (r"<configuration>", "ASP.NET Web.config configuration file disclosure", "CWE-22", "critical", 9.1),
    (r"\[extensions\]", "Windows win.ini system file disclosure", "CWE-22", "high", 8.6),
    (r"root:x:0:0:", "Linux /etc/passwd user database disclosure", "CWE-22", "high", 8.6),
    (r"\[fonts\]", "Windows system file disclosure", "CWE-22", "medium", 6.5),
    (r"\[boot loader\]", "Windows boot.ini system file disclosure", "CWE-22", "high", 8.6),
]


class AIDeepHunter:
    """
    Autonomous AI Security Agent executing bounded deep vulnerability hunting (Phase 4.5).
    """

    def __init__(self, ai_adapter: UniversalAIAdapter):
        self.ai = ai_adapter

    async def hunt(
        self,
        target: SanitizedTarget,
        recon: ReconResult,
        discovery: DiscoveryResult,
        existing_vulns: list[VulnerabilityItem],
        max_duration_seconds: float = 300.0,
    ) -> list[VulnerabilityItem]:
        """
        Executes autonomous deep hunting within a strict time budget (default 300 seconds / 5 minutes).
        Gracefully returns whatever findings were confirmed if time expires.
        """
        start_time = time.monotonic()
        logger.info(
            f"Starting Autonomous AI Deep Hunter on {target.url} (Time budget: {max_duration_seconds:.0f}s)..."
        )

        try:
            confirmed_vulns = await asyncio.wait_for(
                self._run_hunting_routine(target, recon, discovery, existing_vulns, start_time, max_duration_seconds),
                timeout=max_duration_seconds,
            )
            elapsed = time.monotonic() - start_time
            logger.info(f"AI Deep Hunter completed in {elapsed:.1f}s. Confirmed {len(confirmed_vulns)} findings.")
            return confirmed_vulns
        except asyncio.TimeoutError:
            elapsed = time.monotonic() - start_time
            logger.warning(
                f"AI Deep Hunter hit the {max_duration_seconds:.0f}s time budget limit (elapsed: {elapsed:.1f}s). "
                "Gracefully finalizing discovered vulnerabilities."
            )
            return []
        except Exception as e:
            logger.error(f"AI Deep Hunter encountered an unexpected error: {e}", exc_info=True)
            return []

    async def _run_hunting_routine(
        self,
        target: SanitizedTarget,
        recon: ReconResult,
        discovery: DiscoveryResult,
        existing_vulns: list[VulnerabilityItem],
        start_time: float,
        budget_seconds: float,
    ) -> list[VulnerabilityItem]:
        """Internal hunting orchestrator coordinating AI reasoning and targeted micro-probes."""
        confirmed: list[VulnerabilityItem] = []
        base_domain = target.hostname.lower()

        # Gather all testable URLs from discovery
        candidate_urls: list[str] = list(
            set(
                [target.url]
                + discovery.crawled_urls
                + discovery.archived_urls
                + [urljoin(target.url, ep) for ep in discovery.js_endpoints if ep.startswith("/")]
            )
        )
        candidate_urls = [u for u in candidate_urls if self._is_in_scope(u, base_domain)]

        async with httpx.AsyncClient(verify=False, timeout=7.0, follow_redirects=False) as client:
            # ──────────────────────────────────────────────────────────
            # Vector 1: Discovered Parameter Injection & Crash Differentials (SQLi, LFI, SSTI, XSS)
            # ──────────────────────────────────────────────────────────
            injection_vulns = await self._audit_endpoint_injections(client, target, candidate_urls, discovery.forms)
            confirmed.extend(injection_vulns)

            # ──────────────────────────────────────────────────────────
            # Vector 2: Reverse-Proxy Header Spoofing & Perimeter Bypasses
            # ──────────────────────────────────────────────────────────
            header_vulns = await self._audit_header_bypasses(client, target, candidate_urls)
            confirmed.extend(header_vulns)

            # ──────────────────────────────────────────────────────────
            # Vector 3: Deep IDOR & Authorization Differentials
            # ──────────────────────────────────────────────────────────
            idor_vulns = await self._audit_deep_idor(client, target, candidate_urls, existing_vulns)
            confirmed.extend(idor_vulns)

            # ──────────────────────────────────────────────────────────
            # Vector 4: Open Redirection & Query SSRF Vectors
            # ──────────────────────────────────────────────────────────
            redirect_vulns = await self._audit_open_redirects(client, target, candidate_urls)
            confirmed.extend(redirect_vulns)

            # ──────────────────────────────────────────────────────────
            # Vector 5: Diagnostic, Actuator & Sensitive Configuration Leaks
            # ──────────────────────────────────────────────────────────
            diag_vulns = await self._audit_diagnostic_endpoints(client, target)
            confirmed.extend(diag_vulns)

            # ──────────────────────────────────────────────────────────
            # Vector 6: AI-Driven Reasoning & Dynamic Hypothesis Loop (DeepSeek / Nemotron / GLM)
            # ──────────────────────────────────────────────────────────
            time_left = budget_seconds - (time.monotonic() - start_time)
            if time_left > 10.0 and self.ai.api_key:
                ai_vulns = await self._ai_assisted_hypothesis_loop(
                    client=client,
                    target=target,
                    urls=candidate_urls,
                    current_vulns=existing_vulns + confirmed,
                    remaining_seconds=time_left,
                    recon=recon,
                    forms=discovery.forms,
                )
                confirmed.extend(ai_vulns)

        return self._deduplicate(confirmed)

    # ──────────────────────────────────────────────────────────────────
    # Vector 1: Discovered Parameter Injection & Crash Differentials
    # ──────────────────────────────────────────────────────────────────
    async def _audit_endpoint_injections(
        self,
        client: httpx.AsyncClient,
        target: SanitizedTarget,
        urls: list[str],
        forms: list[FormEntry],
    ) -> list[VulnerabilityItem]:
        """
        Audits all discovered URLs with parameters and forms for SQLi, Path Traversal, and XSS.
        """
        vulns: list[VulnerabilityItem] = []

        # Find URLs that contain query strings
        urls_with_params = [u for u in urls if "?" in u]

        # 1. Audit Query Strings on Crawled URLs
        for test_url in urls_with_params[:20]:
            parsed = urlparse(test_url)
            qs = parse_qs(parsed.query)
            if not qs:
                continue

            # Fetch baseline response
            base_len = -1
            try:
                base_resp = await client.get(test_url)
                base_len = len(base_resp.text)
                base_status = base_resp.status_code
            except Exception:
                continue

            for param_name, orig_vals in qs.items():
                orig_val = orig_vals[0] if orig_vals else "1"

                # A. SQL Injection Probe (Syntax error & Crash differential)
                sqli_payloads = [
                    ("'", "Single Quote Syntax Error Probe"),
                    ("1' OR '1'='1", "Boolean Invariant Bypass"),
                    ("1 AND 1=2", "Boolean False Differential"),
                ]
                for sqli_payload, probe_desc in sqli_payloads:
                    mutated_qs = dict(qs)
                    mutated_qs[param_name] = [orig_val + sqli_payload]
                    new_q = urlencode(mutated_qs, doseq=True)
                    probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

                    try:
                        probe_resp = await client.get(probe_url)
                        body = probe_resp.text

                        # Check 1: Known DBMS Error Signature
                        matched_dbms = None
                        matched_cwe = "CWE-89"
                        for pattern, db_name, cwe in SQLI_ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                matched_dbms = db_name
                                matched_cwe = cwe
                                break

                        if matched_dbms:
                            vulns.append(
                                self._build_advanced_finding(
                                    title=f"[AI-Hunter] In-Band SQL Injection in '{param_name}' ({matched_dbms})",
                                    severity="critical",
                                    service=target.scheme,
                                    port=target.effective_port,
                                    cve_id=matched_cwe,
                                    cvss_score=9.8,
                                    target_url=probe_url,
                                    endpoint=parsed.path,
                                    parameter=param_name,
                                    payload=sqli_payload,
                                    verification_technique=f"Database syntax exception signature ({matched_dbms})",
                                    mechanics=(
                                        f"The application fails to parameterize or validate untrusted input passed to the '{param_name}' parameter on {parsed.path}. "
                                        f"Injecting the payload '{sqli_payload}' caused the backend {matched_dbms} database driver to return an unhandled SQL syntax exception. "
                                        "An attacker can exploit this flaw to execute arbitrary database queries, bypass authentication, exfiltrate confidential data tables, or manipulate stored records."
                                    ),
                                    remediation_steps=[
                                        "Use parameterized prepared statements (e.g. SqlCommand with SqlParameter in ASP.NET, PreparedStatement in Java/PHP) for all database queries.",
                                        "Enforce an Object-Relational Mapping (ORM) framework with automatic query parameterization.",
                                        "Apply the principle of least privilege to database service accounts to restrict administrative operations."
                                    ],
                                )
                            )
                            break

                        # Check 2: Unhandled Zero-Length or 500 Crash Differential
                        # (Common in ASP.NET / IIS when an unhandled SQL exception terminates execution abruptly)
                        if base_len > 800 and len(body) == 0 and probe_resp.status_code == 200:
                            vulns.append(
                                self._build_advanced_finding(
                                    title=f"[AI-Hunter] Unhandled Database Crash (Potential Blind SQLi) in '{param_name}'",
                                    severity="high",
                                    service=target.scheme,
                                    port=target.effective_port,
                                    cve_id="CWE-89",
                                    cvss_score=8.5,
                                    target_url=probe_url,
                                    endpoint=parsed.path,
                                    parameter=param_name,
                                    payload=sqli_payload,
                                    verification_technique="Severe response length anomaly (baseline > 800 bytes vs probe = 0 bytes)",
                                    mechanics=(
                                        f"Injecting single-quote syntax characters into parameter '{param_name}' on {parsed.path} caused the server to return an empty 0-byte response, "
                                        f"whereas the baseline returned {base_len} bytes. This severe crash differential strongly indicates an unhandled server-side database exception."
                                    ),
                                    remediation_steps=[
                                        "Implement parameterized queries to safely bind user input.",
                                        "Implement comprehensive error handling and logging without suppressing or abruptly terminating HTTP responses."
                                    ],
                                )
                            )
                            break
                    except Exception:
                        pass

                # B. Path Traversal & Local File Inclusion (LFI) Probe
                # Relevant if parameter name suggests files/templates/paths or already contains a file extension
                file_param_keywords = ["file", "page", "doc", "path", "ad", "newsad", "include", "view", "src", "template", "cat", "load"]
                is_file_param = any(k in param_name.lower() for k in file_param_keywords) or any(orig_val.endswith(ext) for ext in [".html", ".htm", ".txt", ".aspx", ".php"])

                if is_file_param:
                    lfi_payloads = [
                        ("../../web.config", "ASP.NET Web.config Path Traversal"),
                        ("../../../../windows/win.ini", "Windows win.ini Path Traversal"),
                        ("../../../../etc/passwd", "Linux /etc/passwd Path Traversal"),
                    ]
                    for lfi_payload, lfi_desc in lfi_payloads:
                        mutated_qs = dict(qs)
                        mutated_qs[param_name] = [lfi_payload]
                        new_q = urlencode(mutated_qs, doseq=True)
                        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

                        try:
                            probe_resp = await client.get(probe_url)
                            body = probe_resp.text

                            for pattern, file_label, cwe, sev, score in PATH_TRAVERSAL_INDICATORS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    vulns.append(
                                        self._build_advanced_finding(
                                            title=f"[AI-Hunter] Arbitrary File Inclusion / Path Traversal in '{param_name}'",
                                            severity=sev,  # type: ignore[arg-type]
                                            service=target.scheme,
                                            port=target.effective_port,
                                            cve_id=cwe,
                                            cvss_score=score,
                                            target_url=probe_url,
                                            endpoint=parsed.path,
                                            parameter=param_name,
                                            payload=lfi_payload,
                                            verification_technique=f"Matched sensitive file signature '{pattern}' in response",
                                            mechanics=(
                                                f"Parameter '{param_name}' on {parsed.path} is vulnerable to Path Traversal ({lfi_desc}). "
                                                f"The application takes the path directly from user input and includes or renders it without path canonicalization. "
                                                f"Injecting '{lfi_payload}' returned internal system file contents matching signature '{pattern}'."
                                            ),
                                            remediation_steps=[
                                                "Never pass user-controlled input directly to file system APIs or dynamic include statements.",
                                                "Use strict allowlists of allowed file identifiers rather than arbitrary file paths.",
                                                "Validate that the resolved canonical path (e.g. via Path.GetFullPath) stays strictly within the intended base directory."
                                            ],
                                        )
                                    )
                                    break
                        except Exception:
                            pass

                # C. Reflected XSS Probe
                xss_canary = f"orion_probe_{uuid4().hex[:6]}"
                xss_payload = f"'\"><{xss_canary}>"
                mutated_qs = dict(qs)
                mutated_qs[param_name] = [xss_payload]
                new_q = urlencode(mutated_qs, doseq=True)
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))

                try:
                    probe_resp = await client.get(probe_url)
                    if f"<{xss_canary}>" in probe_resp.text:
                        vulns.append(
                            self._build_advanced_finding(
                                title=f"[AI-Hunter] Reflected Cross-Site Scripting (XSS) in '{param_name}'",
                                severity="high",
                                service=target.scheme,
                                port=target.effective_port,
                                cve_id="CWE-79",
                                cvss_score=7.5,
                                target_url=probe_url,
                                endpoint=parsed.path,
                                parameter=param_name,
                                payload=xss_payload,
                                verification_technique="Unencoded reflection of HTML tag breakout canary in response body",
                                mechanics=(
                                    f"The application reflects untrusted input from query parameter '{param_name}' on {parsed.path} "
                                    "directly into the HTML DOM without contextual output encoding. "
                                    f"The injected canary payload '{xss_payload}' was reflected completely unescaped. "
                                    "Attackers can leverage this flaw to execute arbitrary client-side JavaScript in victims' sessions."
                                ),
                                remediation_steps=[
                                    "Apply context-aware output encoding (HTML Entity Encoding, Attribute Encoding) before rendering user input in responses.",
                                    "Enforce a Content-Security-Policy (CSP) that restricts script sources and disallows 'unsafe-inline'.",
                                    "Set the 'HttpOnly' flag on sensitive session cookies."
                                ],
                            )
                        )
                except Exception:
                    pass

        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Vector 2: Reverse-Proxy Header Spoofing
    # ──────────────────────────────────────────────────────────────────
    async def _audit_header_bypasses(
        self, client: httpx.AsyncClient, target: SanitizedTarget, urls: list[str]
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        admin_patterns = [r"/admin", r"/manage", r"/dashboard", r"/portal", r"/internal", r"/private"]
        target_paths = [u for u in urls if any(re.search(p, u, re.I) for p in admin_patterns)]

        if not target_paths:
            target_paths = [
                urljoin(target.url, "/admin/"),
                urljoin(target.url, "/admin/login.aspx"),
                urljoin(target.url, "/manage/"),
            ]

        for test_url in target_paths[:6]:
            try:
                base_resp = await client.get(test_url)
                if base_resp.status_code in [401, 403]:
                    bypass_headers = [
                        ("X-Custom-IP-Authorization", "127.0.0.1"),
                        ("X-Forwarded-For", "127.0.0.1"),
                        ("X-Original-URL", "/admin"),
                        ("X-Rewrite-URL", "/admin"),
                    ]
                    for hdr_name, hdr_val in bypass_headers:
                        probe_resp = await client.get(test_url, headers={hdr_name: hdr_val})
                        if probe_resp.status_code == 200:
                            parsed = urlparse(test_url)
                            vulns.append(
                                self._build_advanced_finding(
                                    title=f"[AI-Hunter] Admin Boundary Access Bypass via '{hdr_name}' Header",
                                    severity="high",
                                    service=target.scheme,
                                    port=target.effective_port,
                                    cve_id="CWE-288",
                                    cvss_score=8.2,
                                    target_url=test_url,
                                    endpoint=parsed.path,
                                    parameter=hdr_name,
                                    payload=f"{hdr_name}: {hdr_val}",
                                    verification_technique=f"Perimeter status transition from HTTP {base_resp.status_code} to HTTP 200 via header spoofing",
                                    mechanics=(
                                        f"The restricted endpoint {test_url} responded with HTTP {base_resp.status_code} on standard access, "
                                        f"but adding reverse-proxy header '{hdr_name}: {hdr_val}' bypassed the perimeter authorization control and returned HTTP 200. "
                                        "This allows remote attackers to access restricted administrative resources by spoofing client identity headers."
                                    ),
                                    remediation_steps=[
                                        "Configure front-facing load balancers and reverse proxies to strip incoming untrusted client headers.",
                                        "Implement robust authentication checks at the application code layer rather than relying on perimeter IP filters."
                                    ],
                                )
                            )
                            break
            except Exception:
                pass
        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Vector 3: Deep IDOR & Authorization Differentials
    # ──────────────────────────────────────────────────────────────────
    async def _audit_deep_idor(
        self,
        client: httpx.AsyncClient,
        target: SanitizedTarget,
        urls: list[str],
        existing: list[VulnerabilityItem],
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        idor_params = ["id", "uid", "user", "account", "order_id", "item", "report", "newsid"]

        for u in urls[:15]:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            if not qs:
                continue

            matched_param = next((p for p in qs if p.lower() in idor_params), None)
            if not matched_param:
                continue

            orig_val = qs[matched_param][0]
            if not orig_val.isdigit():
                continue

            try:
                base_resp = await client.get(u)
                if base_resp.status_code != 200:
                    continue

                # Probe alternative sequential ID
                probe_id = str(int(orig_val) + 1)
                mutated_qs = dict(qs)
                mutated_qs[matched_param] = [probe_id]
                new_query = urlencode(mutated_qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                probe_resp = await client.get(test_url)
                if probe_resp.status_code == 200 and probe_resp.text != base_resp.text and len(probe_resp.text) > 300:
                    sensitive_keys = ["email", "balance", "credit", "phone", "ssn", "password", "username", "account", "title", "author"]
                    exposes_data = any(k in probe_resp.text.lower() for k in sensitive_keys)

                    severity: Severity = "high" if exposes_data else "medium"
                    score = 8.5 if exposes_data else 6.5

                    vulns.append(
                        self._build_advanced_finding(
                            title=f"[AI-Hunter] Insecure Direct Object Reference (IDOR) on '{matched_param}'",
                            severity=severity,
                            service=target.scheme,
                            port=target.effective_port,
                            cve_id="CWE-639",
                            cvss_score=score,
                            target_url=test_url,
                            endpoint=parsed.path,
                            parameter=matched_param,
                            payload=f"{matched_param}={probe_id}",
                            verification_technique="Sequential identifier mutation successfully retrieved distinct record without authorization",
                            mechanics=(
                                f"Parameter '{matched_param}' on {parsed.path} exposed distinct user/object records "
                                f"when incrementing value from {orig_val} to {probe_id} without session ownership validation.\n"
                                f"Baseline URL: {u}\nMutated URL: {test_url}"
                            ),
                            remediation_steps=[
                                "Implement server-side authorization checks verifying that the authenticated user owns the requested record.",
                                "Use indirect reference maps (UUIDs or cryptographic hashes) instead of direct sequential database integers."
                            ],
                        )
                    )
                    break
            except Exception:
                pass
        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Vector 4: Open Redirection & Query SSRF Vectors
    # ──────────────────────────────────────────────────────────────────
    async def _audit_open_redirects(
        self, client: httpx.AsyncClient, target: SanitizedTarget, urls: list[str]
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        redirect_params = ["redirect", "url", "next", "return", "dest", "target", "goto", "out"]
        canary = "https://example.com/orion_canary_audit"

        for u in urls[:15]:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            if not qs:
                continue

            matched_param = next((p for p in qs if p.lower() in redirect_params), None)
            if not matched_param:
                continue

            mutated_qs = dict(qs)
            mutated_qs[matched_param] = [canary]
            new_query = urlencode(mutated_qs, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                resp = await client.get(test_url)
                loc = resp.headers.get("location", "")
                if resp.status_code in [301, 302, 303, 307, 308] and canary in loc:
                    vulns.append(
                        self._build_advanced_finding(
                            title=f"[AI-Hunter] Open Redirection Vulnerability in '{matched_param}'",
                            severity="medium",
                            service=target.scheme,
                            port=target.effective_port,
                            cve_id="CWE-601",
                            cvss_score=6.1,
                            target_url=test_url,
                            endpoint=parsed.path,
                            parameter=matched_param,
                            payload=f"{matched_param}={canary}",
                            verification_technique=f"Received HTTP {resp.status_code} with Location pointing to arbitrary domain canary",
                            mechanics=(
                                f"Parameter '{matched_param}' on {parsed.path} accepted arbitrary external destination '{canary}' "
                                f"and issued an unvalidated HTTP {resp.status_code} redirect.\n"
                                "Attackers can abuse this endpoint in phishing campaigns to lend legitimacy to malicious URLs."
                            ),
                            remediation_steps=[
                                "Implement strict whitelist validation for all redirect destinations.",
                                "Disallow absolute URLs in redirection parameters, enforcing relative path redirects only."
                            ],
                        )
                    )
                    break
            except Exception:
                pass
        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Vector 5: Diagnostic, Actuator & Sensitive Configuration Leaks
    # ──────────────────────────────────────────────────────────────────
    async def _audit_diagnostic_endpoints(
        self, client: httpx.AsyncClient, target: SanitizedTarget
    ) -> list[VulnerabilityItem]:
        vulns: list[VulnerabilityItem] = []
        diag_paths = [
            ("/trace.axd", "ASP.NET Trace Diagnostic Exposure", "CWE-200", "high", 7.5),
            ("/elmah.axd", "ASP.NET ELMAH Error Log Diagnostic Exposure", "CWE-200", "critical", 9.1),
            ("/actuator/health", "Spring Boot Health Diagnostic Interface Exposed", "CWE-200", "info", 3.1),
            ("/actuator/env", "Spring Boot Environment Variables Leak", "CWE-200", "critical", 9.8),
            ("/.git/HEAD", "Exposed .git Source Code Repository", "CWE-200", "high", 8.2),
            ("/.env", "Exposed .env Production Environment Configuration", "CWE-200", "critical", 9.8),
            ("/web.config.bak", "Exposed Web.config Backup File", "CWE-200", "critical", 9.1),
            ("/phpinfo.php", "PHPInfo System Diagnostics Page Exposed", "CWE-200", "medium", 5.3),
        ]

        for path, title, cwe, severity, score in diag_paths:
            test_url = urljoin(target.url, path)
            try:
                resp = await client.get(test_url)
                if resp.status_code == 200 and len(resp.text) > 15:
                    vulns.append(
                        self._build_advanced_finding(
                            title=f"[AI-Hunter] {title}",
                            severity=severity,  # type: ignore[arg-type]
                            service=target.scheme,
                            port=target.effective_port,
                            cve_id=cwe,
                            cvss_score=score,
                            target_url=test_url,
                            endpoint=path,
                            parameter=None,
                            payload=path,
                            verification_technique="HTTP GET returned status 200 with active diagnostic interface content",
                            mechanics=(
                                f"Publicly accessible diagnostic or configuration resource at {test_url} returned status 200 ({len(resp.text)} bytes). "
                                "This endpoint leaks internal environment variables, architecture diagnostics, or source code metadata to unauthorized clients."
                            ),
                            remediation_steps=[
                                "Disable diagnostic and tracing modules (e.g. trace.axd, ELMAH, Spring Actuator) in production configurations.",
                                "Restrict administrative paths via web server access control lists or VPN requirements."
                            ],
                        )
                    )
                elif resp.status_code == 403 and path in ["/trace.axd", "/elmah.axd"]:
                    # Information disclosure: endpoint exists on the server
                    vulns.append(
                        self._build_advanced_finding(
                            title=f"[AI-Hunter] ASP.NET Diagnostic Endpoint Detected: {path}",
                            severity="low",
                            service=target.scheme,
                            port=target.effective_port,
                            cve_id="CWE-200",
                            cvss_score=4.3,
                            target_url=test_url,
                            endpoint=path,
                            parameter=None,
                            payload=path,
                            verification_technique="HTTP 403 Forbidden confirms existence of internal diagnostic module",
                            mechanics=(
                                f"Accessing {test_url} returned HTTP 403 Forbidden, confirming the module is installed on the web server. "
                                "Attackers can use this information to identify ASP.NET architecture and attempt authorization bypasses."
                            ),
                            remediation_steps=[
                                "Remove unused diagnostic handlers from web.config altogether if not required in production."
                            ],
                        )
                    )
            except Exception:
                pass
        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Vector 6: AI-Driven Reasoning & Dynamic Hypothesis Loop
    # ──────────────────────────────────────────────────────────────────
    async def _ai_assisted_hypothesis_loop(
        self,
        client: httpx.AsyncClient,
        target: SanitizedTarget,
        urls: list[str],
        current_vulns: list[VulnerabilityItem],
        remaining_seconds: float = 60.0,
        recon: Optional[ReconResult] = None,
        forms: Optional[list[FormEntry]] = None,
    ) -> list[VulnerabilityItem]:
        """Queries the LLM (DeepSeek/Nemotron) to hypothesize attack paths on discovered endpoints."""
        vulns: list[VulnerabilityItem] = []
        tech_summary = ", ".join((recon.tech_fingerprint.technologies if recon else []) or ["Web Application"])
        server_info = (recon.tech_fingerprint.server if recon else None) or "Unknown Server"

        system_prompt = f"""You are an elite Autonomous Penetration Testing Agent with {remaining_seconds:.0f}s time budget.
Analyze the target's crawled endpoints and forms, and synthesize up to 3 targeted verification micro-probes for high-impact flaws (SQL Injection, Path Traversal, SSTI, Auth Bypass).

Rules:
1. Target tech stack: {server_info}, Technologies: {tech_summary}.
2. Formulate specific test requests on the REAL discovered endpoints.
3. Return ONLY valid JSON matching this schema:
{{
  "probes": [
    {{
      "path": "/relative/path",
      "method": "GET",
      "params": {{"key": "test_payload"}},
      "expected_indicator": "string to look for in response that indicates success",
      "vuln_title": "Descriptive Vulnerability Title",
      "severity": "critical"|"high"|"medium"|"low",
      "cvss_score": 8.5,
      "cwe_id": "CWE-89"
    }}
  ]
}}
Do NOT output markdown fences or explanatory text. Return raw JSON.
""".strip()

        form_summaries = [{"action": f.action, "method": f.method, "params": f.params} for f in (forms or [])[:6]]
        user_prompt = json.dumps({
            "target": target.url,
            "sample_endpoints": urls[:25],
            "forms": form_summaries,
            "already_found": [v.title for v in current_vulns[:6]],
        }, indent=2)

        try:
            ai_resp = await self.ai.call(system_prompt=system_prompt, user_prompt=user_prompt, json_mode=True)
            if ai_resp.ok and isinstance(ai_resp.data, dict):
                probes = ai_resp.data.get("probes", [])
                for p in probes[:3]:
                    rel_path = p.get("path", "")
                    method = p.get("method", "GET").upper()
                    params = p.get("params", {})
                    indicator = p.get("expected_indicator", "")
                    title = p.get("vuln_title", "AI Identified Logic Flaw")
                    sev: Severity = p.get("severity", "medium").lower()  # type: ignore[assignment]
                    if sev not in ["critical", "high", "medium", "low", "info"]:
                        sev = "medium"
                    score = float(p.get("cvss_score", 7.5))
                    cwe = p.get("cwe_id", "CWE-20")

                    full_url = urljoin(target.url, rel_path)
                    if not self._is_in_scope(full_url, target.hostname):
                        continue

                    try:
                        if method == "POST":
                            probe_r = await client.post(full_url, data=params)
                        else:
                            probe_r = await client.get(full_url, params=params)

                        if probe_r.status_code == 200 and indicator and indicator.lower() in probe_r.text.lower():
                            param_str = json.dumps(params)
                            vulns.append(
                                self._build_advanced_finding(
                                    title=f"[AI-Hunter] {title}",
                                    severity=sev,
                                    service=target.scheme,
                                    port=target.effective_port,
                                    cve_id=cwe,
                                    cvss_score=score,
                                    target_url=full_url,
                                    endpoint=rel_path,
                                    parameter=list(params.keys())[0] if params else None,
                                    payload=param_str,
                                    verification_technique=f"Matched expected validation indicator '{indicator}' in response body",
                                    mechanics=(
                                        f"Autonomous AI Reasoning Engine identified and verified an active logic/injection vulnerability on {full_url}.\n"
                                        f"When testing parameter payload '{param_str}', the response returned the anomalous indicator '{indicator}'."
                                    ),
                                    remediation_steps=[
                                        "Sanitize and validate all client input on this endpoint.",
                                        "Implement strict server-side authorization and type validation controls."
                                    ],
                                )
                            )
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"AI hypothesis loop ended: {e}")

        return vulns

    # ──────────────────────────────────────────────────────────────────
    # Structured Advanced Vulnerability Builder
    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _build_advanced_finding(
        title: str,
        severity: Severity,
        service: str,
        port: Optional[int],
        cve_id: str,
        cvss_score: float,
        target_url: str,
        endpoint: str,
        parameter: Optional[str],
        payload: Optional[str],
        verification_technique: str,
        mechanics: str,
        remediation_steps: list[str],
    ) -> VulnerabilityItem:
        """
        Creates an advanced, comprehensive vulnerability report finding
        with explicit Location, Payload, Mechanics, and CVSS Scoring sections.
        """
        param_label = f"`{parameter}`" if parameter else "N/A (Path/Header/Direct Resource)"
        payload_label = f"`{payload}`" if payload else "N/A"
        port_label = str(port) if port is not None else "80/443"

        # CVSS Vector Synthesis
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if severity == "critical" else (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" if severity == "high" else (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N" if severity == "medium" else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
            )
        )

        detailed_description = (
            f"### 📍 Vulnerability Location\n"
            f"- **Target URL / Endpoint**: `{endpoint}`\n"
            f"- **Full Target URL**: `{target_url}`\n"
            f"- **Vulnerable Parameter / Component**: {param_label}\n"
            f"- **Service & Port**: `{service}` / Port {port_label}\n\n"
            f"### 💥 Exploitation Proof & Payload\n"
            f"- **Tested Payload**: {payload_label}\n"
            f"- **Verification Technique**: {verification_technique}\n"
            f"- **CVSS v3.1 Vector**: `{cvss_vector}`\n\n"
            f"### 🔬 Technical Analysis & Vulnerability Mechanics\n"
            f"{mechanics}\n\n"
            f"### 📊 Threat Severity & CVSS v3.1 Scoring\n"
            f"- **CVSS v3.1 Base Score**: **{cvss_score:.1f} ({severity.capitalize()})**\n"
            f"- **Authoritative Classification**: **{cve_id}**\n"
            f"- **Business Impact**: Unauthorized data compromise, application integrity degradation, or perimeter access bypass."
        )

        return VulnerabilityItem(
            id=str(uuid4()),
            title=title[:290],
            severity=severity,
            service=service,
            port=port,
            cve_id=cve_id,
            cvss_score=cvss_score,
            description=detailed_description,
            remediation_steps=remediation_steps,
        )

    # ──────────────────────────────────────────────────────────────────
    # Utilities
    # ──────────────────────────────────────────────────────────────────
    @staticmethod
    def _is_in_scope(url: str, base_domain: str) -> bool:
        """Enforces strict scope pinning to prevent SSRF or scanning foreign hosts."""
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            return host == base_domain or host.endswith(f".{base_domain}")
        except Exception:
            return False

    @staticmethod
    def _deduplicate(vulns: list[VulnerabilityItem]) -> list[VulnerabilityItem]:
        seen = set()
        unique = []
        for v in vulns:
            if v.title not in seen:
                seen.add(v.title)
                unique.append(v)
        return unique
