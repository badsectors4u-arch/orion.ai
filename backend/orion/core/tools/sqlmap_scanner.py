"""
Orion Security Platform — SQLMap Scanner Wrapper & Native SQLi Engine.

PURPOSE: Executes SQLMap safely when available.
Provides an Active Pure-Python SQL Injection Scanner Fallback that tests both
GET query parameters and POST forms using error-based, database crash differential,
and authentication bypass probes against MySQL, MSSQL, PostgreSQL, Oracle, and SQLite.
"""
from __future__ import annotations

import logging
import re
import shutil
import tempfile
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx
from orion.core.schemas import FormEntry, SanitizedTarget, VulnerabilityItem
from orion.core.tools.base_tool import ToolInterface

logger = logging.getLogger(__name__)

# Known SQL Error Signatures across Database Management Systems
SQLI_ERROR_SIGNATURES = [
    # Microsoft SQL Server / ASP.NET / Access
    (r"Unclosed quotation mark after the character string", "Microsoft SQL Server"),
    (r"Microsoft OLE DB Provider for SQL Server", "Microsoft SQL Server"),
    (r"ODBC SQL Server Driver", "Microsoft SQL Server"),
    (r"System\.Data\.SqlClient\.", "ASP.NET / MS SQL Server"),
    (r"Microsoft Access Driver", "Microsoft Access"),
    (r"Syntax error in string in query expression", "Microsoft Access / Jet"),
    # MySQL / MariaDB
    (r"You have an error in your SQL syntax", "MySQL"),
    (r"supplied argument is not a valid MySQL result resource", "MySQL"),
    (r"check the manual that corresponds to your MySQL server version", "MySQL"),
    # PostgreSQL
    (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
    (r"pg_query\(\):\s+Query failed", "PostgreSQL"),
    # Oracle
    (r"ORA-01756:\s+quoted string not properly terminated", "Oracle"),
    (r"ORA-00933:\s+SQL command not properly ended", "Oracle"),
    # SQLite
    (r"SQLite3::SQLException", "SQLite"),
    (r"near \".+?\": syntax error", "SQLite"),
    # Generic SQL errors
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning:.*?mysqli_", "PHP MySQLi"),
]


class SqlmapScanner(ToolInterface):
    name = "sqlmap"

    async def _run_impl(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        sqlmap_bin = shutil.which("sqlmap")

        if sqlmap_bin:
            temp_dir = tempfile.mkdtemp(prefix="orion_sqlmap_")
            candidate_urls = options.get("urls", [])
            scan_url = candidate_urls[0] if candidate_urls else target.url

            cmd = [
                sqlmap_bin,
                "-u", scan_url,
                "--batch",
                "--level=2",
                "--risk=1",
                "--forms",
                "--threads=1",
                "--time-sec=5",
                "--flush-session",
                "--ignore-redirects",
                "--disable-coloring",
                "--output-dir", temp_dir
            ]

            try:
                returncode, stdout, stderr = await self.run_subprocess(cmd, timeout=300)
                if stdout.strip():
                    return await self.parse_output(stdout, target)
            except Exception as e:
                logger.warning(f"SQLMap CLI execution failed, switching to native SQLi engine: {e}")
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        # Active Native Python SQL Injection Engine Fallback
        return await self._native_sqli_scan(target, options)

    async def _native_sqli_scan(self, target: SanitizedTarget, options: dict[str, Any]) -> list[VulnerabilityItem]:
        """Audits parameters and forms using error-based, crash differential, and auth bypass probes."""
        vulns: list[VulnerabilityItem] = []
        candidate_urls: list[str] = options.get("urls", [])
        forms: list[FormEntry] = options.get("forms", [])

        if target.url not in candidate_urls:
            candidate_urls.insert(0, target.url)

        sqli_probes = [
            ("'", "Error-based Single Quote"),
            ("''", "Syntax Balance Probe"),
            ("' OR '1'='1", "Boolean-based Always True"),
            ("' OR 1=1--", "Inline Comment Bypass"),
            ("\" OR 1=1--", "Double-quote Comment Bypass"),
        ]

        async with httpx.AsyncClient(verify=False, timeout=8.0, follow_redirects=True) as client:
            # 1. Test Query Parameters on Candidate URLs
            for url in candidate_urls[:15]:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query)
                if not qs:
                    continue

                # Baseline request
                base_len = 0
                base_status = 200
                try:
                    base_resp = await client.get(url)
                    base_len = len(base_resp.text)
                    base_status = base_resp.status_code
                except Exception:
                    pass

                for param, vals in qs.items():
                    orig_val = vals[0]
                    for probe_val, probe_desc in sqli_probes:
                        mutated_qs = dict(qs)
                        mutated_qs[param] = [orig_val + probe_val]
                        new_query = urlencode(mutated_qs, doseq=True)
                        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                        try:
                            resp = await client.get(test_url)
                            body = resp.text

                            # Check A: SQL error signatures in response
                            for pattern, dbms in SQLI_ERROR_SIGNATURES:
                                if re.search(pattern, body, re.IGNORECASE):
                                    vulns.append(
                                        self.make_vuln(
                                            title=f"SQL Injection in '{param}' Parameter ({dbms})",
                                            severity="critical",
                                            service=target.scheme,
                                            port=target.effective_port,
                                            cvss_score=9.8,
                                            cve_id="CWE-89",
                                            description=(
                                                f"Parameter '{param}' on {parsed.path} is vulnerable to {probe_desc} SQL Injection. "
                                                f"Database error signature '{pattern}' was returned by {dbms}.\n"
                                                f"Tested URL: {test_url}"
                                            ),
                                            remediation_steps=[
                                                "Use parameterized queries (prepared statements) for all database access.",
                                                "Implement an Object-Relational Mapper (ORM) with strict query binding.",
                                                "Disable detailed database error messages in production environments."
                                            ],
                                        )
                                    )
                                    break

                            # Check B: Database syntax crash differential (e.g. ASP.NET crash dropping to 0 bytes)
                            if probe_val == "'" and not any(v.title.startswith(f"SQL Injection in '{param}'") for v in vulns):
                                if (len(body) == 0 and base_len > 500) or (resp.status_code == 500 and base_status == 200):
                                    vulns.append(
                                        self.make_vuln(
                                            title=f"SQL Syntax Error Crash in '{param}' Parameter",
                                            severity="critical",
                                            service=target.scheme,
                                            port=target.effective_port,
                                            cvss_score=9.5,
                                            cve_id="CWE-89",
                                            description=(
                                                f"Injecting a single-quote syntax probe into parameter '{param}' caused an unhandled "
                                                f"backend database crash (response dropped from {base_len} bytes to {len(body)} bytes, status {resp.status_code}).\n"
                                                f"Tested URL: {test_url}"
                                            ),
                                            remediation_steps=[
                                                "Sanitize query parameters and bind inputs using prepared statements."
                                            ],
                                        )
                                    )

                            if any(v.title.startswith(f"SQL Injection") and param in v.title for v in vulns):
                                break
                        except Exception:
                            pass

            # 2. Test Discovered HTML Forms (e.g. login.jsp, doLogin)
            tested_forms: set[tuple[str, str]] = set()
            for form in forms[:25]:
                base_url = form.url if form.url.startswith("http") else urljoin(target.url, form.url)
                full_form_url = urljoin(base_url, form.action) if form.action else base_url
                
                # Check baseline form submission with non-existent user
                base_text = ""
                try:
                    dummy_data = {p: "orion_invalid_acc_99" for p in form.params}
                    if form.method.upper() == "POST":
                        b_resp = await client.post(full_form_url, data=dummy_data)
                    else:
                        b_resp = await client.get(full_form_url, params=dummy_data)
                    base_text = b_resp.text
                except Exception:
                    pass

                for param in form.params:
                    if param.lower() in ["submit", "btn", "__viewstate", "__eventvalidation"]:
                        continue

                    if (full_form_url, param) in tested_forms:
                        continue
                    tested_forms.add((full_form_url, param))

                    for probe_val in ["admin' --", "' OR 1=1--", "admin' or 1=1--", "' OR '1'='1"]:
                        form_data = {p: "orion_invalid_pass_99" for p in form.params}
                        form_data[param] = probe_val

                        try:
                            if form.method.upper() == "POST":
                                resp = await client.post(full_form_url, data=form_data)
                            else:
                                resp = await client.get(full_form_url, params=form_data)

                            body = resp.text

                            # Check A: Authentication Bypass indicators
                            auth_indicators = ["Sign Off", "Logout", "Sign Out", "Hello ", "Account Balance", "Welcome, ", "Logged in as"]
                            has_auth = any(ind in body for ind in auth_indicators) and not any(ind in base_text for ind in auth_indicators)

                            if has_auth:
                                vulns.append(
                                    self.make_vuln(
                                        title=f"Critical SQL Injection Authentication Bypass at '{full_form_url}'",
                                        severity="critical",
                                        service=target.scheme,
                                        port=target.effective_port,
                                        cvss_score=10.0,
                                        cve_id="CWE-89",
                                        description=(
                                            f"Injecting authentication bypass payload '{probe_val}' into field '{param}' at {full_form_url} "
                                            "successfully authenticated without a valid password."
                                        ),
                                        remediation_steps=[
                                            "Use parameterized queries for authentication credentials validation.",
                                            "Never concatenate raw user credentials into SQL statements."
                                        ],
                                    )
                                )
                                break

                            # Check B: SQL error signatures in form response
                            for pattern, dbms in SQLI_ERROR_SIGNATURES:
                                if re.search(pattern, body, re.IGNORECASE):
                                    vulns.append(
                                        self.make_vuln(
                                            title=f"SQL Injection in Form Field '{param}' ({dbms})",
                                            severity="critical",
                                            service=target.scheme,
                                            port=target.effective_port,
                                            cvss_score=9.8,
                                            cve_id="CWE-89",
                                            description=(
                                                f"HTML Form at {full_form_url} is vulnerable to SQL Injection in input '{param}'. "
                                                f"Response leaked {dbms} error signature: {pattern}"
                                            ),
                                            remediation_steps=[
                                                "Sanitize and parameterize all form inputs before database query execution."
                                            ],
                                        )
                                    )
                                    break

                            if any("Authentication Bypass" in v.title for v in vulns):
                                break
                        except Exception:
                            pass

        return vulns

    async def parse_output(self, raw_output: str, target: SanitizedTarget) -> list[VulnerabilityItem]:
        vulns = []
        blocks = re.split(r"(?m)^\s*Parameter:\s*", raw_output)[1:]
        seen = set()

        for b in blocks:
            first_line = b.splitlines()[0]
            m = re.match(r"(.+?)\s+\(([^)]+)\)\s*$", first_line)
            if not m:
                continue

            param = m.group(1).strip()
            where = m.group(2).strip()

            if (param, where) in seen:
                continue
            seen.add((param, where))

            types = list(dict.fromkeys(
                t.strip() for t in re.findall(r"(?m)^\s*Type:\s*(.+)$", b)
            ))
            inj_type = ", ".join(types) or "SQL Injection"

            vulns.append(self.make_vuln(
                title=f"SQL Injection in '{param}' parameter ({where})",
                severity="critical",
                service=target.scheme,
                port=target.effective_port,
                description=(
                    f"SQLMap confirmed that the '{param}' parameter ({where}) is vulnerable "
                    f"to {inj_type}. An attacker could manipulate database queries to bypass "
                    "authentication, steal sensitive data, or modify records."
                ),
                remediation_steps=[
                    "Use parameterized queries (prepared statements) for all database interactions.",
                    "Implement strict input validation and whitelist allowed characters.",
                    "Apply the principle of least privilege to the database user."
                ],
                cvss_score=9.8
            ))

        return vulns
