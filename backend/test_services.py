"""
Orion Security Platform â€” Comprehensive Services & Scanners Test Suite.

Tests Phase 1 through Phase 5 components:
1. NmapScanner XML parsing and VulnerabilityItem validation.
2. HeadersAnalyzer detection of missing security headers.
3. UniversalAIAdapter configuration across cloud, custom, and local providers.
4. AttackGraphGenerator fallback generation without AI.
5. BreachService HIBP integration (mocked 404 and 200 responses).
6. KBService OWASP Top 10 articles validation.
7. PDFGenerator report compilation and non-empty bytes output.
"""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from orion.ai.attack_graph_generator import AttackGraphGenerator
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import SanitizedTarget, VulnerabilityItem
from orion.core.tools.nmap_scanner import NmapScanner
from orion.core.tools.web_scanners import HeadersAnalyzer
from orion.services.breach_service import check_email_breach
from orion.services.kb_service import get_article_by_id, get_knowledgebase_articles
from orion.services.pdf_generator import generate_pdf_report


class TestOrionServices(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.mock_target = SanitizedTarget(
            original="http://example.com",
            scheme="http",
            hostname="example.com",
            port=80,
            resolved_ip="93.184.216.34",
            path="/",
            url="http://example.com/"
        )

    def tearDown(self):
        self.loop.close()

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 1. Nmap XML Parsing Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_nmap_xml_parsing(self):
        async def _test():
            scanner = NmapScanner()
            sample_xml = """<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE nmaprun>
            <nmaprun scanner="nmap" version="7.94">
                <host>
                    <ports>
                        <port protocol="tcp" portid="21">
                            <state state="open" reason="syn-ack"/>
                            <service name="ftp" product="vsftpd" version="3.0.3"/>
                        </port>
                        <port protocol="tcp" portid="80">
                            <state state="open" reason="syn-ack"/>
                            <service name="http" product="nginx" version="1.18.0"/>
                        </port>
                    </ports>
                </host>
            </nmaprun>
            """
            vulns = await scanner.parse_output(sample_xml, self.mock_target)
            self.assertIsInstance(vulns, list)
            # Port 21 is statically flagged as dangerous FTP
            ftp_vuln = next((v for v in vulns if v.port == 21), None)
            self.assertIsNotNone(ftp_vuln)
            self.assertEqual(ftp_vuln.severity, "medium")
            self.assertIn("vsftpd", ftp_vuln.service)

        self.loop.run_until_complete(_test())

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 2. Headers Analyzer Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_headers_analyzer_missing_headers(self):
        async def _test():
            analyzer = HeadersAnalyzer()
            # Mock httpx response missing HSTS, CSP, X-Frame-Options
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"Content-Type": "text/html"}  # Missing security headers
                mock_get.return_value = mock_resp

                result = await analyzer.run(self.mock_target)
                self.assertTrue(result.success)
                self.assertGreaterEqual(len(result.vulnerabilities), 4)
                titles = [v.title for v in result.vulnerabilities]
                self.assertTrue(any("strict-transport-security" in t.lower() for t in titles))
                self.assertTrue(any("content-security-policy" in t.lower() for t in titles))

        self.loop.run_until_complete(_test())

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 3. Universal AI Adapter Provider Configuration
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_universal_ai_adapter_providers(self):
        # Cloud (Groq)
        adapter_cloud = UniversalAIAdapter({"provider": "cloud"})
        self.assertIn("groq.com", adapter_cloud.base_url)

        # Custom (OpenAI)
        adapter_custom = UniversalAIAdapter({
            "provider": "custom",
            "api_key": "sk-test12345",
            "model": "gpt-4o-mini"
        })
        self.assertEqual(adapter_custom.model, "gpt-4o-mini")
        self.assertEqual(adapter_custom.api_key, "sk-test12345")

        # Local (Ollama)
        adapter_ollama = UniversalAIAdapter({"provider": "local_ollama"})
        self.assertIn("11434", adapter_ollama.base_url)
        self.assertEqual(adapter_ollama.api_key, "ollama")

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 4. Attack Graph Generator Fallback Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_attack_graph_fallback(self):
        async def _test():
            mock_adapter = MagicMock()
            # Simulate failed AI response
            mock_adapter.call = AsyncMock(return_value=MagicMock(ok=False, data=None))
            generator = AttackGraphGenerator(mock_adapter)

            sample_vulns = [
                VulnerabilityItem(
                    title="SQL Injection",
                    severity="critical",
                    service="http",
                    port=80,
                    description="SQLi detected in id param",
                    remediation_steps=["Use prepared statements"]
                ),
                VulnerabilityItem(
                    title="Missing CSP Header",
                    severity="high",
                    service="http",
                    port=80,
                    description="Content-Security-Policy header is missing",
                    remediation_steps=["Add CSP header"]
                )
            ]

            graph = await generator.generate(sample_vulns, self.mock_target.url)
            self.assertIsNotNone(graph)
            self.assertGreaterEqual(len(graph.nodes), 3)  # root target + 2 vulns
            self.assertGreaterEqual(len(graph.edges), 2)
            # Root target exists
            self.assertEqual(graph.nodes[0].type, "target")

        self.loop.run_until_complete(_test())

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 5. Breach Service Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_breach_service_responses(self):
        async def _test():
            # Test 1: Clean account (404)
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 404
                mock_get.return_value = mock_resp

                with patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"}):
                    clean_res = await check_email_breach("clean_user@example.com")
                    self.assertEqual(clean_res["breach_count"], 0)
                    self.assertEqual(len(clean_res["breaches"]), 0)

            # Test 2: Breached account (200)
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = [
                    {
                        "Title": "TestBreach Corp",
                        "BreachDate": "2024-01-15",
                        "DataClasses": ["Email addresses", "Passwords"],
                        "PwnCount": 5000000
                    }
                ]
                mock_get.return_value = mock_resp

                with patch.dict(os.environ, {"HIBP_API_KEY": "dummy_key"}):
                    pwned_res = await check_email_breach("pwned_user@example.com")
                    self.assertEqual(pwned_res["breach_count"], 1)
                    self.assertEqual(pwned_res["breaches"][0]["name"], "TestBreach Corp")
                    self.assertEqual(pwned_res["breaches"][0]["account_count"], 5000000)

        self.loop.run_until_complete(_test())

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 6. Knowledgebase Articles Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_knowledgebase_articles(self):
        articles = get_knowledgebase_articles()
        self.assertEqual(len(articles), 10)  # Complete OWASP Top 10

        required_keys = {"id", "title", "cwe_id", "severity", "description", "vulnerable_code", "remediation_code", "references"}
        for art in articles:
            self.assertTrue(required_keys.issubset(art.keys()))
            self.assertIn(art["severity"], ("critical", "high", "medium", "low"))
            self.assertTrue(len(art["description"]) > 50)
            self.assertTrue(len(art["vulnerable_code"]) > 10)
            self.assertTrue(len(art["remediation_code"]) > 10)

        # Single article lookup
        sqli = get_article_by_id("kb-001-cwe-89-sqli")
        self.assertIsNotNone(sqli)
        self.assertEqual(sqli["cwe_id"], "CWE-89")

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # 7. PDF Report Generator Test
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def test_pdf_report_generation(self):
        async def _test():
            scan_data = {
                "risk_score": 75.0,
                "vulnerabilities": [
                    {
                        "title": "SQL Injection in /api/login",
                        "severity": "critical",
                        "service": "http",
                        "port": 80,
                        "cve_id": "CVE-2023-1234",
                        "description": "SQL injection leads to auth bypass.",
                        "remediation_steps": ["Use parameterized queries."]
                    }
                ],
                "ai_analysis": {
                    "summary": "Target hosts critical SQL injection flaw.",
                    "risk_score": 75.0,
                    "top_recommendations": ["Fix SQL injection immediately."]
                },
                "tools_used": ["Nmap", "Headers", "SQLMap"]
            }

            pdf_bytes = await generate_pdf_report(scan_data, "http://testphp.vulnweb.com")
            self.assertIsInstance(pdf_bytes, bytes)
            self.assertGreater(len(pdf_bytes), 100)
            self.assertTrue(pdf_bytes.startswith(b"%PDF"))

        self.loop.run_until_complete(_test())


if __name__ == "__main__":
    print("======================================================")
    print("[TEST] RUNNING ORION SERVICES & SCANNERS UNIT TESTS [TEST]")
    print("======================================================")
    unittest.main(verbosity=2)
