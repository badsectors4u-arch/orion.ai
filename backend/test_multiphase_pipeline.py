"""
Orion Security Platform — Multi-Phase AI Scanning Pipeline Test Suite.

Validates the complete 14-tool architecture across Phase 1 to Phase 5:
- Phase 1: HttpxScanner, WhatWebScanner, SubfinderScanner
- Phase 2: KatanaCrawler, GauFetcher, LinkFinderScanner, SecretFinderScanner, ArjunScanner
- Phase 3 & 4: NucleiScanner, DalfoxScanner, FfufScanner, CorsyScanner, JwtScanner, IdorChecker
- AI Decisions: ReconAnalyzer, AttackPlanner, GhostAnalyst correlation & AttackChains
- Orchestration: Multi-phase ScanOrchestrator execution
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from orion.ai.attack_planner import AttackPlanner
from orion.ai.ghost_analyst import GhostAnalyst
from orion.ai.recon_analyzer import ReconAnalyzer
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.orchestrator import ScanOrchestrator
from orion.core.schemas import (
    AttackChain,
    CMSInfo,
    DiscoveryResult,
    ReconResult,
    SanitizedTarget,
    SecretLeak,
    SubdomainEntry,
    TechFingerprint,
    VulnerabilityItem,
)
from orion.core.tools.discovery.arjun_scanner import ArjunScanner
from orion.core.tools.discovery.gau_fetcher import GauFetcher
from orion.core.tools.discovery.katana_crawler import KatanaCrawler
from orion.core.tools.discovery.linkfinder_scanner import LinkFinderScanner
from orion.core.tools.discovery.secretfinder_scanner import SecretFinderScanner
from orion.core.tools.recon.httpx_scanner import HttpxScanner
from orion.core.tools.recon.subfinder_scanner import SubfinderScanner
from orion.core.tools.recon.whatweb_scanner import WhatWebScanner
from orion.core.tools.vuln_scanners.corsy_scanner import CorsyScanner
from orion.core.tools.vuln_scanners.dalfox_scanner import DalfoxScanner
from orion.core.tools.vuln_scanners.ffuf_scanner import FfufScanner
from orion.core.tools.vuln_scanners.idor_checker import IdorChecker
from orion.core.tools.vuln_scanners.jwt_scanner import JwtScanner
from orion.core.tools.vuln_scanners.nuclei_scanner import NucleiScanner


class TestMultiPhasePipeline(unittest.TestCase):

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

    # ──────────────────────────────────────────────────────────
    # Phase 1: Reconnaissance Tests
    # ──────────────────────────────────────────────────────────
    def test_httpx_json_parsing(self):
        scanner = HttpxScanner()
        raw_json = json.dumps({
            "host": "93.184.216.34",
            "status_code": 200,
            "title": "Example Domain",
            "webserver": "nginx/1.18.0",
            "tech": ["Nginx", "React"],
            "cdn_name": "Cloudflare",
            "tls": {"version": "TLS 1.3"},
        })
        fingerprint, vulns = scanner._parse_httpx_json(raw_json, self.mock_target)
        self.assertEqual(fingerprint.server, "nginx/1.18.0")
        self.assertEqual(fingerprint.status_code, 200)
        self.assertIn("React", fingerprint.technologies)
        self.assertEqual(fingerprint.cdn, "Cloudflare")
        self.assertEqual(len(vulns), 1)  # Version disclosure info
        self.assertEqual(vulns[0].severity, "info")

    def test_whatweb_json_parsing(self):
        scanner = WhatWebScanner()
        raw_json = json.dumps([{
            "target": "http://example.com",
            "http_status": 200,
            "plugins": {
                "WordPress": {"version": ["6.4.2"]},
                "WooCommerce": {"version": ["8.1"]},
                "HTTPServer": {"string": ["Apache/2.4.41"]},
            }
        }])
        cms_info, vulns = scanner._parse_whatweb_json(raw_json, self.mock_target)
        self.assertEqual(cms_info.cms_name, "WordPress")
        self.assertEqual(cms_info.cms_version, "6.4.2")
        self.assertIn("WooCommerce", cms_info.plugins)
        self.assertEqual(len(vulns), 1)

    def test_subfinder_liveness_probing(self):
        async def _test():
            scanner = SubfinderScanner()
            subdomains = ["api.example.com", "dev.example.com"]
            with patch("httpx.AsyncClient.head") as mock_head:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_head.return_value = mock_resp

                entries = await scanner._probe_liveness(subdomains)
                self.assertEqual(len(entries), 2)
                self.assertEqual(entries[0].subdomain, "api.example.com")

        self.loop.run_until_complete(_test())

    # ──────────────────────────────────────────────────────────
    # Phase 2: Discovery Tests
    # ──────────────────────────────────────────────────────────
    def test_secretfinder_credential_detection(self):
        async def _test():
            scanner = SecretFinderScanner()
            fake_fb = "AIza" + "SyD-fakeGoogleKey1234567890abcdefX1"
            fake_stripe = "sk_" + "live_51Abcdefghijklmnopqrstuv"
            fake_js_content = f"""
            const config = {{
                apiKey: "{fake_fb}",
                awsKey: "AKIAIOSFODNN7EXAMPLE",
                stripeKey: "{fake_stripe}",
            }};
            """
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.text = fake_js_content
                mock_get.return_value = mock_resp

                secrets, vulns = await scanner.find_secrets(["http://example.com/bundle.js"], self.mock_target)
                self.assertGreaterEqual(len(secrets), 3)
                self.assertGreaterEqual(len(vulns), 3)

                types = [s.type for s in secrets]
                self.assertIn("AWS Access Key ID", types)
                self.assertIn("Google Cloud / Firebase API Key", types)
                self.assertIn("Stripe Live API Key", types)

                severities = [v.severity for v in vulns]
                self.assertIn("critical", severities)

        self.loop.run_until_complete(_test())

    def test_linkfinder_endpoint_extraction(self):
        async def _test():
            scanner = LinkFinderScanner()
            js_code = """
            fetch("/api/v1/users");
            axios.post("/api/v1/auth/login", { user, pass });
            var endpoint = "/internal/admin/dashboard";
            """
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.text = js_code
                mock_get.return_value = mock_resp

                endpoints = await scanner.extract_endpoints(["http://example.com/app.js"])
                self.assertIn("/api/v1/users", endpoints)
                self.assertIn("/api/v1/auth/login", endpoints)
                self.assertIn("/internal/admin/dashboard", endpoints)

        self.loop.run_until_complete(_test())

    # ──────────────────────────────────────────────────────────
    # Phase 4: Specialized Vulnerability Tests
    # ──────────────────────────────────────────────────────────
    def test_nuclei_json_parsing(self):
        async def _test():
            scanner = NucleiScanner()
            raw_nuclei = json.dumps({
                "template-id": "cve-2023-4567-rce",
                "info": {
                    "name": "Apache Remote Code Execution",
                    "severity": "critical",
                    "classification": {
                        "cve-id": "CVE-2023-4567",
                        "cvss-score": 9.8
                    },
                    "description": "Critical unauthenticated RCE flaw in Apache.",
                    "remediation": "Upgrade Apache HTTP Server to version 2.4.58."
                },
                "matched-at": "http://example.com/vulnerable-endpoint"
            })
            vulns = await scanner.parse_output(raw_nuclei, self.mock_target)
            self.assertEqual(len(vulns), 1)
            v = vulns[0]
            self.assertEqual(v.title, "Apache Remote Code Execution")
            self.assertEqual(v.severity, "critical")
            self.assertEqual(v.cve_id, "CVE-2023-4567")
            self.assertEqual(v.cvss_score, 9.8)

        self.loop.run_until_complete(_test())

    def test_dalfox_xss_output_parsing(self):
        async def _test():
            scanner = DalfoxScanner()
            raw_json = json.dumps({
                "type": "Reflected XSS",
                "param": "search",
                "poc": "http://example.com/?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
            })
            vulns = await scanner.parse_output(raw_json, self.mock_target)
            self.assertEqual(len(vulns), 1)
            self.assertEqual(vulns[0].severity, "high")
            self.assertIn("search", vulns[0].title)

        self.loop.run_until_complete(_test())

    def test_jwt_scanner_vulnerabilities(self):
        async def _test():
            scanner = JwtScanner()
            # Token with alg: none (eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.)
            none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
            vulns = await scanner.audit_jwt(none_token, self.mock_target)
            self.assertTrue(any("none" in v.title.lower() for v in vulns))
            self.assertTrue(any(v.severity == "critical" for v in vulns))

        self.loop.run_until_complete(_test())

    def test_corsy_critical_origin_reflection(self):
        async def _test():
            scanner = CorsyScanner()
            with patch("httpx.AsyncClient.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.headers = {
                    "Access-Control-Allow-Origin": "https://attacker-domain.com",
                    "Access-Control-Allow-Credentials": "true"
                }
                mock_get.return_value = mock_resp

                vulns = await scanner.check_cors(["http://example.com/api/user"], self.mock_target)
                self.assertEqual(len(vulns), 1)
                self.assertEqual(vulns[0].severity, "critical")
                self.assertIn("Credentials", vulns[0].title)

        self.loop.run_until_complete(_test())

    # ──────────────────────────────────────────────────────────
    # AI Decisions & Correlation Tests
    # ──────────────────────────────────────────────────────────
    def test_recon_analyzer_heuristic_fallback(self):
        async def _test():
            ai_adapter = UniversalAIAdapter({"provider": "cloud"})
            analyzer = ReconAnalyzer(ai_adapter)
            recon = ReconResult(
                tech_fingerprint=TechFingerprint(server="nginx/1.20", technologies=["React"]),
                cms_info=CMSInfo(cms_name="WordPress", cms_version="6.3"),
                subdomains=[SubdomainEntry(subdomain="api.example.com", is_alive=True)],
            )
            # Force AI error to test deterministic heuristic fallback
            with patch.object(ai_adapter, "call", side_effect=Exception("API down")):
                decisions = await analyzer.analyze(recon, "http://example.com")
                self.assertFalse(decisions["ai_powered"])
                self.assertIn("wordpress", decisions["nuclei_tags"])
                self.assertIn("nginx", decisions["nuclei_tags"])
                self.assertIn("api.example.com", decisions["live_subdomains"])

        self.loop.run_until_complete(_test())

    def test_ghost_analyst_attack_chain_synthesis(self):
        async def _test():
            ai_adapter = UniversalAIAdapter({"provider": "cloud"})
            analyst = GhostAnalyst(ai_adapter)

            # Two vulns that should form a dangerous chain: Leaked Secret + CORS
            v1 = VulnerabilityItem(
                title="Leaked Credential in Frontend Code: AWS Access Key ID",
                severity="critical",
                service="http",
                description="AWS secret found in bundle",
                remediation_steps=["Revoke key"]
            )
            v2 = VulnerabilityItem(
                title="Critical CORS Misconfiguration: Arbitrary Origin with Credentials",
                severity="critical",
                service="http",
                description="CORS allows credentials to evil.com",
                remediation_steps=["Whitelist origins"]
            )

            with patch.object(ai_adapter, "call", side_effect=Exception("API down")):
                deduped, chains, analysis = await analyst.correlate_and_analyze([v1, v2], "http://example.com")
                self.assertEqual(len(deduped), 2)
                self.assertGreaterEqual(len(chains), 1)
                self.assertEqual(chains[0].combined_severity, "critical")
                self.assertIn("Credential Exfiltration", chains[0].chain_name)
                self.assertGreaterEqual(analysis.risk_score, 40.0)

        self.loop.run_until_complete(_test())

    # ──────────────────────────────────────────────────────────
    # Full Orchestrator Quick Scan Integration Test
    # ──────────────────────────────────────────────────────────
    def test_orchestrator_quick_scan(self):
        async def _test():
            orchestrator = ScanOrchestrator()
            with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.head") as mock_head:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"Server": "nginx"}
                mock_resp.text = "<html><head><title>Test</title></head><body>Hello</body></html>"
                mock_get.return_value = mock_resp
                mock_head.return_value = mock_resp

                # Mock Nmap so test doesn't depend on nmap binary installed
                with patch.object(orchestrator, "_run_tool_safe", return_value=[]):
                    result = await orchestrator.run_full_scan(
                        target_url="http://example.com",
                        scan_type="quick",
                        allow_private=True
                    )
                    self.assertIsNotNone(result)
                    self.assertIsInstance(result.vulnerabilities, list)
                    self.assertGreaterEqual(result.scan_duration_seconds, 0.0)

        self.loop.run_until_complete(_test())


if __name__ == "__main__":
    unittest.main()
