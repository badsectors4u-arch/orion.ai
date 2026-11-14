"""
Unit tests for Autonomous AI Deep Hunter (Phase 4.5).
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from orion.ai.deep_hunter import AIDeepHunter
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.schemas import (
    AIResponse,
    DiscoveryResult,
    ReconResult,
    SanitizedTarget,
    VulnerabilityItem,
)


class TestAIDeepHunter(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.target = SanitizedTarget(
            original="https://example.com/",
            scheme="https",
            hostname="example.com",
            port=443,
            path="/",
            resolved_ip="93.184.216.34",
            is_private=False,
            url="https://example.com/",
            effective_port=443,
        )
        self.recon = ReconResult()
        self.discovery = DiscoveryResult(
            crawled_urls=["https://example.com/Comments.aspx?id=1"],
            forms=[],
            js_endpoints=["/api/v1/user/settings"],
        )
        self.ai_adapter = UniversalAIAdapter({"provider": "cloud", "api_key": ""})
        self.hunter = AIDeepHunter(self.ai_adapter)

    def test_scope_enforcer(self):
        """Ensures probes never leave the authorized target domain."""
        self.assertTrue(self.hunter._is_in_scope("https://example.com/api", "example.com"))
        self.assertTrue(self.hunter._is_in_scope("https://sub.example.com/api", "example.com"))
        self.assertFalse(self.hunter._is_in_scope("https://evil.com/steal", "example.com"))
        self.assertFalse(self.hunter._is_in_scope("https://attacker.org/", "example.com"))

    async def test_time_budget_enforcement(self):
        """Ensures the hunter respects the strict time budget without blocking."""
        with patch.object(self.hunter, "_run_hunting_routine", side_effect=asyncio.TimeoutError):
            vulns = await self.hunter.hunt(
                target=self.target,
                recon=self.recon,
                discovery=self.discovery,
                existing_vulns=[],
                max_duration_seconds=0.1,
            )
            self.assertEqual(len(vulns), 0)

    async def test_ai_hypothesis_success(self):
        """Tests that when AI generates valid hypothesis and probe matches, vulnerability is created."""
        mock_ai_resp = AIResponse(
            ok=True,
            data={
                "probes": [
                    {
                        "path": "/api/v1/user/settings",
                        "method": "GET",
                        "params": {"debug": "1"},
                        "expected_indicator": "api_secret_key",
                        "vuln_title": "Debug Key Leakage in API Settings",
                        "severity": "high",
                    }
                ]
            },
        )
        self.hunter.ai.call = AsyncMock(return_value=mock_ai_resp)

        mock_http_resp = AsyncMock()
        mock_http_resp.status_code = 200
        mock_http_resp.text = "System response contains: api_secret_key=xyz123"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_http_resp)

        vulns = await self.hunter._ai_assisted_hypothesis_loop(
            client=mock_client,
            target=self.target,
            urls=["https://example.com/api/v1/user/settings"],
            current_vulns=[],
            remaining_seconds=60.0,
        )
        self.assertEqual(len(vulns), 1)
        self.assertIn("Debug Key Leakage", vulns[0].title)
        self.assertEqual(vulns[0].severity, "high")
        self.assertEqual(vulns[0].cve_id, "CWE-20")


if __name__ == "__main__":
    unittest.main()

