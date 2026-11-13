import asyncio
import unittest
from orion.core.schemas import SanitizedTarget
from orion.core.tools.sqlmap_scanner import SqlmapScanner


class TestSqlmapParser(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.scanner = SqlmapScanner()
        self.target = SanitizedTarget(
            original="http://example.com/?id=1",
            scheme="http",
            hostname="example.com",
            port=None,
            resolved_ip="93.184.216.34",
            path="/",
            url="http://example.com/?id=1"
        )

    def tearDown(self):
        self.loop.close()

    def test_two_parameters_multiple_techniques(self):
        async def _test():
            raw = """
            [INFO] testing connection
            Parameter: id (GET)
                Type: boolean-based blind
                Type: time-based blind
            Parameter: name (POST)
                Type: error-based
            """
            vulns = await self.scanner.parse_output(raw, self.target)
            self.assertEqual(len(vulns), 2)
            self.assertEqual(vulns[0].title, "SQL Injection in 'id' parameter (GET)")
            self.assertIn("boolean-based blind, time-based blind", vulns[0].description)
            self.assertEqual(vulns[0].severity, "critical")
            self.assertEqual(vulns[0].cvss_score, 9.8)

            self.assertEqual(vulns[1].title, "SQL Injection in 'name' parameter (POST)")
            self.assertIn("error-based", vulns[1].description)

        self.loop.run_until_complete(_test())

    def test_cookie_parameter(self):
        async def _test():
            raw = """
            Parameter: session_token (Cookie)
                Type: boolean-based blind
            """
            vulns = await self.scanner.parse_output(raw, self.target)
            self.assertEqual(len(vulns), 1)
            self.assertEqual(vulns[0].title, "SQL Injection in 'session_token' parameter (Cookie)")

        self.loop.run_until_complete(_test())

    def test_duplicate_param(self):
        async def _test():
            raw = """
            Parameter: id (GET)
                Type: boolean-based blind
            Parameter: id (GET)
                Type: error-based
            """
            vulns = await self.scanner.parse_output(raw, self.target)
            self.assertEqual(len(vulns), 1)
            self.assertIn("boolean-based blind", vulns[0].description)

        self.loop.run_until_complete(_test())


if __name__ == "__main__":
    unittest.main()
