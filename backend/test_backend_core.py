"""
Orion Security Platform — Member 2 Comprehensive Integration Test Suite.

Verifies end-to-end functionality of Member 2 Backend:
1. System Health Endpoint (/api/health)
2. Authentication (Register, Login, /me, Custom AI Provider Settings)
3. Target Management (Create, List, Delete)
4. Daily Scan Quotas (Free Tier 3-scan enforcement -> HTTP 429)
5. Plan Upgrades (Free -> Pro direct upgrade & quota unlock)
6. Scan Lifecycle & Details (/api/scans, /api/scans/{id})
7. Scan Diff Engine (/api/scans/compare -> resolved, new, persistent, score improvement)
8. Threat Intelligence Breach Checker (/api/threats/breach-check)
9. OWASP Knowledgebase (Public listing, search filter, plan-gated remediation code)
10. AI Security Copilot (/api/ai/chat)
11. Executive Assessment PDF Export (/api/scans/{id}/pdf)
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock
import uuid
from datetime import datetime

# Configure test environment
os.environ["DATABASE_URL"] = "sqlite:///./test_orion_m2.db"
os.environ["SECRET_KEY"] = "test-secret-key-orion-backend-2026"

# Ensure backend root is on sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient
from orion.api.main import app
from orion.models.database import Base, Scan, SessionLocal, Target, User, Vulnerability, engine, init_db
from orion.services.kb_service import seed_knowledgebase


class TestMember2BackendCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Prepare fresh test database and API test client."""
        # Drop previous test DB if exists
        Base.metadata.drop_all(bind=engine)
        init_db()

        # Seed KB articles
        db = SessionLocal()
        try:
            import asyncio
            asyncio.run(seed_knowledgebase(db))
        finally:
            db.close()

        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        """Clean up test database file."""
        Base.metadata.drop_all(bind=engine)
        if os.path.exists("./test_orion_m2.db"):
            try:
                os.remove("./test_orion_m2.db")
            except Exception:
                pass

    def test_01_health_endpoint(self):
        """Verify GET /api/health returns 200 OK."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["platform"], "Orion Security Platform")

    def test_02_auth_registration_and_jwt(self):
        """Verify user registration returns Bearer token and Free plan."""
        payload = {
            "email": "lead_auditor@orion-sec.io",
            "password": "StrongPassword2026!",
            "username": "lead_auditor",
        }
        res = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["token_type"], "bearer")
        self.assertEqual(data["user"]["plan"], "free")
        self.assertEqual(data["user"]["email"], "lead_auditor@orion-sec.io")

        # Test duplicate registration rejection (HTTP 400)
        res_dup = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(res_dup.status_code, 400)

    def test_03_auth_login_and_me(self):
        """Verify login returns valid token and /me fetches user profile."""
        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]

        headers = {"Authorization": f"Bearer {token}"}
        me_res = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["username"], "lead_auditor")

    def test_04_user_custom_ai_settings(self):
        """Verify user can update AI provider to BYOK / Local Ollama."""
        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        update_payload = {
            "ai_provider": "local_ollama",
            "ai_base_url": "http://localhost:11434/v1",
            "ai_model": "qwen2.5-coder:14b",
        }
        res = self.client.put("/api/auth/settings", json=update_payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["ai_provider"], "local_ollama")
        self.assertEqual(data["ai_model"], "qwen2.5-coder:14b")

    def test_05_target_management_crud(self):
        """Verify POST, GET, and DELETE /api/targets."""
        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Create target
        res = self.client.post("/api/targets", json={"url": "http://testaspnet.vulnweb.com"}, headers=headers)
        self.assertEqual(res.status_code, 201)
        target_id = res.json()["id"]
        self.assertEqual(res.json()["domain"], "testaspnet.vulnweb.com")

        # List targets
        list_res = self.client.get("/api/targets", headers=headers)
        self.assertEqual(list_res.status_code, 200)
        self.assertTrue(len(list_res.json()) >= 1)

        # Delete target
        del_res = self.client.delete(f"/api/targets/{target_id}", headers=headers)
        self.assertEqual(del_res.status_code, 204)

    @mock.patch("orion.tasks.scan_tasks.execute_scan_task_sync")
    @mock.patch("orion.tasks.scan_tasks.run_scan_task.delay")
    def test_06_daily_quota_guard_and_plan_upgrade(self, mock_delay, mock_sync):
        """
        Verify Free tier daily quota limit (3 scans/day):
        1. Free user launches 3 scans successfully.
        2. 4th scan is blocked with HTTP 429 Too Many Requests.
        3. User upgrades to Pro tier.
        4. 4th scan now succeeds immediately!
        """
        # Register a separate free user
        user_res = self.client.post(
            "/api/auth/register",
            json={"email": "quota_test@orion.sec", "password": "TestPassword123!"},
        )
        token = user_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Check initial quota
        q_res = self.client.get("/api/plans/quota", headers=headers)
        self.assertEqual(q_res.status_code, 200)
        self.assertEqual(q_res.json()["daily_limit"], 3)
        self.assertEqual(q_res.json()["scans_today"], 0)
        self.assertEqual(q_res.json()["scans_remaining"], 3)

        # Launch 3 scans
        for i in range(3):
            scan_payload = {
                "target_url": f"http://example{i}.org",
                "scan_type": "quick",
                "ai_hunter_duration": 300,
            }
            s_res = self.client.post("/api/scans", json=scan_payload, headers=headers)
            self.assertEqual(s_res.status_code, 201)
            self.assertEqual(s_res.json()["status"], "pending")

        # 4th scan MUST trigger HTTP 429 Quota Exceeded
        blocked_res = self.client.post(
            "/api/scans",
            json={"target_url": "http://example-blocked.org", "scan_type": "quick"},
            headers=headers,
        )
        self.assertEqual(blocked_res.status_code, 429)
        self.assertIn("Daily scan", blocked_res.json()["detail"])

        # Upgrade to Pro
        upgrade_res = self.client.post(
            "/api/plans/upgrade", json={"plan": "pro"}, headers=headers
        )
        self.assertEqual(upgrade_res.status_code, 200)
        self.assertEqual(upgrade_res.json()["new_plan"], "pro")

        # Now 4th scan must succeed on Pro!
        unblocked_res = self.client.post(
            "/api/scans",
            json={"target_url": "http://example-unblocked.org", "scan_type": "quick"},
            headers=headers,
        )
        self.assertEqual(unblocked_res.status_code, 201)

    def test_07_scan_diff_comparison_engine(self):
        """
        Verify GET /api/scans/compare correctly calculates:
        - resolved vulnerabilities
        - new vulnerabilities
        - persistent vulnerabilities
        - security score improvement percentage
        """
        # Create user & token
        user_res = self.client.post(
            "/api/auth/register",
            json={"email": "diff_engineer@orion.sec", "password": "DiffPassword123!"},
        )
        token = user_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        user_id = user_res.json()["user"]["id"]

        db = SessionLocal()
        try:
            # Create target
            target = Target(user_id=user_id, url="http://testaspnet.vulnweb.com", domain="testaspnet.vulnweb.com")
            db.add(target)
            db.commit()
            db.refresh(target)

            # Create Baseline Scan A (Contains SQLi and XSS)
            scan_a = Scan(
                target_id=target.id,
                user_id=user_id,
                target_url="http://testaspnet.vulnweb.com",
                status="completed",
                completed_at=datetime.utcnow(),
                risk_score=75.0,
            )
            db.add(scan_a)
            db.commit()
            db.refresh(scan_a)

            v1_a = Vulnerability(
                scan_id=scan_a.id,
                title="SQL Injection in /artists.aspx",
                severity="critical",
                service="http",
                port=80,
                cvss_score=9.8,
                description="### 📍 Vulnerability Location\nhttp://testaspnet.vulnweb.com/artists.aspx?artist=1",
            )
            v2_a = Vulnerability(
                scan_id=scan_a.id,
                title="Reflected XSS in search.aspx",
                severity="high",
                service="http",
                port=80,
                cvss_score=7.5,
                description="### 📍 Vulnerability Location\nhttp://testaspnet.vulnweb.com/search.aspx?query=<script>",
            )
            db.add_all([v1_a, v2_a])
            db.commit()

            # Create Follow-up Scan B (SQLi was resolved, XSS is persistent, SSRF is newly introduced)
            scan_b = Scan(
                target_id=target.id,
                user_id=user_id,
                target_url="http://testaspnet.vulnweb.com",
                status="completed",
                completed_at=datetime.utcnow(),
                risk_score=45.0,
            )
            db.add(scan_b)
            db.commit()
            db.refresh(scan_b)

            v2_b = Vulnerability(
                scan_id=scan_b.id,
                title="Reflected XSS in search.aspx",
                severity="high",
                service="http",
                port=80,
                cvss_score=7.5,
                description="### 📍 Vulnerability Location\nhttp://testaspnet.vulnweb.com/search.aspx?query=<script>",
            )
            v3_b = Vulnerability(
                scan_id=scan_b.id,
                title="Server-Side Request Forgery in /fetch.aspx",
                severity="medium",
                service="http",
                port=80,
                cvss_score=6.5,
                description="### 📍 Vulnerability Location\nhttp://testaspnet.vulnweb.com/fetch.aspx",
            )
            db.add_all([v2_b, v3_b])
            db.commit()

            scan_a_id = str(scan_a.id)
            scan_b_id = str(scan_b.id)
        finally:
            db.close()

        # Call Diff API
        diff_res = self.client.get(
            f"/api/scans/compare?scan_a={scan_a_id}&scan_b={scan_b_id}",
            headers=headers,
        )
        self.assertEqual(diff_res.status_code, 200)
        diff_data = diff_res.json()

        # Assertions
        resolved = [v["title"] for v in diff_data["resolved_vulnerabilities"]]
        new = [v["title"] for v in diff_data["new_vulnerabilities"]]
        persistent = [v["title"] for v in diff_data["persistent_vulnerabilities"]]

        self.assertIn("SQL Injection in /artists.aspx", resolved)
        self.assertIn("Server-Side Request Forgery in /fetch.aspx", new)
        self.assertIn("Reflected XSS in search.aspx", persistent)

        # Score formula: ((1 resolved - 1 new) / 2 total) * 100 = 0.0
        self.assertEqual(diff_data["security_score_improvement"], 0.0)

    def test_08_breach_checker(self):
        """Verify POST /api/threats/breach-check returns structured breach intelligence."""
        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        res = self.client.post(
            "/api/threats/breach-check",
            json={"email": "test-admin@target-domain.com"},
            headers=headers,
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["email"], "test-admin@target-domain.com")
        self.assertIn("breach_count", data)
        self.assertIn("breaches", data)

    def test_09_knowledgebase_public_and_plan_gating(self):
        """
        Verify OWASP Knowledgebase:
        1. Public listing returns articles.
        2. Keyword search filters articles.
        3. Free user detail request masks remediation_code.
        4. Pro user detail request receives full remediation code!
        """
        # Public listing (no auth header)
        res = self.client.get("/api/knowledgebase")
        self.assertEqual(res.status_code, 200)
        articles = res.json()
        self.assertTrue(len(articles) >= 1)

        # Keyword search
        search_res = self.client.get("/api/knowledgebase?search=sql")
        self.assertEqual(search_res.status_code, 200)
        search_articles = search_res.json()
        self.assertTrue(any("SQL" in a["title"] for a in search_articles))

        # Free user detail check (Remediation code must be None)
        free_login = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        free_token = free_login.json()["access_token"]
        free_headers = {"Authorization": f"Bearer {free_token}"}

        free_detail = self.client.get("/api/knowledgebase/CWE-89", headers=free_headers)
        self.assertEqual(free_detail.status_code, 200)
        # Free plan user receives None for remediation_code
        self.assertIsNone(free_detail.json()["remediation_code"])

        # Pro user detail check (Remediation code must be present)
        pro_login = self.client.post(
            "/api/auth/login",
            json={"email": "quota_test@orion.sec", "password": "TestPassword123!"},
        )
        pro_token = pro_login.json()["access_token"]
        pro_headers = {"Authorization": f"Bearer {pro_token}"}

        pro_detail = self.client.get("/api/knowledgebase/CWE-89", headers=pro_headers)
        self.assertEqual(pro_detail.status_code, 200)
        self.assertIsNotNone(pro_detail.json()["remediation_code"])
        self.assertIn("prepared statements", (pro_detail.json()["remediation_code"] or "").lower())

    @mock.patch("orion.ai.universal_ai_adapter.UniversalAIAdapter.call")
    def test_10_ai_copilot_chat(self, mock_adapter_call):
        """Verify POST /api/ai/chat returns structured security copilot reply."""
        from orion.ai.universal_ai_adapter import AIResponse
        mock_adapter_call.return_value = AIResponse(
            ok=True,
            data={
                "answer": "لحماية الكود من ثغرة SQL Injection يجب استخدام الاستعلامات المجهزة Parameterized Queries.",
                "key_points": ["Prepared Statements", "Input Sanitization"],
                "severity": "critical",
                "suggestions": ["عرض كود آمن"],
                "references": ["OWASP A03:2021", "CWE-89"],
            },
        )

        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "lead_auditor@orion-sec.io", "password": "StrongPassword2026!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        chat_payload = {
            "message": "كيف يمكن إصلاح ثغرة SQL Injection في كود بايثون؟",
            "history": [],
        }
        res = self.client.post("/api/ai/chat", json=chat_payload, headers=headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("answer", data)
        self.assertIn("key_points", data)
        self.assertIn("suggestions", data)
        self.assertTrue(len(data["answer"]) > 10)

    def test_11_pdf_export_route(self):
        """Verify GET /api/scans/{id}/pdf streams a valid PDF assessment report."""
        login_res = self.client.post(
            "/api/auth/login",
            json={"email": "diff_engineer@orion.sec", "password": "DiffPassword123!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Fetch scans for this user
        scans_res = self.client.get("/api/scans", headers=headers)
        self.assertEqual(scans_res.status_code, 200)
        scans = scans_res.json()
        self.assertTrue(len(scans) >= 1)
        scan_id = scans[0]["id"]

        # Request PDF download
        pdf_res = self.client.get(f"/api/scans/{scan_id}/pdf", headers=headers)
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers.get("content-type"), "application/pdf")
        self.assertTrue(len(pdf_res.content) > 100)
        # Verify PDF header magic bytes %PDF
        self.assertTrue(pdf_res.content.startswith(b"%PDF"))


if __name__ == "__main__":
    unittest.main()
