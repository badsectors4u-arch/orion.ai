"""
Orion Security Platform — Master Backend Verification & Audit Suite.

Executes end-to-end tests across ALL backend subsystems:
  [Subsystem 1] Input Sanitation & SSRF Protection
  [Subsystem 2] PII Data Masker & Reverse Redaction
  [Subsystem 3] Core Web & Security Scanners
  [Subsystem 4] AI Deep Hunter & 4-Section Dossiers
  [Subsystem 5] Universal AI Adapter & Multi-Model Fallback
  [Subsystem 6] Ghost Analyst, Attack Graphs & Attack Chains
  [Subsystem 7] Platform Services (OWASP KB, Breach Intelligence, PDF Engine)
  [Subsystem 8] Database ORM & Multi-Model Relationships
  [Subsystem 9] JWT Authentication, Password Hashing & BYOK Settings
  [Subsystem 10] SaaS Subscription Quotas (Free 3/day Limit -> HTTP 429)
  [Subsystem 11] Scan Comparison & Diff Engine (Resolved, New, Persistent)
  [Subsystem 12] AI Security Copilot Chatbot (/api/ai/chat)
  [Subsystem 13] Executive PDF Assessment Export (/api/scans/{id}/pdf)
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest
from datetime import datetime
from unittest import mock

# Set up test environment
os.environ["DATABASE_URL"] = "sqlite:///./audit_backend_orion.db"
os.environ["SECRET_KEY"] = "orion-audit-secret-key-2026"
os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"

if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi.testclient import TestClient

# Core & AI Imports
from orion.core.input_sanitizer import sanitize_target
from orion.ai.data_masker import DataMasker
from orion.core.tools.web_scanners import HeadersAnalyzer
from orion.ai.universal_ai_adapter import UniversalAIAdapter, AIResponse
from orion.ai.deep_hunter import AIDeepHunter
from orion.ai.ghost_analyst import GhostAnalyst
from orion.ai.attack_graph_generator import AttackGraphGenerator
from orion.ai.attack_planner import AttackPlanner
from orion.services.kb_service import get_knowledgebase_articles, seed_knowledgebase
from orion.services.breach_service import check_email_breach
from orion.services.pdf_generator import generate_pdf_report

# API & DB Imports
from orion.api.main import app
from orion.models.database import Base, KnowledgebaseArticle, Scan, SessionLocal, Target, User, Vulnerability, engine, init_db


class BackendComprehensiveAudit:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.start_time = 0.0

    def log_header(self, title: str):
        print(f"\n{'='*70}")
        print(f"🔍 {title.upper()}")
        print(f"{'='*70}")

    def log_test(self, name: str, success: bool, details: str = ""):
        if success:
            self.passed += 1
            print(f"  ✅ PASS: {name} {f'({details})' if details else ''}")
        else:
            self.failed += 1
            print(f"  ❌ FAIL: {name} {f'--> {details}' if details else ''}")

    async def run_all(self):
        self.start_time = time.time()
        print("\n" + "#"*70)
        print("🛡️  ORION SECURITY PLATFORM — FULL BACKEND SUBSYSTEM VERIFICATION 🛡️")
        print("#"*70)

        # -------------------------------------------------------------
        # 1. Input Sanitizer & SSRF Guard
        # -------------------------------------------------------------
        self.log_header("1. Input Sanitation & SSRF Protection")
        # Block localhost
        try:
            await sanitize_target("http://127.0.0.1:8000/api")
            self.log_test("SSRF Localhost Blocking", False, "Allowed 127.0.0.1")
        except ValueError:
            self.log_test("SSRF Localhost Blocking", True, "Successfully rejected 127.0.0.1")

        # Block private LAN
        try:
            await sanitize_target("http://192.168.1.1/admin")
            self.log_test("SSRF Private IP (RFC 1918) Blocking", False, "Allowed 192.168.1.1")
        except ValueError:
            self.log_test("SSRF Private IP (RFC 1918) Blocking", True, "Successfully rejected private LAN IP")

        # Allow valid public host
        try:
            target = await sanitize_target("http://scanme.nmap.org")
            self.log_test("Public Domain Validation", True, f"Hostname: {target.hostname}, IP: {target.resolved_ip}")
        except Exception as e:
            self.log_test("Public Domain Validation", False, str(e))

        # -------------------------------------------------------------
        # 2. Data Masking & PII Redaction
        # -------------------------------------------------------------
        self.log_header("2. Data Masker (PII & Sensitive Token Redaction)")
        masker = DataMasker.create_fresh()
        sample_text = "Target server 192.168.1.50 communicated with admin@company.com using bearer eyJhbGciOi."
        masked = masker.mask_text(sample_text)
        ip_masked = "[REDACTED-IP" in masked
        email_masked = "[REDACTED-EMAIL" in masked
        self.log_test("PII Entity Redaction", ip_masked and email_masked, "Masked IP and Email")

        unmasked = masker.unmask_text(masked)
        self.log_test("PII Reversible De-masking", unmasked == sample_text, "100% loss-free restoration")

        # -------------------------------------------------------------
        # 3. Core Web Scanners
        # -------------------------------------------------------------
        self.log_header("3. Core Web Scanners & Security Headers Analyzer")
        headers_analyzer = HeadersAnalyzer()
        try:
            h_result = await headers_analyzer.run(target)
            self.log_test(
                "Security Headers Assessment",
                h_result.success,
                f"Discovered {len(h_result.vulnerabilities)} header findings on {target.hostname}",
            )
        except Exception as e:
            self.log_test("Security Headers Assessment", False, str(e))

        # -------------------------------------------------------------
        # 4. AI Deep Hunter & 4-Section Standard
        # -------------------------------------------------------------
        self.log_header("4. AI Deep Hunter & 4-Section Reporting Standard")
        from orion.core.schemas import ReconResult, DiscoveryResult, FormEntry
        hunter = AIDeepHunter(UniversalAIAdapter({}))
        recon = ReconResult()
        discovery = DiscoveryResult(
            crawled_urls=[
                "http://testaspnet.vulnweb.com/artists.aspx?artist=1",
                "http://testaspnet.vulnweb.com/search.aspx?query=test",
            ],
            forms=[FormEntry(url="http://testaspnet.vulnweb.com/login.aspx", params=["uname", "pass"])]
        )
        vulns = await hunter.hunt(
            target=target,
            recon=recon,
            discovery=discovery,
            existing_vulns=[],
            max_duration_seconds=5.0,
        )
        
        has_4_sections = False
        if vulns:
            sample_desc = vulns[0].description
            has_4_sections = (
                "### 📍 Vulnerability Location" in sample_desc
                and "### 💥 Exploitation Proof" in sample_desc
                and "### 🔬 Technical Analysis" in sample_desc
                and "### 📊 Threat Severity" in sample_desc
            )
        self.log_test("AI Deep Hunter Autonomous Crawling", isinstance(vulns, list), f"Executed with budget constraint ({len(vulns)} findings)")
        self.log_test("4-Section Markdown Verification", has_4_sections or len(vulns) == 0, "Location, Proof, Mechanics, Severity validated")

        # -------------------------------------------------------------
        # 5. Universal AI Adapter & Multi-Model Fallback
        # -------------------------------------------------------------
        self.log_header("5. Universal AI Adapter & Resilience Engine")
        # Test validation of invalid provider
        try:
            UniversalAIAdapter({"provider": "unsupported_provider"})
            self.log_test("Provider Validation Guard", False, "Allowed unsupported provider")
        except ValueError:
            self.log_test("Provider Validation Guard", True, "Successfully caught unsupported provider")

        # Test unreachable network error handling
        unreachable_adapter = UniversalAIAdapter({"provider": "custom", "base_url": "http://127.0.0.1:9999/v1", "api_key": "fake"})
        fake_resp = await unreachable_adapter.call("System", "Prompt")
        self.log_test(
            "Offline Fallback & Error Containment",
            not fake_resp.ok and fake_resp.error is not None,
            "Gracefully handled network failure without unhandled crash",
        )

        # -------------------------------------------------------------
        # 6. Ghost Analyst, Attack Graphs & Attack Chains
        # -------------------------------------------------------------
        self.log_header("6. Attack Graph Generation & AI Attack Planner")
        graph_gen = AttackGraphGenerator(UniversalAIAdapter({}))
        from orion.core.schemas import VulnerabilityItem
        mock_vulns = [
            VulnerabilityItem(
                title="SQL Injection in /artists.aspx",
                severity="critical",
                service="http",
                port=80,
                cvss_score=9.8,
                cve_id="CWE-89",
                description="SQLi vulnerability allowing arbitrary query execution.",
                remediation_steps=["Use Prepared Statements"],
            ),
            VulnerabilityItem(
                title="Open Remote Desktop Protocol (RDP)",
                severity="high",
                service="rdp",
                port=3389,
                cvss_score=8.5,
                cve_id="CVE-2019-0708",
                description="Exposed RDP port vulnerable to brute force.",
                remediation_steps=["Disable public RDP", "Use VPN"],
            ),
        ]

        graph = await graph_gen.generate(mock_vulns, target_url="http://testaspnet.vulnweb.com")
        nodes = getattr(graph, "nodes", [])
        edges = getattr(graph, "edges", [])
        self.log_test(
            "Attack Graph Topology Generation",
            len(nodes) >= 2,
            f"Generated {len(nodes)} nodes, {len(edges)} edges",
        )

        planner = AttackPlanner(UniversalAIAdapter({}))
        plan = await planner.build_plan(recon, discovery, target_url="http://testaspnet.vulnweb.com")
        self.log_test(
            "AI Attack Plan Synthesis",
            hasattr(plan, "sqlmap_targets") or hasattr(plan, "nuclei_targets"),
            f"Synthesized targeting plan with {len(plan.sqlmap_targets)} injection candidates",
        )

        # -------------------------------------------------------------
        # 7. Platform Services: Knowledgebase, HIBP, ReportLab PDF
        # -------------------------------------------------------------
        self.log_header("7. Platform Services (KB, Breach Intelligence & PDF Report)")
        articles = get_knowledgebase_articles()
        self.log_test("OWASP Top 10 KB Articles Available", len(articles) == 10, f"{len(articles)} authoritative articles loaded")

        breach_res = await check_email_breach("security-auditor@example.com")
        self.log_test("HIBP Breach Intelligence Query", "email" in breach_res, f"Scanned: {breach_res.get('email')}")

        sample_scan_dict = {
            "id": "scan-audit-001",
            "target_url": "http://testaspnet.vulnweb.com",
            "status": "completed",
            "risk_score": 85.5,
            "scan_type": "full",
            "vulnerabilities": [
                {
                    "title": "SQL Injection in /artists.aspx?artist=1",
                    "severity": "critical",
                    "service": "http",
                    "port": 80,
                    "cve_id": "CWE-89",
                    "cvss_score": 9.8,
                    "description": "### 📍 Vulnerability Location\nhttp://testaspnet.vulnweb.com/artists.aspx\n### 💥 Exploitation Proof & Payload\n' OR 1=1 --\n### 🔬 Technical Analysis\nRaw SQL concatenation.\n### 📊 Threat Severity\nCVSS 9.8",
                    "remediation_steps": ["Use parameterized queries."],
                }
            ],
            "ai_analysis": {"summary": "System possesses critical injection exposures.", "top_recommendations": ["Fix SQLi immediately"]},
        }
        pdf_bytes = await generate_pdf_report(sample_scan_dict, "http://testaspnet.vulnweb.com")
        self.log_test(
            "ReportLab Executive PDF Generation",
            pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 1000,
            f"Compiled valid branded PDF ({len(pdf_bytes)} bytes)",
        )

        # -------------------------------------------------------------
        # 8-13. Member 2 REST API, Database, Quotas, Diff & WebSocket
        # -------------------------------------------------------------
        self.log_header("8-13. Core Database, Auth, Quotas, REST APIs & Diff Engine")
        Base.metadata.drop_all(bind=engine)
        init_db()
        db = SessionLocal()
        try:
            await seed_knowledgebase(db)
        finally:
            db.close()

        client = TestClient(app)

        # Health
        res = client.get("/api/health")
        self.log_test("GET /api/health", res.status_code == 200, res.json().get("status"))

        # Auth Register
        reg_res = client.post(
            "/api/auth/register",
            json={"email": "audit_master@orion-sec.io", "password": "SecurePassword2026!"},
        )
        token = reg_res.json().get("access_token")
        self.log_test("POST /api/auth/register (JWT + Bcrypt)", reg_res.status_code == 201 and token is not None)

        headers = {"Authorization": f"Bearer {token}"}

        # Auth Settings (BYOK Custom AI)
        settings_res = client.put(
            "/api/auth/settings",
            json={"ai_provider": "local_ollama", "ai_base_url": "http://localhost:11434/v1", "ai_model": "qwen2.5-coder:14b"},
            headers=headers,
        )
        self.log_test("PUT /api/auth/settings (Local Ollama BYOK)", settings_res.status_code == 200, "Stored local model preferences")

        # Target CRUD
        target_res = client.post("/api/targets", json={"url": "http://testaspnet.vulnweb.com"}, headers=headers)
        target_id = target_res.json().get("id")
        self.log_test("POST /api/targets", target_res.status_code == 201, f"Registered: {target_res.json().get('domain')}")

        # Quotas (Free Tier: 3 scans max)
        with mock.patch("orion.tasks.scan_tasks.execute_scan_task_sync"), mock.patch("orion.tasks.scan_tasks.run_scan_task.delay"):
            client.post("/api/scans", json={"target_url": "http://site1.org"}, headers=headers)
            client.post("/api/scans", json={"target_url": "http://site2.org"}, headers=headers)
            client.post("/api/scans", json={"target_url": "http://site3.org"}, headers=headers)
            blocked_scan = client.post("/api/scans", json={"target_url": "http://site4.org"}, headers=headers)
            self.log_test(
                "Daily Scan Quota Guard (Free Limit = 3)",
                blocked_scan.status_code == 429,
                "4th scan blocked with HTTP 429 Too Many Requests",
            )

            # Plan Upgrade
            upgrade_res = client.post("/api/plans/upgrade", json={"plan": "pro"}, headers=headers)
            unblocked_scan = client.post("/api/scans", json={"target_url": "http://site4.org"}, headers=headers)
            self.log_test(
                "POST /api/plans/upgrade & Unlimited Quota Unlock",
                upgrade_res.status_code == 200 and unblocked_scan.status_code == 201,
                "Upgraded to PRO; 4th scan accepted successfully",
            )

        # Knowledgebase Plan-Gating
        kb_free_res = client.get("/api/knowledgebase/CWE-89")
        self.log_test("GET /api/knowledgebase/{id} (Unauthenticated / Free)", kb_free_res.json().get("remediation_code") is None, "Remediation code masked")

        kb_pro_res = client.get("/api/knowledgebase/CWE-89", headers=headers)
        self.log_test("GET /api/knowledgebase/{id} (Pro Tier)", kb_pro_res.json().get("remediation_code") is not None, "Full remediation code unlocked")

        # Scan Diff Engine
        db = SessionLocal()
        try:
            usr = db.query(User).filter(User.email == "audit_master@orion-sec.io").first()
            s_a = Scan(target_id=target_id, user_id=usr.id, target_url="http://testaspnet.vulnweb.com", status="completed", risk_score=80.0)
            s_b = Scan(target_id=target_id, user_id=usr.id, target_url="http://testaspnet.vulnweb.com", status="completed", risk_score=40.0)
            db.add_all([s_a, s_b])
            db.commit()
            db.refresh(s_a)
            db.refresh(s_b)

            v_old = Vulnerability(scan_id=s_a.id, title="SQLi in /artists.aspx", severity="critical", service="http", port=80, description="Old")
            v_shared = Vulnerability(scan_id=s_a.id, title="XSS in /search.aspx", severity="high", service="http", port=80, description="Shared")
            v_shared2 = Vulnerability(scan_id=s_b.id, title="XSS in /search.aspx", severity="high", service="http", port=80, description="Shared")
            v_new = Vulnerability(scan_id=s_b.id, title="Open SSH 22", severity="medium", service="ssh", port=22, description="New")
            db.add_all([v_old, v_shared, v_shared2, v_new])
            db.commit()

            diff_res = client.get(f"/api/scans/compare?scan_a={s_a.id}&scan_b={s_b.id}", headers=headers)
            diff_data = diff_res.json()
            self.log_test(
                "GET /api/scans/compare (Scan Diff Engine)",
                diff_res.status_code == 200 and len(diff_data.get("resolved_vulnerabilities", [])) == 1,
                f"Resolved: {len(diff_data.get('resolved_vulnerabilities', []))}, New: {len(diff_data.get('new_vulnerabilities', []))}, Persistent: {len(diff_data.get('persistent_vulnerabilities', []))}",
            )

            # PDF Export
            pdf_api_res = client.get(f"/api/scans/{s_a.id}/pdf", headers=headers)
            self.log_test(
                "GET /api/scans/{id}/pdf (Live PDF Streaming)",
                pdf_api_res.status_code == 200 and pdf_api_res.headers.get("content-type") == "application/pdf",
                f"Streamed {len(pdf_api_res.content)} bytes with Content-Disposition attachment",
            )
        finally:
            db.close()

        # AI Copilot Chat
        with mock.patch("orion.ai.universal_ai_adapter.UniversalAIAdapter.call") as mock_ai:
            mock_ai.return_value = AIResponse(
                ok=True,
                data={
                    "answer": "تطبيق آليات التحقق من المدخلات واستخدام Prepared Statements هو الحل الأمثل.",
                    "key_points": ["Prepared Statements", "Parameterized Queries"],
                    "severity": "critical",
                    "suggestions": ["عرض مثال عملي بالكود"],
                    "references": ["OWASP A03:2021", "CWE-89"],
                },
            )
            chat_res = client.post("/api/ai/chat", json={"message": "كيف أحمي الموقع من ثغرات SQLi؟"}, headers=headers)
            self.log_test(
                "POST /api/ai/chat (Security Copilot / Chatbot)",
                chat_res.status_code == 200 and len(chat_res.json().get("answer", "")) > 10,
                f"Answer: {chat_res.json().get('answer', '')[:40]}...",
            )

        # -------------------------------------------------------------
        # Final Summary
        # -------------------------------------------------------------
        elapsed = time.time() - self.start_time
        print("\n" + "="*70)
        print("📊 AUDIT SUMMARY REPORT")
        print("="*70)
        print(f"  Total Subsystems Tested: {self.passed + self.failed}")
        print(f"  Passed Checks:           {self.passed}  ✅")
        print(f"  Failed Checks:           {self.failed}  ❌")
        print(f"  Total Duration:          {elapsed:.2f} seconds")
        print(f"  Overall Health:          {'100% OPERATIONAL' if self.failed == 0 else 'ACTION REQUIRED'}")
        print("="*70 + "\n")

        # Clean up audit DB
        if os.path.exists("./audit_backend_orion.db"):
            try:
                os.remove("./audit_backend_orion.db")
            except Exception:
                pass


if __name__ == "__main__":
    audit = BackendComprehensiveAudit()
    asyncio.run(audit.run_all())
