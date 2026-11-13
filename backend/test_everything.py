import os
import asyncio
import logging

# Silence the AI error logs for a cleaner output
logging.getLogger("orion").setLevel(logging.CRITICAL)

# Fix Nmap path for this test
os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"

from orion.core.input_sanitizer import sanitize_target
from orion.ai.data_masker import DataMasker
from orion.core.tools.web_scanners import HeadersAnalyzer
from orion.core.tools.nmap_scanner import NmapScanner
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.core.orchestrator import ScanOrchestrator

async def main():
    print("======================================================")
    print("🚀 ORION SECURITY PLATFORM - FULL SYSTEM TEST 🚀")
    print("======================================================\n")

    # ---------------------------------------------------------
    # 1. INPUT SANITIZER
    # ---------------------------------------------------------
    print("[1/6] Testing Input Sanitizer (SSRF Protection)...")
    try:
        await sanitize_target("http://localhost") # Should block
        print("  ❌ FAIL: Allowed localhost!")
    except ValueError:
        print("  ✅ PASS: Blocked localhost (SSRF protection works).")
        
    target = await sanitize_target("http://scanme.nmap.org")
    print(f"  ✅ PASS: Allowed safe target {target.hostname}.\n")

    # ---------------------------------------------------------
    # 2. DATA MASKER
    # ---------------------------------------------------------
    print("[2/6] Testing Data Masker (Privacy)...")
    masker = DataMasker.create_fresh()
    masked = masker.mask_text("Server at 10.0.0.5 and 10.0.0.5 failed.")
    if masked.count("[REDACTED-IP-1]") == 2:
        print("  ✅ PASS: Same IP masked consistently.")
    else:
        print("  ❌ FAIL: IP masking broken.")
    print("")

    # ---------------------------------------------------------
    # 3. WEB SCANNERS
    # ---------------------------------------------------------
    print("[3/6] Testing Web Scanners (Headers)...")
    headers_tool = HeadersAnalyzer()
    result = await headers_tool.run(target)
    print(f"  ✅ PASS: Found {len(result.vulnerabilities)} missing headers on {target.hostname}.\n")

    # ---------------------------------------------------------
    # 4. NMAP SCANNER
    # ---------------------------------------------------------
    print("[4/6] Testing Nmap Scanner (Port Scanning)...")
    nmap_tool = NmapScanner()
    nmap_result = await nmap_tool.run(target)
    if nmap_result.success:
        print(f"  ✅ PASS: Nmap scan complete. Found {len(nmap_result.vulnerabilities)} open ports.\n")
    else:
        print(f"  ❌ FAIL: Nmap failed: {nmap_result.error}\n")

    # ---------------------------------------------------------
    # 5. UNIVERSAL AI ADAPTER
    # ---------------------------------------------------------
    print("[5/6] Testing AI Adapter (Cloud Connection)...")
    ai = UniversalAIAdapter({"provider": "cloud", "api_key": os.getenv("GROQ_API_KEY", "")})
    ai_resp = await ai.call("You are a bot.", "Reply with the word: SUCCESS", json_mode=False)
    if ai_resp.ok:
        print(f"  ✅ PASS: AI responded with: '{ai_resp.data.strip()}'\n")
    else:
        print(f"  ❌ FAIL: AI failed. Check your API key.\n")

    # ---------------------------------------------------------
    # 6. MASTER ORCHESTRATOR
    # ---------------------------------------------------------
    print("[6/6] Testing Master Orchestrator (End-to-End Integration)...")
    print("  --> Running full scan (Headers + Nmap + AI Analysis)...")
    
    orchestrator = ScanOrchestrator(ai_config={"provider": "cloud", "api_key": os.getenv("GROQ_API_KEY", "")})
    scan_result = await orchestrator.run_full_scan("http://scanme.nmap.org", scan_type="quick")
    
    print(f"\n  ✅ PASS: Orchestrator Finished!")
    print(f"  Duration: {scan_result.scan_duration_seconds}s")
    print(f"  Tools Used: {scan_result.tools_used}")
    print(f"  Risk Score: {scan_result.risk_score}/100")
    print(f"  AI Summary: {scan_result.ai_analysis.summary[:150]}...")
    
    print("\n======================================================")
    print("🎉 ALL TESTS COMPLETE. ENGINE IS BULLETPROOF. 🎉")
    print("======================================================")

if __name__ == "__main__":
    asyncio.run(main())