import os
import asyncio
import logging

os.environ["PATH"] += r";C:\Program Files (x86)\Nmap"
logging.getLogger("orion").setLevel(logging.ERROR)

from orion.core.orchestrator import ScanOrchestrator

async def main():
    print("======================================================")
    print("🚀 ORION: REAL TARGET FULL PENETRATION TEST 🚀")
    print("======================================================\n")

    # Using IBM's stable vulnerable banking site
    target_url = "http://demo.testfire.net/search.jsp?query=test"
    
    config = {"provider": "cloud", "api_key": os.getenv("GROQ_API_KEY", "")}
    orchestrator = ScanOrchestrator(ai_config=config)

    print(f"Target: {target_url}")
    print("Scanning... (SQLMap will take 1-2 minutes)\n")

    result = await orchestrator.run_full_scan(target_url, scan_type="full")

    print("\n======================================================")
    print("✅ SCAN COMPLETE")
    print("======================================================")
    print(f"Duration:      {result.scan_duration_seconds} seconds")
    print(f"Tools Used:    {result.tools_used}")
    print(f"Risk Score:    {result.risk_score}/100")
    print(f"Total Vulns:   {len(result.vulnerabilities)}\n")

    print("--- AI EXECUTIVE SUMMARY ---")
    print(result.ai_analysis.summary)
    print("\n")

    print("--- CRITICAL & HIGH VULNERABILITIES ---")
    for v in result.vulnerabilities:
        if v.severity in ["critical", "high"]:
            print(f"[{v.severity.upper()}] {v.title}")
            print(f"   -> {v.description[:150]}...\n")

if __name__ == "__main__":
    asyncio.run(main())