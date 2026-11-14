"""
Orion Security Platform — Live Multi-Phase Security Scanner Runner.

Executes the full 5-phase scanning pipeline against a live target URL or the
built-in local benchmark vulnerable server.
Saves the complete structured results to `scan_results_report.json`.

Usage:
    python run_live_test.py                        # Runs against local benchmark target
    python run_live_test.py https://example.com    # Runs against custom URL
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from mock_vulnerable_target import TargetServer
from orion.core.orchestrator import ScanOrchestrator


class MockRedisPubSub:
    """Simulates Redis WebSocket publisher in the terminal."""
    async def publish(self, channel: str, message: str):
        try:
            data = json.loads(message)
            pct = data.get("percentage", 0)
            tool = data.get("current_tool") or "pipeline"
            msg = data.get("message", "")
            print(f"  [{pct:>3}%] [{tool:<14}] {msg}")
        except Exception:
            pass


async def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else None
    local_server = None

    if not target_url:
        print("=" * 70)
        print("🚀 Starting Orion Local Benchmark Vulnerable Target on http://127.0.0.1:8888 ...")
        local_server = TargetServer(port=8888)
        local_server.start()
        target_url = "http://127.0.0.1:8888/"
        time.sleep(0.5)

    redis_mock = MockRedisPubSub()
    orchestrator = ScanOrchestrator()

    ai_desc = f"Active Neural Engine: {orchestrator.ai_adapter.model} (Provider: {orchestrator.ai_adapter.provider})" if orchestrator.ai_adapter.api_key else "Rule-based & Mathematical Heuristics"

    print("=" * 70)
    print(f"🎯 Target URL: {target_url}")
    print("🛡️  Pipeline: 5-Phase Multi-Tool Intelligent Security Scan")
    print(f"🧠 AI Mode: {ai_desc}")
    print("=" * 70)

    start_ts = time.time()
    try:
        result = await orchestrator.run_full_scan(
            target_url=target_url,
            scan_type="full",
            scan_id="test-run-001",
            redis_client=redis_mock,
            allow_private=True,
            plan="advanced",
            ai_hunter_duration=300,
        )
    finally:
        if local_server:
            local_server.stop()

    elapsed = time.time() - start_ts

    # Export complete results to JSON file
    output_filename = "scan_results_report.json"
    result_dict = result.model_dump()

    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=2, ensure_ascii=False)

    # Print Executive Summary Table
    print("\n" + "=" * 70)
    print("📊 SCAN COMPLETED SUCCESSFULLY — EXECUTIVE DASHBOARD")
    print("=" * 70)
    print(f"⏱️  Duration:           {elapsed:.2f} seconds")
    print(f"🛠️  Tools Executed:      {', '.join(result.tools_used)}")
    print(f"🚨 Total Findings:      {len(result.vulnerabilities)} vulnerabilities identified")
    print(f"📈 Risk Score:          {result.risk_score:.1f} / 100.0")

    # Severity Breakdown
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in result.vulnerabilities:
        severities[v.severity] = severities.get(v.severity, 0) + 1

    print("\n[Severity Breakdown]")
    for sev, count in severities.items():
        badge = "🔴" if sev in ["critical", "high"] else ("🟡" if sev == "medium" else "🔵")
        print(f"  {badge} {sev.upper():<10}: {count}")

    # Attack Chains Breakdown
    if result.attack_chains:
        print(f"\n[🔗 Attack Chains Synthesized ({len(result.attack_chains)})]")
        for i, chain in enumerate(result.attack_chains, 1):
            print(f"  {i}. {chain.chain_name} [{chain.combined_severity.upper()}]")
            print(f"     Narrative: {chain.narrative[:120]}...")

    # Recon & Discovery Highlights
    if result.recon:
        print("\n[📡 Reconnaissance Highlights]")
        print(f"  Server:        {result.recon.tech_fingerprint.server}")
        print(f"  CMS:           {result.recon.cms_info.cms_name} {result.recon.cms_info.cms_version or ''}")
        print(f"  Technologies:  {', '.join(result.recon.tech_fingerprint.technologies)}")

    if result.discovery:
        print("\n[🔍 Discovery Highlights]")
        print(f"  Crawled URLs:  {len(result.discovery.crawled_urls)} pages")
        print(f"  HTML Forms:    {len(result.discovery.forms)} forms")
        print(f"  JS Endpoints:  {len(result.discovery.js_endpoints)} endpoints")
        print(f"  Leaked Secrets:{len(result.discovery.leaked_secrets)} secrets detected")

    print(f"\n💾 Full JSON Report exported to: {os.path.abspath(output_filename)}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())

