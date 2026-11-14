import asyncio
from orion.core.orchestrator import ScanOrchestrator

async def test():
    print("=== Testing Master Orchestrator ===")
    
    # Put your real Groq key here!
    config = {"provider": "cloud", "api_key": os.getenv("GROQ_API_KEY", "")}
    
    # Create the Orchestrator
    orchestrator = ScanOrchestrator(ai_config=config)
    
    # We will scan scanme.nmap.org on "quick" mode (skips SQLMap to save time)
    target_url = "http://scanme.nmap.org"
    
    print(f"Starting Orchestrated Scan on {target_url}...")
    result = await orchestrator.run_full_scan(target_url, scan_type="quick")
    
    print("\n=== SCAN COMPLETE ===")
    print(f"Duration: {result.scan_duration_seconds}s")
    print(f"Tools Used: {result.tools_used}")
    print(f"Total Vulnerabilities Found: {len(result.vulnerabilities)}")
    print(f"Risk Score: {result.risk_score}")
    
    print("\n--- AI Executive Summary ---")
    print(result.ai_analysis.summary)
    
    print("\n--- Attack Graph Nodes ---")
    for node in result.attack_graph.nodes:
        print(f"  [{node.severity.upper()}] {node.label}")

if __name__ == "__main__":
    asyncio.run(test())