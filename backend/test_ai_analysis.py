import asyncio
from orion.ai.universal_ai_adapter import UniversalAIAdapter
from orion.ai.attack_graph_generator import AttackGraphGenerator
from orion.ai.ghost_analyst import GhostAnalyst
from orion.core.schemas import VulnerabilityItem

async def test():
    print("=== Testing AI Analysis Layer (Fallback Mode) ===")
    
    # Fake AI config to force the fallback logic (since key is bad)
    config = {"provider": "custom", "api_key": "bad_key", "base_url": "https://api.openai.com/v1"}
    ai = UniversalAIAdapter(config)
    
    graph_gen = AttackGraphGenerator(ai)
    analyst = GhostAnalyst(ai)
    
    # Create fake vulnerabilities
    vulns = [
        VulnerabilityItem(title="SQL Injection in 'id'", severity="critical", service="http", port=80, description="...", remediation_steps=[]),
        VulnerabilityItem(title="Missing CSP", severity="high", service="http", port=80, description="...", remediation_steps=[])
    ]
    
    target = "http://example.com"
    
    print("\n--- Generating Attack Graph ---")
    graph = await graph_gen.generate(vulns, target)
    print(f"Nodes generated: {len(graph.nodes)}")
    for n in graph.nodes:
        print(f"  [{n.severity.upper()}] {n.label}")
        
    print("\n--- Generating Ghost Analyst Summary ---")
    analysis = await analyst.analyze(vulns, target)
    print(f"Risk Score: {analysis.risk_score}")
    print(f"Fallback Used: {analysis.fallback}")
    print(f"Summary: {analysis.summary}")

if __name__ == "__main__":
    asyncio.run(test())