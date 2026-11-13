import asyncio
from orion.ai.universal_ai_adapter import UniversalAIAdapter

async def test():
    print("=== Testing REAL Groq AI Connection ===")
    
    # ⚠️ PASTE YOUR REAL KEY HERE:
    config = {
    "provider": "cloud",
    "api_key": os.getenv("GROQ_API_KEY", ""),
    "model": "openai/gpt-oss-120b"
}
    
    ai = UniversalAIAdapter(config)
    
    print("Sending prompt to Llama 3.3 70B...")
    
    system = "You are an expert cybersecurity analyst."
    user = "Explain what an SQL Injection is in exactly 2 sentences."
    
    result = await ai.call(system, user, json_mode=False)
    
    if result.ok:
        print("\n[SUCCESS] AI Responded!")
        print(f"Model: {result.model}")
        print(f"Latency: {result.latency_ms:.0f} ms")
        print(f"\nResponse:\n{result.data}")
    else:
        print(f"\n[FAILED] {result.error}")

if __name__ == "__main__":
    asyncio.run(test())