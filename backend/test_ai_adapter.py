import asyncio
from orion.ai.universal_ai_adapter import UniversalAIAdapter

def test_json_extraction():
    print("=== Testing JSON Extractor ===")
    ai = UniversalAIAdapter({"provider": "cloud", "api_key": "fake"})
    
    # Test 1: Raw JSON
    raw1 = '{"nodes": [], "edges": []}'
    assert ai._extract_json(raw1) == raw1
    
    # Test 2: Markdown wrapped JSON (Ollama does this often)
    raw2 = '```json\n{\n  "nodes": [],\n  "edges": []\n}\n```'
    expected = '{\n  "nodes": [],\n  "edges": []\n}'
    assert ai._extract_json(raw2) == expected
    
    # Test 3: Text surrounding JSON (Some models do this)
    raw3 = 'Here is your JSON:\n{\n  "status": "success"\n}\nHave a nice day!'
    expected3 = '{\n  "status": "success"\n}'
    assert ai._extract_json(raw3) == expected3
    
    print("[PASS] JSON Extractor handles raw, markdown, and text-wrapped JSON.\n")

async def test_error_handling():
    print("=== Testing API Error Handling (Fake Key) ===")
    # We use a fake OpenAI key. The API should return a 401 Unauthorized.
    config = {
        "provider": "custom",
        "api_key": "sk-fake_key_to_test_error_handling",
        "model": "gpt-4o",
        "base_url": "https://api.openai.com/v1"
    }
    ai = UniversalAIAdapter(config)
    result = await ai.test_connection()
    
    assert result.ok is False, "Fail: API accepted a fake key!"
    assert "401" in result.error or "Unauthorized" in result.error, f"Fail: Error message unclear: {result.error}"
    
    print(f"[PASS] Gracefully caught API error: {result.error[:80]}...")

if __name__ == "__main__":
    test_json_extraction()
    asyncio.run(test_error_handling())
    print("\nALL AI ADAPTER TESTS PASSED SUCCESSFULLY.")