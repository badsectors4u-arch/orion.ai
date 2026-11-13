"""
Orion Security Platform — Universal AI Adapter.

PURPOSE: Single interface for Cloud (Groq), BYOK (OpenAI/DeepSeek/Claude), 
and Local (Ollama). Utilizes the OpenAI /chat/completions standard.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import httpx
from orion.core.schemas import AIResponse

logger = logging.getLogger(__name__)


def _auto_load_dotenv():
    """Auto-loads .env if environment variables are not yet present."""
    if not os.getenv("AI_API_KEY") and not os.getenv("GROQ_API_KEY"):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            ".env", "../.env", "../../.env",
            os.path.join(base_dir, ".env"),
            os.path.join(base_dir, "..", ".env"),
            os.path.join(base_dir, "..", "..", ".env"),
        ]
        for env_path in candidates:
            if os.path.exists(env_path):
                try:
                    with open(env_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                k, v = line.split("=", 1)
                                if k.strip() not in os.environ:
                                    os.environ[k.strip()] = v.strip()
                except Exception:
                    pass
                if os.getenv("AI_API_KEY") or os.getenv("GROQ_API_KEY"):
                    break


_auto_load_dotenv()


class UniversalAIAdapter:
    def __init__(self, config: dict[str, Any]):
        _auto_load_dotenv()

        default_provider = os.getenv("AI_PROVIDER") or "cloud"
        self.provider = config.get("provider") or default_provider
        self.api_key = config.get("api_key", "")
        self.model = config.get("model", "")
        self.base_url = config.get("base_url", "")
        self.fallback_models = config.get("fallback_models") or [
            "deepseek/deepseek-v4.1-flash",
            "nvidia/nemotron-3-ultra-550b-a55b:free",
            "z-ai/glm-5.3-flash",
            "nvidia/nemotron-3.5-super-vl:free",
            "nvidia/nemotron-3.5-lightning:free",
        ]

        # Defaults based on provider
        if self.provider == "cloud":
            self.base_url = self.base_url or os.getenv("GROQ_BASE_URL") or "https://api.groq.com/openai/v1"
            self.api_key = self.api_key or os.getenv("GROQ_API_KEY", "")
            self.model = self.model or os.getenv("GROQ_MODEL") or "llama3-70b-8192"
        elif self.provider == "custom":
            self.base_url = self.base_url or os.getenv("AI_BASE_URL") or "https://api.openai.com/v1"
            self.api_key = self.api_key or os.getenv("AI_API_KEY", "") or os.getenv("OPENAI_API_KEY", "")
            self.model = self.model or os.getenv("AI_MODEL") or "deepseek/deepseek-v4.1-flash"
        elif self.provider == "local_ollama":
            self.base_url = self.base_url or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434/v1"
            self.api_key = "ollama"  # Ollama requires a key, but ignores its value
            self.model = self.model or "qwen2.5-coder:14b"
        else:
            raise ValueError(f"Unknown AI provider: {self.provider}")

        # Clean up base URL (remove trailing slash)
        self.base_url = self.base_url.rstrip("/")
        self.url = f"{self.base_url}/chat/completions"

    async def test_connection(self) -> AIResponse:
        """Sends a minimal test ping to verify credentials and endpoint availability."""
        return await self.call("You are an AI security assistant.", "Respond with pong.", json_mode=False)

    async def call(self, system_prompt: str, user_prompt: str, json_mode: bool = False) -> AIResponse:
        """Sends a prompt to the AI with automatic multi-model fallback chain. Never raises."""
        start_time = time.monotonic()

        # If no API key is provided and not local ollama, gracefully fail immediately
        if not self.api_key and self.provider != "local_ollama":
            return AIResponse(
                ok=False,
                error="AI API key not set; falling back to rule-based engine.",
                provider=self.provider,
                model=self.model,
            )

        # Model Fallback Chain: Primary model first, then fallbacks
        candidate_models = [self.model]
        for m in self.fallback_models:
            if m and m not in candidate_models:
                candidate_models.append(m)

        last_error = "Unknown error"
        for current_model in candidate_models:
            payload = {
                "model": current_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1
            }

            if json_mode:
                payload["response_format"] = {"type": "json_object"}

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://orion-security.local",
                "X-Title": "Orion Security Platform",
            }

            try:
                # 15-second timeout for cloud models
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(self.url, json=payload, headers=headers)
                    resp.raise_for_status()

                    data = resp.json()
                    msg = data["choices"][0]["message"]
                    content = msg.get("content") or msg.get("reasoning") or ""
                    if not content and "reasoning_details" in msg:
                        details = msg["reasoning_details"]
                        if isinstance(details, list) and details and isinstance(details[0], dict) and "text" in details[0]:
                            content = details[0]["text"]
                    latency = (time.monotonic() - start_time) * 1000

                    if json_mode:
                        cleaned_content = self._extract_json(content)
                        parsed_data = json.loads(cleaned_content)
                        return AIResponse(
                            ok=True, data=parsed_data, latency_ms=latency, 
                            provider=self.provider, model=current_model
                        )

                    return AIResponse(
                        ok=True, data=content, latency_ms=latency, 
                        provider=self.provider, model=current_model
                    )
            except Exception as e:
                last_error = str(e)
                logger.debug(f"AI call failed on model '{current_model}': {e}. Trying next candidate...")

        return AIResponse(
            ok=False, error=last_error, latency_ms=(time.monotonic() - start_time) * 1000,
            provider=self.provider, model=self.model
        )

    def _extract_json(self, text: str) -> str:
        """Helper to extract JSON from raw, markdown, or text-wrapped model outputs."""
        text = text.strip()
        # Markdown fence extraction
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end != -1:
                return text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end != -1:
                return text[start:end].strip()

        # Text-wrapped JSON: find first '{' or '[' and last '}' or ']'
        s_brace = text.find("{")
        s_bracket = text.find("[")
        e_brace = text.rfind("}")
        e_bracket = text.rfind("]")

        if s_brace != -1 and e_brace != -1 and (s_bracket == -1 or s_brace < s_bracket):
            return text[s_brace:e_brace + 1].strip()
        if s_bracket != -1 and e_bracket != -1:
            return text[s_bracket:e_bracket + 1].strip()

        return text
