"""
Orion Security Platform — Ghost Analyst & AI Security Copilot (Chatbot Engine).

PURPOSE:
- Powers the interactive AI Security Chatbot (/api/ai/chat) and UI Copilot widget.
- Answers vulnerability questions, explains exploit chains, and provides code remediations.
- Grounded in real-time scan context (vulnerabilities, open ports, tech stack).
- Fully bilingual (matches user prompt language: Arabic or English).
- Powered by UniversalAIAdapter with automatic multi-model fallback (DeepSeek -> Nemotron -> GLM).
- Deterministic offline security fallback when network/API is unavailable.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from orion.ai.universal_ai_adapter import UniversalAIAdapter

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Pydantic Response Schema
# ──────────────────────────────────────────────────────────────

class AnalystResponse(BaseModel):
    """Structured reply matching ChatResponse in ai_router."""
    answer: str = Field(..., description="Main technical answer in user's language")
    key_points: List[str] = Field(default_factory=list, description="Key bullet takeaways")
    severity: Optional[str] = Field(None, description="Critical, High, Medium, Low, or None")
    suggestions: List[str] = Field(default_factory=list, description="Follow-up prompts or actions")
    references: List[str] = Field(default_factory=list, description="CVE IDs, CWE, or OWASP references")


# ──────────────────────────────────────────────────────────────
# System Prompt
# ──────────────────────────────────────────────────────────────

_CHAT_SYSTEM_PROMPT = """You are Orion Ghost — an elite bilingual AI Cybersecurity Copilot and Senior Penetration Tester embedded in the Orion Security Platform.

### CRITICAL INSTRUCTIONS:
1. LANGUAGE MATCHING:
   - If the user speaks or writes in Arabic, answer FULLY in professional Arabic (باللغة العربية السليمة).
   - If the user writes in English, answer in English.
2. ROLE & TONE:
   - Calm, authoritative, technical, and constructive.
   - Provide concrete remediation code, patch instructions, and defense-in-depth advice.
3. CONTEXT INTEGRATION:
   - When scan findings are provided in the context, refer to them directly (vulnerability titles, ports, severities).
4. MANDATORY JSON FORMAT:
   Return ONLY a valid JSON object matching this schema:
   {
     "answer": "<detailed technical answer and remediation guidance>",
     "key_points": ["<bullet point 1>", "<bullet point 2>"],
     "severity": "critical"|"high"|"medium"|"low"|"info"|null,
     "suggestions": ["<follow-up suggestion 1>", "<follow-up suggestion 2>"],
     "references": ["OWASP A03:2021", "CWE-89", "CVE-202X-XXXX"]
   }
   Do NOT output markdown fences outside the JSON. Return raw JSON.
""".strip()


# ──────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────

def _mask_text_safely(sanitizer: Any, text: str) -> str:
    """Safely masks text with whatever sanitizer object is passed."""
    if not text or not sanitizer:
        return text
    if hasattr(sanitizer, "mask"):
        return sanitizer.mask(text)
    if hasattr(sanitizer, "mask_text"):
        return sanitizer.mask_text(text)
    return text


def _unmask_safely(sanitizer: Any, val: Any) -> Any:
    """Safely reverses masking on text, lists, or dicts."""
    if not sanitizer:
        return val
    unmask_func = getattr(sanitizer, "reverse_mask", getattr(sanitizer, "unmask_text", None))
    if not unmask_func:
        return val

    if isinstance(val, str):
        return unmask_func(val)
    elif isinstance(val, list):
        return [unmask_func(item) if isinstance(item, str) else item for item in val]
    return val


def _build_context_prompt(scan_context: Dict[str, Any], sanitizer: Any) -> str:
    """Formats scan findings into a concise security briefing context."""
    if not scan_context:
        return "No scan context provided."
    raw = json.dumps(scan_context, indent=2, default=str)
    return _mask_text_safely(sanitizer, raw)


def _build_history_prompt(history: List[Dict[str, str]], sanitizer: Any) -> str:
    """Serializes previous conversation turns (last 6 turns)."""
    if not history:
        return ""
    lines = ["### Recent Conversation History:"]
    for turn in history[-6:]:
        role = turn.get("role", "user")
        content = _mask_text_safely(sanitizer, turn.get("content", ""))
        lines.append(f"{role.capitalize()}: {content}")
    return "\n".join(lines)


def _offline_fallback(user_message: str, scan_context: Dict[str, Any]) -> AnalystResponse:
    """
    Intelligent deterministic fallback when external AI models are unreachable.
    Prevents 502 Bad Gateway and supplies structured security intelligence.
    """
    msg_lower = user_message.lower()
    is_arabic = any("\u0600" <= c <= "\u06FF" for c in user_message)

    # Context analysis
    vulns = scan_context.get("vulnerabilities", [])
    target = scan_context.get("target", "Target")

    if is_arabic:
        if "sql" in msg_lower or "حقن" in msg_lower:
            return AnalystResponse(
                answer=(
                    f"ثغرة حقن أوامر قواعد البيانات (SQL Injection) تعد من أخطر الثغرات الأمنية (Critical). "
                    f"تسمح للمهاجم بتجاوز آليات المصادقة وقراءة أو تعديل البيانات الحساسة من قاعدة البيانات. "
                    f"لإصلاح هذه الثغرة بشكل جذري، يجب الاعتماد حصرياً على الاستعلامات المجهزة (Parameterized Prepared Statements) "
                    f"واستخدام مكتبات ORM وتجنب دمج مدخلات المستخدم مباشرة داخل جمل الاستعلام."
                ),
                key_points=[
                    "استخدام Prepared Statements / Parameterized Queries لمنع حقن الأوامر.",
                    "تطبيق مبدأ أقل الصلاحيات (Least Privilege) على حساب قاعدة البيانات.",
                    "تفعيل جدار حماية تطبيقات الويب (WAF) لرصد أنماط الهجوم.",
                ],
                severity="critical",
                suggestions=[
                    "كيف أطبق الاستعلامات المجهزة في كود الباك إند؟",
                    "ما هي التوصيات لتأمين قاعدة بيانات الموقع المفحوص؟",
                ],
                references=["OWASP Top 10 - A03:2021 Injection", "CWE-89: SQL Injection"],
            )
        elif "xss" in msg_lower or "سكريبت" in msg_lower:
            return AnalystResponse(
                answer=(
                    f"ثغرة Cross-Site Scripting (XSS) تتيح للمهاجم تنفيذ كود JavaScript خبيث داخل متصفح المستخدم الضحية، "
                    f"مما يمكنه من سرقة ملفات الارتباط (Session Cookies) أو إعادة توجيهه لصفحات تصيد احتيالي. "
                    f"الحل الأمني يتمثل في تشفير المخرجات حسب السياق (Context-aware Output Encoding) وتفعيل ترويسة CSP."
                ),
                key_points=[
                    "تطبيق Context-aware HTML/JS Output Encoding لجميع المدخلات المعروضة.",
                    "تفعيل ترويسة Content-Security-Policy (CSP) الصارمة لمنع تنفيذ سكريبتات غير موثوقة.",
                    "تعيين علامة HttpOnly لملفات تعريف الارتباط الحساسة لمنع سرقتها عبر JS.",
                ],
                severity="high",
                suggestions=[
                    "كيف أكتب ترويسة Content-Security-Policy آمنة؟",
                    "ما الفرق بين Stored XSS و Reflected XSS؟",
                ],
                references=["OWASP Top 10 - A03:2021", "CWE-79: Cross-Site Scripting"],
            )
        else:
            vuln_count = len(vulns)
            return AnalystResponse(
                answer=(
                    f"أهلاً بك، أنا مساعد Orion Ghost الأمني. "
                    f"بالنظر إلى سياق الهدف ({target})، تم رصد {vuln_count} ثغرة أمنية في الفحص الحالي. "
                    f"يمكنني مساعدتك في تحليل أي ثغرة محددة، أو شرح سيناريوهات الاستغلال الممكنة، أو توفير كود المعالجة الدقيق."
                ),
                key_points=[
                    f"عدد الثغرات المرصودة في الجلسة الحالية: {vuln_count}",
                    "يُنصح بالبدء بمعالجة الثغرات ذات التصنيف الحرجة والعالية أولاً.",
                ],
                severity="medium" if vuln_count > 0 else "info",
                suggestions=[
                    "ما هي أخطر ثغرة تم اكتشافها في الفحص؟",
                    "كيف أقوم بإصلاح الثغرات المكتشفة في الموقع؟",
                ],
                references=["OWASP Top 10 Security Guidelines", "NIST SP 800-115"],
            )
    else:
        # English fallback
        if "sql" in msg_lower:
            return AnalystResponse(
                answer=(
                    "SQL Injection (SQLi) is a critical vulnerability that occurs when untrusted user input is directly "
                    "concatenated into dynamic database queries. Attackers can bypass authentication, exfiltrate sensitive data, "
                    "or execute administrative operations. Remediation requires parameterized prepared statements and ORMs."
                ),
                key_points=[
                    "Use parameterized prepared statements exclusively.",
                    "Enforce the principle of least privilege on database credentials.",
                    "Deploy Web Application Firewall (WAF) inspection rules.",
                ],
                severity="critical",
                suggestions=[
                    "Show me secure parameterized query code examples.",
                    "How can I test for blind SQL injection?",
                ],
                references=["OWASP A03:2021 Injection", "CWE-89"],
            )
        else:
            return AnalystResponse(
                answer=(
                    f"Hello! I am Orion Ghost Security Analyst. "
                    f"Regarding target {target}, there are {len(vulns)} vulnerability findings in the current scan session. "
                    f"Feel free to ask for remediation code, attack chain analysis, or security hardening recommendations."
                ),
                key_points=[
                    f"Active findings for this session: {len(vulns)}",
                    "Prioritize Critical and High severity findings first.",
                ],
                severity="medium" if len(vulns) > 0 else "info",
                suggestions=[
                    "What are the highest risk vulnerabilities found?",
                    "How do I harden our HTTP security headers?",
                ],
                references=["OWASP Top 10:2021", "CIS Benchmarks"],
            )


# ──────────────────────────────────────────────────────────────
# Main Chat Function (Interface for ai_router.py)
# ──────────────────────────────────────────────────────────────

# Global single-instance adapter cache
_global_adapter: Optional[UniversalAIAdapter] = None

def get_ai_adapter() -> UniversalAIAdapter:
    global _global_adapter
    if _global_adapter is None:
        _global_adapter = UniversalAIAdapter({})
    return _global_adapter


async def chat(
    user_message: str,
    scan_context: Dict[str, Any],
    sanitizer: Any = None,
    history: Optional[List[Dict[str, str]]] = None,
    ai_adapter: Optional[UniversalAIAdapter] = None,
) -> AnalystResponse:
    """
    Primary endpoint for the Orion Security Copilot / Chatbot.
    Called directly by `POST /api/ai/chat` in ai_router.py.
    """
    adapter = ai_adapter or get_ai_adapter()

    # Build prompt components
    ctx_str = _build_context_prompt(scan_context, sanitizer)
    hist_str = _build_history_prompt(history or [], sanitizer)
    masked_message = _mask_text_safely(sanitizer, user_message)

    user_prompt = (
        f"### Scan Context:\n{ctx_str}\n\n"
        f"{hist_str}\n\n"
        f"### User Message:\n{masked_message}"
    )

    try:
        response = await adapter.call(_CHAT_SYSTEM_PROMPT, user_prompt, json_mode=True)
        if response.ok and isinstance(response.data, dict):
            d = response.data
            answer_text = str(d.get("answer", ""))
            key_points = d.get("key_points", [])
            suggestions = d.get("suggestions", [])
            references = d.get("references", [])
            severity = d.get("severity")

            # Restore de-masked values
            answer_unmasked = _unmask_safely(sanitizer, answer_text)
            kp_unmasked = _unmask_safely(sanitizer, key_points)
            sugg_unmasked = _unmask_safely(sanitizer, suggestions)

            return AnalystResponse(
                answer=answer_unmasked,
                key_points=kp_unmasked if isinstance(kp_unmasked, list) else [],
                severity=severity,
                suggestions=sugg_unmasked if isinstance(sugg_unmasked, list) else [],
                references=references if isinstance(references, list) else [],
            )
        else:
            logger.warning("AI model returned non-JSON or failure: %s, using fallback.", response.error)
    except Exception as exc:
        logger.error("Chatbot AI execution error: %s, initiating fallback.", exc)

    # Intelligent fallback
    return _offline_fallback(user_message, scan_context)


# ──────────────────────────────────────────────────────────────
# Per-Scan Sanitizer Registry (Required by ai_router)
# ──────────────────────────────────────────────────────────────

_sanitizers: Dict[str, Any] = {}

def get_sanitizer(scan_id: str) -> Any:
    """Gets or initializes a DataMasker/Sanitizer for the given scan session."""
    if scan_id not in _sanitizers:
        try:
            from orion.ai.data_masker import DataMasker
            _sanitizers[scan_id] = DataMasker.create_fresh()
        except ImportError:
            _sanitizers[scan_id] = None
    return _sanitizers[scan_id]


def clear_sanitizer(scan_id: str) -> None:
    """Cleans up session sanitizer to prevent memory leaks."""
    _sanitizers.pop(scan_id, None)

