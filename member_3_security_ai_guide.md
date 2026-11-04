# 🛡️ العضو 3: الدليل التنفيذي الكامل — مهندس الفحص الأمني ومحول الذكاء الاصطناعي الهجين (Security Scanning & AI Engineer)
# Member 3: Complete Execution Guide — Security Scanning & AI Engineer

> **المسمى الوظيفي**: مهندس محركات الفحص الأمني ومحول الذكاء الاصطناعي الهجين (Security Scanning & AI Engineer)  
> **النطاق الحصري المملوك**: `backend/orion/core/`, `backend/orion/ai/`, `backend/orion/services/`  
> **فرع Git المخصص**: `feature/security-ai-tools`  
> **تنبيه حاسم**: يُمنع منعاً باتاً تعديل مسارات ونماذج العضو 2 (`backend/orion/api/`, `backend/orion/models/`) أو مجلد `app/` أو ملفات `docker-compose*`!

---

## 🌍 البرومبت التأسيسي الموحد (The Foundation Prompt)
> **تعليمات الاستخدام**: انسخ هذا البرومبت بالكامل والصقه كأول رسالة ترسلها لأي نموذج ذكاء اصطناعي تستعين به في العمل. يشرح هذا البرومبت للذكاء الاصطناعي معمارية أدوات الفحص، ومحول الـ AI الثلاثي (سحابي / مفتاح مخصص / محلي أوفلاين عبر Ollama)، وعقود البيانات ومسؤولياتك بدقة.

```text
You are an AI assistant specialized in cybersecurity tool development and AI integration using Python.

## Project Overview:
Project Name: Orion Security Platform
Orion is a SaaS vulnerability scanning platform. I am responsible for building the scanning engines, AI adapter, threat services, and PDF report generator.

## Full Architecture:
- Backend: Python 3.11+ + FastAPI (Member 2 manages API routes — I write the services he calls)
- Database: PostgreSQL (Member 2 manages)
- Queue: Redis + Celery (Member 2 manages)
- AI Engine: Universal adapter supporting 3 providers:
  1. Cloud: Groq LLaMA 3.3 70B / Google Gemini Flash
  2. Custom API Key (BYOK): OpenAI / DeepSeek / Claude
  3. Local Ollama: http://localhost:11434/v1 (100% Offline)
- Scanning Tools: Nmap, SQLMap, Custom Python HTTP scanners

## My Responsibilities:
1. Tool wrappers: Nmap Scanner, SQLMap Scanner, HTTP Header/XSS/SSL Scanners
2. Orchestrator: manages sequential tool execution and result aggregation
3. Universal AI Adapter: single interface for Cloud/Custom/Local Ollama
4. Attack Graph Generator: AI prompt to extract React Flow nodes/edges
5. Ghost Analyst: AI-powered executive summary and risk scoring
6. Data Masker: redact IPs before sending to AI
7. Breach Service: HaveIBeenPwned API integration
8. Knowledgebase Seed Data: OWASP Top 10 structured data
9. PDF Report Generator: professional colored report via ReportLab

## Output Contracts (Member 1 and Member 2 depend on these EXACT structures):

# Each vulnerability
vulnerability_dict = {
    "id": str, "title": str,
    "severity": "critical"|"high"|"medium"|"low"|"info",
    "service": str, "port": int|None,
    "cve_id": str|None, "cvss_score": float|None,
    "description": str, "remediation_steps": list[str]
}

# Attack graph (consumed by Member 1's React Flow)
attack_graph_payload = {
    "nodes": [{"id": str, "type": "target"|"service"|"vulnerability"|"root", "label": str, "severity": str}],
    "edges": [{"id": str, "source": str, "target": str, "label": str, "animated": bool}]
}

# Breach check result
breach_result = {"email": str, "breach_count": int, "breaches": [{"name": str, "date": str, "data_classes": list[str]}]}

## My Role:
I am Member 3 of 5. I write services and tools that Member 2 calls from API routes. Member 1 displays my output in the UI.

## What I need now:
Help me build all scanning tools, the AI adapter, and services phase by phase.
```

---

## 📂 شجرة الملفات الكاملة والمملوكة حصرياً للعضو 3

```
backend/orion/
├── core/
│   ├── __init__.py
│   ├── orchestrator.py                    # المنسق الرئيسي للفحص وإدارة تسلسل الأدوات وبث التقدم
│   ├── input_sanitizer.py                 # التحقق الصارم من الأهداف ومنع فحص النطاقات المحمية
│   └── tools/
│       ├── __init__.py
│       ├── base_tool.py                   # الفئة المجردة الموحدة لكافة الأدوات (ToolInterface)
│       ├── nmap_scanner.py                # مغلف فحص المنافذ والخدمات عبر Nmap
│       ├── sqlmap_scanner.py              # مغلف الكشف عن ثغرات حقن قواعد البيانات SQLMap
│       └── web_scanners.py                # محركات فحص الويب المخصصة (Headers, XSS, SSL)
├── ai/
│   ├── __init__.py
│   ├── universal_ai_adapter.py            # المحول الشامل للذكاء الاصطناعي (Groq, OpenAI, Ollama)
│   ├── attack_graph_generator.py          # هندسة برومبتات استخراج مسارات الهجوم لـ React Flow
│   ├── ghost_analyst.py                   # محلل الذكاء الاصطناعي للملخص التنفيذي ومصفوفة المخاطر
│   └── data_masker.py                     # قناع حجب وتعمية العناوين والبيانات الحساسة قبل إرسالها للـ AI
└── services/
    ├── __init__.py
    ├── breach_service.py                  # خدمة التحقق من تسريبات البريد الإلكتروني عبر HaveIBeenPwned
    ├── kb_service.py                      # البيانات المعرفية التأسيسية لثغرات OWASP Top 10
    └── pdf_generator.py                   # محرك توليد التقارير التنفيذية بصيغة PDF عبر ReportLab
```

---

## 🛠️ المكدس التقني الكامل (Complete Tech Stack)

| التقنية / المكتبة | الإصدار | الغرض والاستخدام |
|:---|:---|:---|
| **Python** | `3.11+` | لغة البرمجة الأساسية لكافة الخدمات والمحركات |
| **asyncio.subprocess** | مدمج في بايثون | تشغيل أدوات الأمان الخارجية (Nmap و SQLMap) بشكل آمن وغير متزامن |
| **httpx** | أحدث إصدار | عميل HTTP غير متزامن للاتصال بنماذج AI وواجهات HIBP |
| **aiohttp + bs4** | أحدث إصدار | تنفيذ فحوصات الويب المخصصة وتحليل استجابات صفحات HTML |
| **python-nmap** | أحدث إصدار | التعامل مع مخرجات وبيانات Nmap XML |
| **Groq SDK** | أحدث إصدار | الاتصال بنموذج LLaMA 3.3 70B السحابي فائق السرعة |
| **Ollama API** | عبر HTTP محلي | تشغيل الذكاء الاصطناعي بدون إنترنت محلياً بنسبة 100% |
| **ReportLab** | `4.1` | توليد وطباعة التقارير الأمنية بصيغة PDF بألوان وتنسيقات احترافية |
| **redis** | أحدث إصدار | بث نسب تقدم الفحص ورسائل الأدوات الحالية عبر قنوات Pub/Sub |

---

## 📋 خطة التنفيذ خطوة بخطوة مع برومبتات الذكاء الاصطناعي (AI Prompts)

---

### المرحلة 1: أساس الأدوات ومحركات الفحص الأمني (Tool Foundation & Scanners)
* **المدة الزمنية**: اليوم 1 إلى 3
* **الملفات المستهدفة**: `backend/orion/core/tools/*`, `backend/orion/core/input_sanitizer.py`
* **الهدف**: بناء الفئة المجردة `ToolInterface` ومصفي المدخلات الأمنية، وتطوير مغلفات Nmap و SQLMap والمحركات المخصصة لفحص ترويسات الأمان (Security Headers) وثغرات XSS وشهادات SSL مع ضمان عدم استخدام `shell=True` لأسباب أمنية.

#### 1.1 الواجهة التأسيسية ومغلف Nmap
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
I am building a security scanning tool system for the Orion platform in Python.

Write these files:

1. **core/tools/base_tool.py**: Abstract base class:
   class ToolInterface(ABC):
       name: str
       async def run(self, target: str, options: dict) -> dict
       async def parse_output(self, raw_output: str) -> list[dict]

2. **core/input_sanitizer.py**: Input validation functions:
   - sanitize_target(target: str) -> str: validates URL or IP format, rejects invalid input
   - is_private_ip(ip: str) -> bool: rejects internal IPs (127.x, 10.x, 192.168.x)
   - validate_scan_scope(target: str) -> bool: ensures target isn't a protected site

3. **core/tools/nmap_scanner.py**: Nmap wrapper:
   class NmapScanner(ToolInterface):
       name = "nmap"
       async def run(self, target, options):
           - Build safe Nmap command: nmap -sV -sC --top-ports 1000 -oX - {target}
           - Execute with asyncio.create_subprocess_exec (NOT shell=True — security!)
           - Set timeout: 120 seconds
           - Parse XML output
           - Return list of vulnerability dicts for each open port/service discovered
       
       Each result MUST match VulnerabilityItem structure:
       { id, title, severity, service, port, cve_id, cvss_score, description, remediation_steps }

SECURITY: Never use shell=True. Always use subprocess with argument lists.
```

#### 1.2 مغلف SQLMap وفواحص الويب المخصصة
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Continue building scanning tools for Orion.

Write these files:

1. **core/tools/sqlmap_scanner.py**: SQLMap wrapper:
   class SqlmapScanner(ToolInterface):
       name = "sqlmap"
       - Runs SQLMap in safe batch mode: sqlmap -u {target} --batch --level=2 --risk=1 --forms
       - Parses results, extracts discovered injection points
       - Each finding: severity="critical", service="http", title="SQL Injection in {parameter}"

2. **core/tools/web_scanners.py**: Custom HTTP scanners (no external tools needed):

   a) class HeadersAnalyzer(ToolInterface):
      name = "headers"
      - Sends GET request to target using httpx
      - Checks for missing security headers:
        Strict-Transport-Security, Content-Security-Policy, X-Frame-Options,
        X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
      - Each missing header = vulnerability with severity "medium" or "low"

   b) class XSSScanner(ToolInterface):
      name = "xss"
      - Tests for reflected XSS with payloads: <script>alert(1)</script>, <img onerror=alert(1)>
      - Checks if payload appears in response body
      - Each match = vulnerability with severity "high"

   c) class SSLChecker(ToolInterface):
      name = "ssl"
      - Checks SSL certificate: expiration, self-signed, domain mismatch
      - Each issue = vulnerability with severity "high" or "medium"

All tools return list[dict] matching VulnerabilityItem structure.
```

---

### المرحلة 2: محول الذكاء الاصطناعي الشامل وقناع تعمية البيانات (Universal AI Adapter & Masker)
* **المدة الزمنية**: اليوم 4 إلى 5
* **الملفات المستهدفة**: `backend/orion/ai/universal_ai_adapter.py`, `backend/orion/ai/data_masker.py`
* **الهدف**: بناء محول موحد يتعامل مع واجهات OpenAI المتوافقة عبر 3 أوضاع: السحابي عبر Groq LLaMA 3.3، والمخصص (BYOK)، والمحلي دون إنترنت بنسبة 100% عبر Ollama على الجهاز المضيف، مع بناء قناع تعمية لعناوين الـ IP الحساسة لحماية الخصوصية.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build a Universal AI Adapter for Orion that supports 3 AI providers with a SINGLE interface.

Write 2 files:

1. **ai/data_masker.py**: Data redaction before AI calls:
   - mask_ip_addresses(text: str) -> str: replaces real IPs with [REDACTED-IP-1], [REDACTED-IP-2]
   - mask_sensitive_data(scan_results: dict) -> dict: redacts IPs, emails, internal paths
   - Maintains a mapping dictionary to restore original data after analysis

2. **ai/universal_ai_adapter.py**: Universal AI client:

   class UniversalAIAdapter:
       def __init__(self, config: dict):
           # config = {"provider": "cloud"|"custom"|"local_ollama", "custom_api_key": ..., ...}
       
       async def call(self, system_prompt: str, user_prompt: str) -> dict:
           # THE KEY INSIGHT: Groq, OpenAI, and Ollama ALL support the same OpenAI chat/completions format!
           
           if provider == "cloud":
               base_url = "https://api.groq.com/openai/v1"
               api_key = os.getenv("GROQ_API_KEY")
               model = "llama-3.3-70b-versatile"
           elif provider == "custom":
               base_url = config.get("custom_base_url", "https://api.openai.com/v1")
               api_key = config["custom_api_key"]
               model = config.get("model_name", "gpt-4o-mini")
           elif provider == "local_ollama":
               base_url = config.get("custom_base_url", "http://host.docker.internal:11434/v1")
               api_key = "ollama"  # Ollama doesn't need a real key
               model = config.get("model_name", "llama3:latest")
           
           # Unified API call using httpx:
           POST {base_url}/chat/completions
           Headers: Authorization: Bearer {api_key}
           Body: { model, messages: [{role: "system", ...}, {role: "user", ...}], response_format: {type: "json_object"}, temperature: 0.1 }
       
       async def test_connection(self) -> dict:
           # Send simple test message, return {"success": True, "latency_ms": 234, "model": "llama3"}
   
   Error handling:
   - Connection failure: return None with clear error message
   - Timeout: 120 seconds (local models can be slow)
   - Fallback: if AI fails, return None and orchestrator uses rule-based analysis
```

---

### المرحلة 3: التحليل الذكي وتوليد سلاسل الهجوم (Attack Graph & Ghost Analyst)
* **المدة الزمنية**: اليوم 6 إلى 7
* **الملفات المستهدفة**: `backend/orion/ai/attack_graph_generator.py`, `backend/orion/ai/ghost_analyst.py`
* **الهدف**: هندسة برومبتات استخراج العقد والروابط لمخطط React Flow البصري، وبرمجة المحلل الذكي (Ghost Analyst) لتوليد الملخص التنفيذي ومصفوفة الأولويات وحساب درجة الخطورة (Risk Score).

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the AI analysis layer for Orion.

Write 2 files:

1. **ai/attack_graph_generator.py**: Generates attack chain graph from scan results:

   class AttackGraphGenerator:
       def __init__(self, ai_adapter: UniversalAIAdapter):
           pass
       
       async def generate(self, vulnerabilities: list[dict], target_url: str) -> dict:
           # Sends vulnerabilities to AI with this system prompt:
           """
           You are a SOC Analyst. Given discovered vulnerabilities, generate an attack chain graph.
           Return ONLY valid JSON with this EXACT structure:
           {
             "nodes": [
               {"id": "node-1", "type": "target", "label": "example.com", "severity": "info"},
               {"id": "node-2", "type": "service", "label": "HTTP :80", "severity": "low"},
               {"id": "node-3", "type": "vulnerability", "label": "SQL Injection (CVE-xxx)", "severity": "critical"},
               {"id": "node-4", "type": "root", "label": "Full System Compromise", "severity": "critical"}
             ],
             "edges": [
               {"id": "edge-1-2", "source": "node-1", "target": "node-2", "label": "Exposes", "animated": true},
               {"id": "edge-2-3", "source": "node-2", "target": "node-3", "label": "Exploits via", "animated": true}
             ]
           }
           Rules: types MUST be target/service/vulnerability/root. severity MUST be critical/high/medium/low/info.
           Return ONLY JSON, no markdown, no explanation.
           """
           
           # Fallback: if AI fails, generate a simple rule-based graph from vulnerabilities directly

2. **ai/ghost_analyst.py**: Executive summary and risk scoring:

   class GhostAnalyst:
       async def analyze(self, scan_results: dict, target_url: str) -> dict:
           # Asks AI for:
           # - Executive summary (3-5 sentences)
           # - Risk score (0-100)
           # - Top 3 urgent recommendations
           # - Priority matrix
           # Returns: {"summary": str, "risk_score": float, "top_recommendations": list[str], "priority_matrix": dict}

CRITICAL: Node/edge field names MUST match what Member 1 expects in React Flow (AttackGraphPayload interface).
```

---

### المرحلة 4: المنسق الشامل وبث نسب التقدم (Master Scan Orchestrator)
* **المدة الزمنية**: اليوم 8 إلى 9
* **الملفات المستهدفة**: `backend/orion/core/orchestrator.py`
* **الهدف**: بناء المنسق المركزي الذي يستدعيه العضو 2 داخل مهام Celery لتنفيذ تسلسل الفحص خطوة بخطوة، ونشر التقدم اللحظي واسم الأداة الحالية عبر Redis Pub/Sub للـ WebSocket، وتجميع النتائج في كائن موحد.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the master scan orchestrator for Orion that coordinates all tools and AI analysis.

File: core/orchestrator.py

class ScanOrchestrator:
    def __init__(self, ai_config: dict = None):
        # Initialize all tools: NmapScanner, SqlmapScanner, HeadersAnalyzer, XSSScanner, SSLChecker
        # Initialize AI: UniversalAIAdapter, AttackGraphGenerator, GhostAnalyst

    async def run_full_scan(self, target_url: str, scan_type: str, scan_id: str = None, redis_client = None) -> dict:
        """
        This is the MAIN FUNCTION that Member 2 calls from scan_tasks.py.
        
        Execution sequence with Redis progress publishing:
        1. Validate target (input_sanitizer) — 0%
        2. Mask sensitive data (data_masker)
        3. Run tools sequentially, publishing progress via Redis:
           - Nmap (0→25%): publish {"type":"progress", "percentage":25, "current_tool":"nmap", "message":"Scanning ports..."}
           - Headers (25→40%): publish {"percentage":40, "current_tool":"headers"}
           - SSL (40→50%): publish {"percentage":50, "current_tool":"ssl"}
           - XSS (50→65%): publish {"percentage":65, "current_tool":"xss"}
           - SQLMap (65→80%): only if scan_type == "full"
        4. Aggregate all vulnerabilities into single list
        5. AI Analysis (80→95%):
           - Attack graph generation
           - Ghost analyst summary
        6. Final assembly (95→100%)
        
        Redis publishing (if redis_client and scan_id are provided):
        await redis_client.publish(f"scan:{scan_id}", json.dumps(progress_msg))
        
        Returns:
        {
            "vulnerabilities": list[dict],      # All vulns matching VulnerabilityItem format
            "attack_graph": dict,               # {"nodes": [...], "edges": [...]}
            "ai_analysis": dict,                # {"summary": ..., "risk_score": ..., ...}
            "risk_score": float,                # 0-100
            "tools_used": list[str],            # ["nmap", "headers", "ssl", "xss", "sqlmap"]
            "scan_duration_seconds": float
        }
        
        Error handling:
        - If one tool fails: continue with remaining tools, log the error
        - If AI fails: use rule-based fallback analysis and generate simple graph
        """

Member 2 calls this as:
from orion.core.orchestrator import ScanOrchestrator
orchestrator = ScanOrchestrator(ai_config=user_ai_settings)
results = await orchestrator.run_full_scan(target_url, scan_type, scan_id, redis_client)
```

---

### المرحلة 5: الخدمات المتقدمة (فاحص التسريبات والموسوعة والتقارير PDF)
* **المدة الزمنية**: اليوم 10 إلى 12
* **الملفات المستهدفة**: `backend/orion/services/breach_service.py`, `backend/orion/services/kb_service.py`, `backend/orion/services/pdf_generator.py`

#### 5.1 خدمة فحص تسريبات البريد (Breach Service)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the email breach checking service for Orion using HaveIBeenPwned API.

File: services/breach_service.py

async def check_email_breach(email: str) -> dict:
    """
    Queries HaveIBeenPwned API v3 for email breaches.
    
    1. GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}
       Headers: hibp-api-key = os.getenv("HIBP_API_KEY"), user-agent = "Orion-Security-Platform"
    2. If 404: no breaches → return {"email": email, "breach_count": 0, "breaches": []}
    3. If 200: parse response, extract per breach: name, date (BreachDate), data_classes (DataClasses)
    4. Handle rate limiting (429): wait Retry-After seconds, retry once
    
    Returns: {"email": "test@example.com", "breach_count": 3, "breaches": [{name, date, data_classes}, ...]}
    
    Fallback: if HIBP_API_KEY is missing, return error message explaining key is required.
    """

Member 2 calls this: from orion.services.breach_service import check_email_breach
```

#### 5.2 بذور بيانات موسوعة الثغرات (Knowledgebase Seed Data)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the OWASP Top 10 knowledgebase seed data for Orion.

File: services/kb_service.py

Create function: get_knowledgebase_articles() -> list[dict]
Returns 10 articles for the most critical web vulnerabilities:

For each article provide:
1. id: unique UUID
2. title: vulnerability name (e.g., "SQL Injection (SQLi)")
3. cwe_id: CWE identifier (e.g., "CWE-89")
4. severity: "critical", "high", or "medium"
5. description: detailed explanation (5-10 sentences) of what the vulnerability is and how attackers exploit it
6. vulnerable_code: REAL working vulnerable code example (Python, PHP, or JavaScript)
7. remediation_code: the SAME code fixed with security best practices, with inline comments explaining changes
8. references: real URLs from OWASP, MITRE, NVD

The 10 vulnerabilities:
1. SQL Injection (CWE-89) — critical
2. Cross-Site Scripting XSS (CWE-79) — high
3. Broken Access Control (CWE-284) — critical
4. Security Misconfiguration (CWE-16) — medium
5. Server-Side Request Forgery SSRF (CWE-918) — high
6. Insecure Direct Object Reference IDOR (CWE-639) — high
7. Cross-Site Request Forgery CSRF (CWE-352) — medium
8. Insecure Deserialization (CWE-502) — critical
9. Using Components with Known Vulnerabilities (CWE-1104) — high
10. Insufficient Logging & Monitoring (CWE-778) — medium

Also create: seed_knowledgebase(db_session) to insert these into the KnowledgebaseArticle table.
```

#### 5.3 محرك توليد التقارير التنفيذية بصيغة PDF (PDF Report Generator)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build a professional PDF report generator for Orion using ReportLab.

File: services/pdf_generator.py

async def generate_pdf_report(scan_result: dict, target_url: str) -> bytes:
    """
    Generates a professional executive security report as PDF.
    
    Report structure:
    
    Page 1 — Cover:
    - "Orion Security Platform" logo text
    - Target URL
    - Date and time
    - Risk Score in a large colored circle (green <30, amber 30-70, red >70)
    
    Page 2 — Executive Summary:
    - AI-generated summary text
    - Stats: vulnerability count per severity level
    - Top 3 urgent recommendations
    
    Page 3+ — Vulnerability Table:
    - Sorted by severity (Critical first)
    - Columns: #, Title, Severity (colored), Service, Port, CVSS
    - Row colors based on severity
    
    Page 4+ — Vulnerability Details:
    - Each vulnerability: title, description, remediation steps, CVE ID
    
    Final Page — Diff Summary (if available):
    - Resolved/New/Persistent counts
    - Improvement percentage
    
    Color scheme:
    - Background: #1a1a2e (dark blue)
    - Headers: #e84057 (red accent)
    - Critical: #e84057, High: #f97316, Medium: #f59e0b, Low: #3b82f6
    
    Returns: bytes (PDF file content ready for download)
    """
```

---

### المرحلة 6: اختبار وحدات الخدمات والمحركات (Services Unit Testing)
* **المدة الزمنية**: اليوم 13 إلى 14
* **الملفات المستهدفة**: `backend/test_services.py`
* **الهدف**: كتابة اختبارات غير متزامنة عبر pytest للتحقق من سلامة تحليل مخرجات الأدوات وتطابقها مع كائنات الثغرات المعتمدة قبل تسليمها للعضو 2 والعضو 5.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Write a quick test file for Orion's scanning services.

File: backend/test_services.py using pytest + pytest-asyncio + unittest.mock:

1. NmapScanner: test XML output parsing, verify output format matches VulnerabilityItem
2. HeadersAnalyzer: test detection of missing headers
3. UniversalAIAdapter: test correct request building for each provider (cloud, custom, local)
4. AttackGraphGenerator: test fallback when AI fails
5. check_email_breach: test 404 (no breaches) and 200 (breaches found) responses
6. get_knowledgebase_articles: verify all 10 articles have required fields
7. generate_pdf_report: verify non-empty bytes output
```

---

## 🛡️ القواعد الذهبية لمنع أي تعارض عند الدمج (Zero-Conflict Golden Rules)

1. **الالتزام المطلق بحدود الملفات**: لا تلمس نهائياً أي ملف يخص العضو 2 داخل `api/routes/` أو `models/` أو `tasks/`.
2. **التنسيق في ملف الحزم `requirements.txt`**: نسّق مع العضو 2 قبل تعديل الملف، وضع مكتباتك في قسم واضح بالأسفل.
3. **التطابق الصارم في أسماء الحقول ومخرجات الأدوات**: يعتمد كل من العضو 1 (الواجهة) والعضو 2 (قاعدة البيانات) على أسماء الحقول في قواميس الثغرات، وأي خطأ إملائي سيعطل التطبيق بالكامل.
4. **توقيع الدوال (Function Signatures) ثابت ومقدس**: حافظ بدقة على معايير استدعاء الدوال المشتركة:
   - `ScanOrchestrator.run_full_scan(target_url, scan_type, scan_id, redis_client) -> dict`
   - `check_email_breach(email) -> dict`
   - `get_knowledgebase_articles() -> list[dict]`
5. **العزل في الفروع البرمجية**: ارفع عملك على فرع `feature/security-ai-tools` فقط.
6. **تنسيق رسائل الـ Pub/Sub اللحظية**: التزم بصيغة JSON المتفق عليها لتصل شاشات الفرونت إند عبر الـ WebSocket بشكل سليم.

---

## 🔗 نقاط الربط والتكامل مع باقي الفريق (Integration Points)

| دالة توفرها للعضو 2 (Backend) | ملفها في مشروعك | طريقة الاستدعاء |
|:---|:---|:---|
| المنسق الشامل للفحص | `backend/orion/core/orchestrator.py` | `ScanOrchestrator.run_full_scan()` |
| فاحص تسريبات البريد | `backend/orion/services/breach_service.py` | `check_email_breach(email)` |
| مقالات موسوعة الثغرات | `backend/orion/services/kb_service.py` | `get_knowledgebase_articles()` |
| توليد وطباعة تقرير الـ PDF | `backend/orion/services/pdf_generator.py` | `generate_pdf_report(scan_result)` |

| مخرجاتك البرمجية | يستهلكها | صيغة البيانات المعتمدة |
|:---|:---|:---|
| قائمة الثغرات المكتشفة | العضو 1 (الواجهة) + العضو 2 (قاعدة البيانات) | `list[VulnerabilityItem]` |
| مخطط سلاسل الهجوم | العضو 1 (مكتبة React Flow) | `AttackGraphPayload` (عقد وروابط) |
| رسائل تقدم الفحص اللحظية | العضو 1 (عبر الـ WebSocket) | Redis PubSub JSON |

---

*هذا الدليل هو مرجعك التنفيذي الأساسي — اتبعه مرحلة بمرحلة وستبني أذكى وأقوى محرك فحص أمني مدعوم بالذكاء الاصطناعي دون أي تعارض برمجي! 🚀*
