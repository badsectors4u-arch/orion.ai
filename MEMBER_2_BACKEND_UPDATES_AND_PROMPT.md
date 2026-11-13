# ⚙️ دليل العضو 2 (Core Backend, Celery & DB): التحديثات الجديدة والبرومبت التنفيذي
# Member 2 Execution Guide: Backend Pipeline Wiring & AI Settings Integration

> **الموجه إلى**: العضو رقم 2 (Core Backend & DB Engineer)  
> **النطاق الحصري**: مجلد `backend/orion/api/`, `backend/orion/models/`, `backend/orion/tasks/`  
> **حالة الباك إند**: تم بناء واختبار كافة أدوات الفحص والمحول الشامل للذكاء الاصطناعي (Member 3) وجاهزة للاستدعاء عبر Celery و FastAPI.

---

## 📌 1. ملخص التحديثات الجديدة التي أنجزها العضو 3 وتؤثر على الباك إند

1. **تحديث توقيع دالة الفحص المركزية (`run_full_scan`)**:
   - الدالة الرئيسية في [`orchestrator.py`](file:///D:/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/backend/orion/core/orchestrator.py) تقبل الآن باراميترات الخطط المتقدمة وزمن الـ AI:
     ```python
     result = await orchestrator.run_full_scan(
         target_url=target_url,
         scan_type=scan_type,            # "quick" | "standard" | "full"
         scan_id=scan_id,                # UUID
         redis_client=redis_client,      # لإرسال إشعارات التقدم للـ WebSocket
         allow_private=False,
         plan=user_plan,                 # "free" | "advanced" | "pro" | "enterprise"
         ai_hunter_duration=ai_duration, # 300 (5 دقائق) أو 600 (10 دقائق)
     )
     ```
2. **محول الـ AI يدعم اختيار المستخدم (BYOK / Cloud / Local Ollama)**:
   - أصبح بالإمكان تهيئة الـ Orchestrator بإعدادات الـ AI الخاصة بالمستخدم إذا كان لديه مفتاح API مخصص أو يريد استخدام Ollama المحلي بدون إنترنت:
     ```python
     orchestrator = ScanOrchestrator(ai_config={
         "provider": user.ai_provider,      # "custom" | "cloud" | "local_ollama"
         "api_key": user.ai_api_key,        # اختياري في حال الـ custom
         "base_url": user.ai_base_url,      # اختياري (مثل https://openrouter.ai/api/v1 أو http://localhost:11434/v1)
         "model": user.ai_model,            # مثل deepseek/deepseek-v4.1-flash أو qwen2.5-coder:14b
     })
     ```
3. **تحديث محرك الشات بوت (`/api/ai/chat`)**:
   - تم التخلص بالكامل من مكتبة Google GenAI القديمة التي كانت تطلب `GEMINI_API_KEY` إجبارياً وتسبب أخطاء.
   - أصبح ملف [`analyst.py`](file:///D:/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/backend/orion/ai/analyst.py) يعتمد على `UniversalAIAdapter` ونفس مفاتيح OpenRouter وموديل DeepSeek V4.1 Flash مع دعم الـ Fallback التلقائي لنماذج NVIDIA و GLM ونظام حماية أوفلاين ضد أخطاء 502 Bad Gateway.

---

## 💻 2. المطلوب برمجياً من العضو 2

1. في **مهمة Celery الفاحصة (`backend/orion/tasks/scan_tasks.py`)**:
   - تمرير الـ `plan` الخاص بالمستخدم (أو "advanced" كقيمة افتراضية).
   - تمرير `ai_hunter_duration` من جدول الـ Scan أو تعيينها 300 ثانية افتراضياً.
   - تمرير إعدادات الـ AI الخاصة بالمستخدم (إن وجدت في قاعدة البيانات) إلى `ScanOrchestrator(ai_config=...)`.
2. في **مسار الشات بوت (`backend/orion/api/routes/ai_router.py`)**:
   - التأكد من أن دالة `POST /api/ai/chat` تستدعي `from orion.ai.analyst import chat, get_sanitizer` وتمرر الـ `scan_context` والـ `history` بصورة طبيعية.
3. في **قاعدة البيانات (`backend/orion/models/database.py`)**:
   - التأكد من أن حقل `cvss_score` في جدول `Vulnerability` هو من نوع `Float` يقبل القيم العشرية.

---

## 🤖 3. البرومبت التنفيذي الموجه للعضو 2 (انسخه بالكامل والصقه في الـ AI)

```text
You are an expert Senior Backend Engineer working on the Orion Security Platform using FastAPI, SQLAlchemy, PostgreSQL, and Celery.

The Security & AI Engineer (Member 3) has updated the core scanning orchestrator and AI adapter. You need to wire the new parameters into Celery tasks, database persistence, and API routes.

### Required Changes:

1. Update `backend/orion/tasks/scan_tasks.py`:
   - In `execute_scan_task(scan_id: str)`:
     - Fetch the scan record and the owner user from the DB.
     - Determine the user's subscription plan: `user_plan = getattr(user, 'plan', 'advanced')`.
     - Extract `ai_hunter_duration` from scan options (default: 300 seconds).
     - Extract user custom AI settings if present:
       ```python
       ai_config = {}
       if getattr(user, 'ai_provider', None):
           ai_config = {
               "provider": user.ai_provider,
               "api_key": getattr(user, 'ai_api_key', None),
               "base_url": getattr(user, 'ai_base_url', None),
               "model": getattr(user, 'ai_model', None),
           }
       ```
     - Instantiate the orchestrator: `orchestrator = ScanOrchestrator(ai_config=ai_config)`
     - Call `run_full_scan` with the updated arguments:
       ```python
       scan_result = await orchestrator.run_full_scan(
           target_url=scan.target_url,
           scan_type=scan.profile.value if hasattr(scan.profile, 'value') else scan.profile,
           scan_id=str(scan.id),
           redis_client=redis_client,
           allow_private=False,
           plan=user_plan,
           ai_hunter_duration=ai_hunter_duration,
       )
       ```
     - Ensure the persistence loop stores `v.cvss_score` (float), `v.cve_id` (string), and `v.description` (the new rich markdown format) into the `Vulnerability` table.

2. Verify `backend/orion/api/routes/ai_router.py`:
   - In `POST /api/ai/chat`:
     - Keep using `from orion.ai.analyst import chat, get_sanitizer`.
     - Notice that Member 3 has upgraded `analyst.py` to use `UniversalAIAdapter` so no Gemini SDK errors will occur.
     - Ensure `_build_scan_context` provides the target, vulnerabilities list, and ports to the `chat` function so the AI answers with full situational awareness.

3. Verify `backend/orion/models/database.py`:
   - Confirm `Vulnerability.cvss_score = Column(Float, nullable=True)` and `cve_id = Column(String(64), nullable=True)`.
   - In `Scan`, ensure `ai_hunter_duration = Column(Integer, default=300)` is supported or stored in `scan.options` JSON.

Ensure all database transactions commit properly, Celery task state transitions (PENDING -> RUNNING -> COMPLETED/FAILED) remain clean, and WebSocket progress messages stream via Redis without disconnection.
```

