# ⚙️ العضو 2: الدليل التنفيذي الكامل — مهندس النواة الخلفية وقواعد البيانات وحصص الباقات (Core Backend & DB Engineer)
# Member 2: Complete Execution Guide — Core Backend & Database Engineer

> **المسمى الوظيفي**: مهندس النواة الخلفية وقواعد البيانات وحصص الباقات (Core Backend & Database Engineer)  
> **النطاق الحصري المملوك**: `backend/orion/api/`, `backend/orion/models/`, `backend/orion/tasks/`, `backend/alembic/`  
> **فرع Git المخصص**: `feature/backend-core-db`  
> **تنبيه حاسم**: يُمنع منعاً باتاً تعديل مجلدات العضو 3 (`backend/orion/core/`, `backend/orion/ai/`, `backend/orion/services/`) أو مجلد `app/` أو ملفات `docker-compose*`!

---

## 🌍 البرومبت التأسيسي الموحد (The Foundation Prompt)
> **تعليمات الاستخدام**: انسخ هذا البرومبت بالكامل والصقه كأول رسالة ترسلها لأي نموذج ذكاء اصطناعي تستعين به في العمل. يشرح هذا البرومبت للذكاء الاصطناعي معمارية الباك إند بالكامل، ودورك الحصري، وعقود البيانات، وقواعد الربط مع زملائك في الفريق ليعطيك أكواد FastAPI متوافقة 100%.

```text
You are an AI assistant specialized in building backend APIs using Python and FastAPI.

## Project Overview:
Project Name: Orion Security Platform
Orion is a SaaS cybersecurity vulnerability scanning platform. There is a Frontend (React — NOT my responsibility) and I am responsible for building the complete Backend API.

## Full Architecture:
- Backend: Python 3.11+ + FastAPI (Async) + Uvicorn
- Database: PostgreSQL 15 via SQLAlchemy 2.0 ORM + Alembic migrations
- Authentication: JWT (python-jose) + bcrypt (passlib)
- Queue & Cache: Redis 7 + Celery 5 (Background Workers)
- Real-time: WebSocket via FastAPI
- AI: Universal AI Adapter (NOT my responsibility — built by Member 3, I just call it)
- Scanning Tools: Nmap, SQLMap, Custom scanners (NOT my responsibility — built by Member 3)

## My Responsibilities:
1. Design database tables (Users, Targets, Scans, Vulnerabilities, Plans) with SQLAlchemy
2. JWT authentication system (register + login + route protection)
3. Subscription quota enforcement (Free: 3 scans/day, Pro: unlimited, Enterprise: unlimited + domain scanning)
4. API routes for launching scans and retrieving results
5. Scan comparison route (Diff): compare two scans, classify vulnerabilities as new/resolved/persistent
6. Breach checker route (calls Member 3's service)
7. Knowledgebase API route
8. WebSocket channel for real-time scan progress broadcasting
9. Celery configuration for background task execution
10. Automatic Swagger documentation via FastAPI /docs

## Data Contracts (MUST match Frontend exactly):

class VulnerabilityItem(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    service: str
    port: int | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    description: str
    remediation_steps: list[str]

class ScanResult(BaseModel):
    id: str
    target_url: str
    status: Literal["running", "completed", "failed"]
    created_at: datetime
    completed_at: datetime | None = None
    vulnerabilities: list[VulnerabilityItem]
    risk_score: float

class ScanDiffResult(BaseModel):
    scan_a_id: str
    scan_b_id: str
    target_url: str
    resolved_vulnerabilities: list[VulnerabilityItem]
    new_vulnerabilities: list[VulnerabilityItem]
    persistent_vulnerabilities: list[VulnerabilityItem]
    security_score_improvement: float

class BreachResult(BaseModel):
    email: str
    breach_count: int
    breaches: list[dict]

## My Role:
I am Member 2 of 5. I own the API, database, and subscription logic. Member 3 builds the scanning tools and AI — I call his functions via import.

## What I need now:
Help me build the complete backend phase by phase: database models, authentication, API routes, WebSocket, and Celery integration.
```

---

## 📂 شجرة الملفات الكاملة والمملوكة حصرياً للعضو 2

```
backend/
├── alembic.ini                            # ملف إعدادات أداة ترحيل قواعد البيانات Alembic
├── alembic/
│   ├── env.py                             # بيئة تهيئة الاتصال بـ PostgreSQL وإجراء الترحيلات
│   └── versions/
│       ├── 0001_initial_core_schema.py    # ترحيل الجداول الأساسية (Users, Targets, Scans, Vulnerabilities)
│       └── 0002_add_plans_and_diff.py     # ترحيل جداول الاشتراكات ومقارنة الفحوصات
├── requirements.txt                       # حزم ومكتبات بايثون (تنسيق مشترك مع العضو 3)
└── orion/
    ├── __init__.py
    ├── api/
    │   ├── __init__.py
    │   ├── main.py                        # نقطة دخول تطبيق FastAPI + إعدادات CORS وتجميع المسارات
    │   ├── deps.py                        # التوابع والمحقونات: get_current_user, get_db, check_quota
    │   └── routes/
    │       ├── __init__.py
    │       ├── auth.py                    # مسارات تسجيل الدخول وإنشاء الحساب (POST /api/auth/*)
    │       ├── scans.py                   # مسارات إدارة الفحص وطلب النتائج (POST & GET /api/scans)
    │       ├── targets.py                 # إدارة عناوين وأهداف الفحص (POST & GET /api/targets)
    │       ├── plans.py                   # مسارات الاستعلام عن الحصة والترقية (GET & POST /api/plans)
    │       ├── diff.py                    # مسار مقارنة فحصين وإبراز الفروقات (GET /api/scans/compare)
    │       ├── breaches.py                # مسار فحص تسريبات البريد الإلكتروني (POST /api/threats/breach-check)
    │       ├── knowledgebase.py           # مسارات تصفح موسوعة الثغرات (GET /api/knowledgebase)
    │       └── websocket.py               # قناة البث اللحظي للتقدم (WS /api/ws/scans/{scan_id})
    ├── models/
    │   ├── __init__.py
    │   ├── database.py                    # إعداد محرك SQLAlchemy وجداول قاعدة البيانات العلائقية
    │   └── schemas.py                     # مخططات Pydantic v2 للتحقق الصارم من الطلبات والاستجابات
    └── tasks/
        ├── __init__.py
        ├── celery_app.py                  # تهيئة تطبيق Celery والاتصال بوسيط Redis
        └── scan_tasks.py                  # مهمة الفحص في الخلفية واستدعاء محركات العضو 3
```

---

## 🛠️ المكدس التقني الكامل (Complete Tech Stack)

| التقنية / الأداة | الإصدار | الغرض والاستخدام |
|:---|:---|:---|
| **Python** | `3.11+` | لغة البرمجة الأساسية للباك إند |
| **FastAPI** | أحدث إصدار | إطار بناء الـ REST APIs والـ WebSockets غير المتزامن (Async) |
| **Uvicorn** | أحدث إصدار | خادم ASGI الفائق السرعة لتشغيل التطبيق |
| **SQLAlchemy** | `2.0` | نمط الـ ORM الحديث لإدارة جداول وعلاقات قاعدة البيانات |
| **Alembic** | أحدث إصدار | إدارة وإجراء ترحيلات قاعدة البيانات (Database Migrations) |
| **PostgreSQL** | `15` | قاعدة البيانات العلائقية الأولية |
| **python-jose** | أحدث إصدار | توليد وتشفير والتحقق من توكنز JWT |
| **passlib + bcrypt** | أحدث إصدار | التشفير الآمن لكلمات المرور |
| **Redis** | `7` | وسيط الرسائل والتخزين المؤقت ونظام Pub/Sub |
| **Celery** | `5` | إدارة وتنفيذ مهام الفحص الطويلة في الخلفية |
| **Pydantic** | `v2` | التحقق من صحة مدخلات ومخرجات الـ API بدقة فائقة |

---

## 📋 خطة التنفيذ خطوة بخطوة مع برومبتات الذكاء الاصطناعي (AI Prompts)

---

### المرحلة 1: نماذج قاعدة البيانات ومخططات التحقق (Database Models & Schemas)
* **المدة الزمنية**: اليوم 1 إلى 2
* **الملفات المستهدفة**: `backend/orion/models/database.py`, `backend/orion/models/schemas.py`, `backend/alembic/versions/0001_*`
* **الهدف**: بناء جداول PostgreSQL عبر SQLAlchemy 2.0 (المستخدمون، الأهداف، الفحوصات، الثغرات، المقالات)، وإنشاء مخططات Pydantic v2 المطابقة بدقة لعقود البيانات المعتمدة.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
I am building the database layer for a cybersecurity scanning platform called "Orion" using SQLAlchemy 2.0 ORM with PostgreSQL.

Write models/database.py with:

1. Database setup: create_async_engine + async_sessionmaker + declarative Base

2. User table:
   - id: UUID primary key (default uuid4)
   - email: String(255), unique, not null
   - hashed_password: String(255), not null
   - plan: String(20), default "free" — allowed: "free", "pro", "enterprise"
   - scans_today: Integer, default 0
   - last_scan_reset: Date, default today (resets scans_today daily)
   - created_at: DateTime, default now

3. Target table:
   - id: UUID
   - user_id: ForeignKey → User
   - url: String(500), not null
   - created_at: DateTime

4. Scan table:
   - id: UUID
   - target_id: ForeignKey → Target
   - user_id: ForeignKey → User
   - status: String(20), default "pending" — values: "pending", "running", "completed", "failed"
   - scan_type: String(20) — values: "quick", "full", "web_only"
   - risk_score: Float, nullable
   - created_at: DateTime
   - completed_at: DateTime, nullable
   - raw_results: JSON, nullable
   - ai_analysis: JSON, nullable
   - attack_graph: JSON, nullable

5. Vulnerability table:
   - id: UUID
   - scan_id: ForeignKey → Scan
   - title: String(500)
   - severity: String(20) — "critical", "high", "medium", "low", "info"
   - service: String(100)
   - port: Integer, nullable
   - cve_id: String(50), nullable
   - cvss_score: Float, nullable
   - description: Text
   - remediation_steps: JSON (array of strings)

6. KnowledgebaseArticle table:
   - id: UUID, title, cwe_id, severity, description (Text), vulnerable_code (Text), remediation_code (Text), references (JSON)

Then write models/schemas.py with Pydantic v2 models:
- UserCreate, UserLogin, UserResponse, TokenResponse
- ScanCreate, ScanResponse, VulnerabilityResponse
- ScanDiffResult, BreachCheckRequest, BreachResult
- KBArticleResponse, QuotaResponse, PlanUpgradeRequest

CRITICAL: Field names in ScanResponse and VulnerabilityResponse MUST exactly match the data contracts shown in the foundation prompt.
```

---

### المرحلة 2: نظام المصادقة وحصص الاستخدام اليومية (Authentication & JWT Quotas)
* **المدة الزمنية**: اليوم 3
* **الملفات المستهدفة**: `backend/orion/api/routes/auth.py`, `backend/orion/api/deps.py`
* **الهدف**: تنفيذ نظام أمان كامل بتوكنز JWT وتشفير bcrypt، مع برمجة محقون التبعية الحاسم `check_daily_quota` الذي يقفل الفحص على مستخدمي الباقة المجانية بعد 3 فحوصات يومياً ويعيد خطأ HTTP 429.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build a JWT authentication system for Orion using FastAPI.

Write 2 files:

1. **api/deps.py** — Dependency functions:
   - get_db(): yields an AsyncSession
   - get_current_user(token = Depends(oauth2_scheme)): decodes JWT, returns User or raises 401
   - check_daily_quota(user = Depends(get_current_user), db = Depends(get_db)):
     * If plan == "free":
       - Check last_scan_reset: if yesterday or earlier, reset scans_today to 0 and update date
       - If scans_today >= 3: raise HTTPException(429, "Daily scan limit reached. Upgrade to Pro for unlimited scans.")
     * If plan == "pro" or "enterprise": pass through without checking

2. **api/routes/auth.py** — Auth routes:
   - POST /api/auth/register:
     * Accepts: email, password (UserCreate schema)
     * Checks no duplicate email exists
     * Hashes password with bcrypt
     * Creates user with "free" plan
     * Generates JWT token valid 24 hours
     * Returns: { access_token, token_type: "bearer", user: UserResponse }
   
   - POST /api/auth/login:
     * Validates email + password
     * Generates JWT token
     * Returns: { access_token, token_type: "bearer", user: UserResponse }

   - GET /api/auth/me:
     * Protected by get_current_user
     * Returns: UserResponse

Use python-jose[cryptography] for JWT with HS256.
Use passlib[bcrypt] for password hashing.
SECRET_KEY from os.getenv("SECRET_KEY", "dev-secret-key").
```

---

### المرحلة 3: مسارات إدارة الفحص ومهام Celery الخلفية (Scan Routes & Celery Tasks)
* **المدة الزمنية**: اليوم 4 إلى 5
* **الملفات المستهدفة**: `backend/orion/api/routes/scans.py`, `backend/orion/api/routes/targets.py`, `backend/orion/tasks/celery_app.py`, `backend/orion/tasks/scan_tasks.py`
* **الهدف**: استقبال طلبات الفحص وتخزينها، إرسال المعالجة الطويلة إلى Celery وRedis، واستدعاء محرك العضو 3 المنسق (`ScanOrchestrator`)، وتحديث النتائج في قاعدة البيانات ونشر حالة الاكتمال عبر Redis Pub/Sub.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build scan management API routes for Orion using FastAPI.

Write these files:

1. **api/routes/targets.py**:
   - POST /api/targets: Add new target URL linked to current user
   - GET /api/targets: Get all targets for current user
   - DELETE /api/targets/{id}: Delete target (only if owned by user)

2. **api/routes/scans.py**:
   - POST /api/scans:
     * Protected by get_current_user + check_daily_quota
     * Accepts: { target_url: str, scan_type: "quick"|"full"|"web_only" }
     * Creates Scan record with status "pending"
     * Increments scans_today for free plan users
     * Dispatches to Celery: run_scan_task.delay(scan_id)
     * Returns: { scan_id, status: "pending" }
   
   - GET /api/scans: Returns all scans for current user, ordered by newest
   - GET /api/scans/{scan_id}: Returns full scan details with vulnerabilities and attack_graph

3. **tasks/celery_app.py**:
   - Configure Celery with Redis as broker and backend
   - CELERY_BROKER_URL from environment variable

4. **tasks/scan_tasks.py**:
   - Celery task run_scan_task(scan_id):
     * Loads Scan from database
     * Sets status to "running"
     * Calls Member 3's orchestrator:
       from orion.core.orchestrator import ScanOrchestrator
       orchestrator = ScanOrchestrator(ai_config=user_ai_settings)
       results = await orchestrator.run_full_scan(target_url, scan_type, scan_id, redis_client)
     * Saves results to raw_results, ai_analysis, attack_graph fields
     * Creates Vulnerability records from results
     * Sets status to "completed" with completed_at timestamp
     * Publishes completion to Redis PubSub: channel = f"scan:{scan_id}"
     * On error: sets status to "failed"

NOTE: ScanOrchestrator.run_full_scan() is implemented by Member 3. Write a placeholder:
# TODO: Member 3 will implement the actual orchestrator
```

---

### المرحلة 4: مسارات الميزات المتقدمة (Diff, Breach, Knowledgebase & Plans)
* **المدة الزمنية**: اليوم 6 إلى 8
* **الملفات المستهدفة**: `backend/orion/api/routes/diff.py`, `backend/orion/api/routes/breaches.py`, `backend/orion/api/routes/knowledgebase.py`, `backend/orion/api/routes/plans.py`

#### 4.1 مسار مقارنة الفحوصات (Scan Diff API)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the Scan Comparison (Diff) API route for Orion using FastAPI.

File: api/routes/diff.py

GET /api/scans/compare?scan_a={id}&scan_b={id}:
- Protected by get_current_user
- Validates both scans belong to the current user and are "completed"
- Validates both scans target the same URL
- Loads vulnerabilities for Scan A and Scan B
- Compares using (title + port + service) as matching key:
  * resolved_vulnerabilities: present in A but missing in B (fixed ✅)
  * new_vulnerabilities: present in B but missing in A (new threat 🔴)
  * persistent_vulnerabilities: present in both (still open ⚠️)
- Calculates security_score_improvement:
  = ((len(resolved) - len(new)) / max(len(all_vulns_a), 1)) * 100

Response must match this structure EXACTLY:
{
  "scan_a_id": "...",
  "scan_b_id": "...",
  "target_url": "...",
  "resolved_vulnerabilities": [...VulnerabilityItem],
  "new_vulnerabilities": [...VulnerabilityItem],
  "persistent_vulnerabilities": [...VulnerabilityItem],
  "security_score_improvement": 30.0
}
```

#### 4.2 مسار فاحص التسريبات (Breach Checker API)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the Breach Checker API route for Orion using FastAPI.

File: api/routes/breaches.py

POST /api/threats/breach-check:
- Protected by get_current_user
- Checks breach lookup quota: Free = 1/day, Pro/Enterprise = unlimited
- Accepts: { email: str }
- Calls Member 3's service:
  from orion.services.breach_service import check_email_breach
  result = await check_email_breach(email)
- Returns: BreachResult

Placeholder for Member 3's function:
async def check_email_breach(email: str) -> dict:
    # TODO: Member 3 will implement HIBP integration
    return {"email": email, "breach_count": 0, "breaches": []}
```

#### 4.3 مسار موسوعة الثغرات (Knowledgebase API)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the Security Knowledgebase API route for Orion using FastAPI.

File: api/routes/knowledgebase.py

- GET /api/knowledgebase:
  * Optional query params: severity (filter), search (text search in title)
  * Returns: list[KBArticleResponse]
  * Public — no authentication required

- GET /api/knowledgebase/{article_id}:
  * Returns full article with remediation code
  * Free plan: returns description only (no remediation_code)
  * Pro/Enterprise: returns everything
```

#### 4.4 مسار حصص الباقات والترقية (Subscription Plans API)
**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the subscription plans API route for Orion using FastAPI.

File: api/routes/plans.py

- GET /api/plans/quota:
  * Protected
  * Returns: { plan, scans_today, daily_limit (3 for free, -1 for unlimited), scans_remaining }

- POST /api/plans/upgrade:
  * Protected
  * Accepts: { plan: "pro" | "enterprise" }
  * Updates user.plan field
  * Returns: { success: true, new_plan: "pro" }
  (MVP — no real payment processing, just direct upgrade)
```

---

### المرحلة 5: قناة التحديثات اللحظية عبر WebSocket (WebSocket Real-time Updates)
* **المدة الزمنية**: اليوم 9
* **الملفات المستهدفة**: `backend/orion/api/routes/websocket.py`
* **الهدف**: ربط الـ Frontend عبر WebSocket للاستماع إلى قناة Redis Pub/Sub الخاصة برقم الفحص وبث التقدم اللحظي واسم الأداة المنفذة مباشرة إلى المتصفح.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build a WebSocket endpoint for real-time scan progress in Orion using FastAPI.

File: api/routes/websocket.py

WS /api/ws/scans/{scan_id}:
- On client connect:
  1. Verify scan exists in database
  2. Subscribe to Redis PubSub channel: f"scan:{scan_id}"
  3. Listen for progress messages and forward to client

- Message format sent to frontend (JSON):
  { "type": "progress", "percentage": 45, "current_tool": "nmap", "message": "Scanning ports..." }
  { "type": "completed", "scan_id": "...", "message": "Scan completed successfully" }
  { "type": "error", "message": "Scan failed: timeout" }

- On disconnect: unsubscribe from Redis channel

NOTE: Member 3 publishes progress from the orchestrator:
redis_client.publish(f"scan:{scan_id}", json.dumps(progress_data))
```

---

### المرحلة 6: تجميع التطبيق وتوثيق Swagger التفاعلي (App Assembly & Swagger)
* **المدة الزمنية**: اليوم 10 إلى 11
* **الملفات المستهدفة**: `backend/orion/api/main.py`
* **الهدف**: تجميع كافة الموجهات (Routers) تحت تطبيق FastAPI واحد، وضبط سياسات CORS، وتجهيز توثيق Swagger التلقائي عبر المسار `/docs` لاختبارات العضو 5.

**🤖 البرومبت (Prompt بالإنجليزية - انسخه كما هو):**
```text
Build the main FastAPI application file for Orion Security Platform.

File: api/main.py

Requirements:
1. Create FastAPI app with title="Orion Security Platform API", version="1.0.0"
2. CORS middleware: origins=["http://localhost:5173", "http://localhost:80", "http://localhost:3000"]
3. Include all routers with correct prefixes and tags:
   - auth → /api/auth [Authentication]
   - scans → /api/scans [Scans]
   - targets → /api/targets [Targets]
   - plans → /api/plans [Plans & Subscriptions]
   - diff → /api/scans [Scan Comparison]
   - breaches → /api/threats [Breach Checker]
   - kb → /api/knowledgebase [Knowledgebase]
   - ws → /api/ws [WebSocket]
4. Startup event: initialize database tables
5. Shutdown event: close connections
6. Request timing middleware (log response time)
7. Health endpoint: GET /api/health → {"status": "ok", "version": "1.0.0"}
```

---

## 🛡️ القواعد الذهبية لمنع أي تعارض عند الدمج (Zero-Conflict Golden Rules)

1. **الالتزام المطلق بحدود الملفات**: لا تعدل نهائياً أي ملف مملوك للعضو 3 في مجلدات `core/`, `ai/`, `services/`؛ استخدم دواله عبر الاستيراد فقط (`import`).
2. **الاحترام التام لملفات البنية التحتية**: لا تعدل `docker-compose.yml` أو `nginx.conf`؛ هذه مسؤولية العضو 4 الحصرية.
3. **ممنوع لمس مجلد الفرونت إند**: لا تفتح أو تعدل أي ملف داخل `app/` فهو نطاق العضو 1.
4. **التطابق الدقيق مع عقود البيانات**: التزم بأسماء الحقول المحددة في Pydantic لتطابق واجهات TypeScript لدى العضو 1.
5. **العزل في الفروع البرمجية**: ارفع عملك على فرع `feature/backend-core-db` فقط.
6. **دوال العضو 3 غير الجاهزة**: ضع بدائل مؤقتة (Placeholders) مع تعليق `# TODO: Member 3 will implement` حتى لا يتعطل سير عملك.
7. **التوثيق التلقائي في Swagger**: تأكد من إضافة `summary` و `response_model` لكل مسار لتسهيل مهمة العضو 5 في اختبارات Postman.

---

## 🔗 نقاط الربط والتكامل مع باقي الفريق (Integration Points)

| دالة تستوردها في كودك | المطور المسؤول | الملف المصدر |
|:---|:---|:---|
| `ScanOrchestrator.run_full_scan()` | **العضو 3 (Security & AI)** | `backend/orion/core/orchestrator.py` |
| `check_email_breach()` | **العضو 3 (Security & AI)** | `backend/orion/services/breach_service.py` |
| `get_knowledgebase_articles()` | **العضو 3 (Security & AI)** | `backend/orion/services/kb_service.py` |
| رسائل تقدم الفحص اللحظية (PubSub) | **العضو 3 (Security & AI)** | تُنشر من `orchestrator.py` إلى Redis |

| مسار يستدعيه الفرونت إند (العضو 1) | الغرض من المسار | نوع الطلب |
|:---|:---|:---|
| `POST /api/auth/register` & `/login` | تسجيل الحساب وتسجيل الدخول وتوليد التوكن | REST |
| `POST /api/scans` | إطلاق فحص جديد والتحقق من الحصة اليومية | REST |
| `GET /api/scans/{id}` | جلب النتائج الكاملة للفحص مع سلاسل الهجوم | REST |
| `GET /api/scans/compare?scan_a=&scan_b=` | مقارنة فحصين وإرجاع الثغرات الجديدة والمحلولة | REST |
| `POST /api/threats/breach-check` | فحص تسريبات البريد الإلكتروني | REST |
| `GET /api/knowledgebase` | تصفح مقالات موسوعة الثغرات OWASP | REST |
| `GET /api/plans/quota` | الاستعلام عن استهلاك الحصة اليومية | REST |
| `WS /api/ws/scans/{scan_id}` | الاستماع المباشر لنسبة التقدم اللحظي للفحص | WebSocket |

---

*هذا الدليل هو مرجعك التنفيذي الأساسي — اتبعه مرحلة بمرحلة وستبني نواة خلفية قوية وموثوقة تتكامل بانسيابية تامة دون أي أخطاء دمج! 🚀*
