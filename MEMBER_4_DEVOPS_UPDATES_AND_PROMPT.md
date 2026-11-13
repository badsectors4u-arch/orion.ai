# 🐳 دليل العضو 4 (DevOps, Docker & Tools): التحديثات الجديدة والبرومبت التنفيذي
# Member 4 Execution Guide: Docker Environment, Tool Toolchain & Ollama Integration

> **الموجه إلى**: العضو رقم 4 (DevOps & Desktop Integrator)  
> **النطاق الحصري**: ملفات `Dockerfile*`, `docker-compose*`, `nginx.conf`, وسكربتات تثبيت أدوات الأمان  
> **حالة المشروع**: كود فحص الأمان ومحول الذكاء الاصطناعي (Member 3) جاهز ومتكامل مع الـ 19 أداة أمنية في بايثون، والآن نحتاج بيئة Docker Linux لتشغيل الـ CLI Tools ونموذج Ollama بكامل كفاءتهم.

---

## 📌 1. ملخص التحديثات الجديدة التي أنجزها العضو 3 وتؤثر على الـ DevOps

1. **الاعتماد على حزمة الأدوات الـ 19 الرسمية**:
   - قام العضو 3 ببناء مغلفات متكاملة في الباك إند تستدعي الأدوات التنفيذية مباشرة:
     - **أدوات Go**: `katana`, `nuclei`, `dalfox`, `ffuf`, `subfinder`, `gau`
     - **أدوات النظام**: `nmap`, `whatweb`
     - **أدوات Python CLI**: `sqlmap`, `arjun`, `corsy`, `jwt_tool`, `linkfinder`, `secretfinder`
   - على بيئة ويندوز بدون هذه الأدوات، يعتمد الباك إند على محركات بايثون بديلة (Fallback)، لكن ليعمل السيستم بقوته الحقيقية القصوى، يجب أن تُثبت هذه الأدوات في حاوية الـ Docker لينكس الرسمية.
2. **دعم تشغيل Ollama المحلي بدون إنترنت 100%**:
   - أضاف العضو 3 خيار `provider: "local_ollama"` في [`UniversalAIAdapter`](file:///D:/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/DEPI%20VULNERABILITY%20AND%20PENETEST%20TOOL%20(SECURITY%20SEC)/backend/orion/ai/universal_ai_adapter.py).
   - لكي تستطيع حاوية الباك إند / Celery الاتصال بـ Ollama المشغل على جهاز المضيف (Host Machine)، يجب تفعيل `host.docker.internal` في شبكة Docker Compose.
3. **متغيرات البيئة الجديدة للذكاء الاصطناعي**:
   - المنصة تدعم الآن إعدادات الـ AI الموحدة التالية في ملف `.env`:
     ```env
     AI_PROVIDER=custom
     AI_BASE_URL=https://openrouter.ai/api/v1
     AI_API_KEY=sk-or-v1-...
     AI_MODEL=deepseek/deepseek-v4.1-flash
     OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
     ```

---

## 💻 2. المطلوب برمجياً من العضو 4

1. في **ملف الـ Dockerfile المتقدم (`backend/Dockerfile.advanced` أو `backend/Dockerfile`)**:
   - تثبيت حزم Go والأدوات التنفيذية عبر السكربتات المخصصة (`go install github.com/projectdiscovery/katana/cmd/katana@latest`, `nuclei`, إلخ).
   - تثبيت `nmap` و `sqlmap` و `whatweb` عبر مدير الحزم `apt-get`.
2. في **ملفات الـ Docker Compose (`docker-compose.yml`)**:
   - إضافة إعداد `extra_hosts` لحاوية الباك إند و Celery:
     ```yaml
     extra_hosts:
       - "host.docker.internal:host-gateway"
     ```
     هذا يسمح للباك إند بالاتصال بـ Ollama المشغل على جهاز المستخدم خارج الدوكر على بورت `11434`.
3. في **ملف البيئة `.env` و `.env.example`**:
   - توفير قيم افتراضية نظيفة للمتغيرات الجديدة للتأكد من عدم انهيار أي حاوية عند الإقلاع.

---

## 🤖 3. البرومبت التنفيذي الموجه للعضو 4 (انسخه بالكامل والصقه في الـ AI)

```text
You are an expert Senior DevOps & Security Infrastructure Engineer working on the Orion Security Platform using Docker, Docker Compose, Linux, and Nginx.

The Security AI Engineer (Member 3) has completed the 19-tool scanning orchestrator and multi-provider AI engine (supporting Cloud, OpenRouter/DeepSeek, and Local 100% Offline Ollama).

You need to update the Docker configuration so all CLI scanning tools are compiled and ready inside the Celery worker container, and ensure the backend container can reach local Ollama on the host machine.

### Required Changes:

1. Update `backend/Dockerfile` (or `backend/Dockerfile.advanced`):
   - In the base image (e.g. `python:3.11-slim` or multi-stage build with Go):
     - Install required system packages: `apt-get update && apt-get install -y nmap whatweb git curl wget ca-certificates gcc g++ make libpcap-dev`
     - Install Go toolchain (or use multi-stage `golang:1.22-alpine` builder) and compile:
       - `katana`: `go install github.com/projectdiscovery/katana/cmd/katana@latest`
       - `nuclei`: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
       - `subfinder`: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
       - `dalfox`: `go install github.com/hahwul/dalfox/v2@latest`
       - `ffuf`: `go install github.com/ffuf/ffuf/v2@latest`
       - `gau`: `go install github.com/lc/gau/v2/cmd/gau@latest`
     - Copy all compiled Go binaries to `/usr/local/bin/` and verify they are executable in `$PATH`.
     - Install Python CLI security tools: `pip install sqlmap arjun`
     - Clone LinkFinder and Corsy into `/opt/` or install their dependencies.
     - Ensure non-root or secure permissions, and verify `nuclei -update-templates` runs during image build so vulnerability templates are cached locally.

2. Update `docker-compose.yml`:
   - Under both `backend` and `celery_worker` services, add:
     ```yaml
     extra_hosts:
       - "host.docker.internal:host-gateway"
     environment:
       - OLLAMA_BASE_URL=http://host.docker.internal:11434/v1
     ```
     This allows local offline Ollama models running on the user's host machine (Windows/Mac/Linux) to communicate seamlessly with Orion.

3. Verify Environment File `.env`:
   - Provide clear sections for:
     - Database (`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`)
     - Redis (`REDIS_URL`)
     - Security AI Engine:
       `AI_PROVIDER=custom`
       `AI_BASE_URL=https://openrouter.ai/api/v1`
       `AI_MODEL=deepseek/deepseek-v4.1-flash`
       `AI_API_KEY=`
       `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1`

Ensure `docker-compose up --build` spins up all services (Postgres, Redis, Backend, Celery Worker, Frontend, Nginx) with zero crashes and clean healthchecks.
```

