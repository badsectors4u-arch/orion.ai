# 🎨 دليل العضو 1 (Frontend & UI/UX): التحديثات الجديدة والبرومبت التنفيذي
# Member 1 Execution Guide: Security UI Upgrades & Copilot Integration

> **الموجه إلى**: العضو رقم 1 (Lead Frontend Engineer & UI/UX Designer)  
> **النطاق الحصري**: مجلد `app/` (React, TypeScript, Tailwind CSS, React Flow)  
> **حالة الباك إند**: تم إكمال ترقية محرك الفحص الأمني والـ AI Hunter وتوحيد عقود البيانات بنجاح 100%.

---

## 📌 1. ملخص التحديثات الجديدة التي أنجزها العضو 3 وتؤثر على الواجهة

1. **تفاصيل الثغرات أصبحت متقدمة ومفصلة (Advanced Markdown Breakdown)**:
   - حقل `description` في كل ثغرة لم يعد مجرد سطر واحد، بل أصبح يحتوي على 4 أقسام منسقة بالماركداون:
     - `### 📍 Vulnerability Location`: الرابط الكامل، الـ Endpoint، والباراميتر المصاب تحديداً.
     - `### 💥 Exploitation Proof & Payload`: البيلود المستخدم في الفحص وطريقة التحقق وكود الـ CVSS Vector.
     - `### 🔬 Technical Analysis & Vulnerability Mechanics`: التحليل الفني العميق لسبب حدوث الثغرة وكيفية استغلالها.
     - `### 📊 Threat Severity & CVSS v3.1 Scoring`: سكور الـ CVSS الرقمي والتصنيف الرسمي (CWE / CVE).
2. **سكور CVSS رقمي في كل ثغرة**: حقل `cvss_score` لم يعد `null` أبداً، بل يحمل قيمة رقمية دقيقة (مثال: `9.8`, `8.5`, `5.4`).
3. **تفعيل الشات بوت الحقيقي (Ghost Analyst / Security Copilot)**:
   - تم ربط محرك الـ AI للشات بوت (`/api/ai/chat`) وأصبح ثنائي اللغة تماماً (عربي / إنجليزي).
   - الشات بوت يفهم سياق الفحص بالكامل؛ فيمكن للمستخدم أن يسأله عن الثغرات المكتشفة في الموقع وطرق ترقيعها بالكود.
   - يجب إزالة المحاكاة المزيفة (`setTimeout`) في `AIAssistantWidget.tsx` واستدعاء الـ API الحقيقي.
4. **تخصيص وقت الـ AI Deep Hunter في الفحص**:
   - الفحص المتقدم يدعم الآن مدة فحص الـ AI (`ai_hunter_duration`: 5 دقائق افتراضي، أو 10/15 دقيقة للفحص العميق).

---

## 💻 2. المطلوب برمجياً من العضو 1 في مجلد `app/`

1. في **نافذة تفاصيل الثغرة (Vulnerability Detail Modal / Table)**:
   - استخدام مفسر ماركداون (مثل `react-markdown`) لعرض حقل `description` بتنسيقه الجذاب بدلاً من عرضه كنص خام.
   - عرض شارة سكور الـ CVSS بجانب شارة الخطورة (مثال: `CVSS 9.8` بلون أحمر للـ Critical و `CVSS 8.5` برتقالي للـ High).
2. في **ودجت الشات بوت (`app/src/components/ai-widget/AIAssistantWidget.tsx`)**:
   - ربط إرسال الرسائل بدالة `api.ai.chat(...)` الموجودة مسبقاً في `app/src/api/index.ts`.
   - تمرير الـ `scan_id` إذا كان المستخدم يشاهد فحصاً محدداً ليتحدث الـ AI في سياق ثغراته.
3. في **مودال بدء فحص جديد (`NewScanModal.tsx`)**:
   - إضافة خيار بسيط لاختيار مدة فحص الـ AI في الخطط المتقدمة (Standard 5 min / Deep 10 min).

---

## 🤖 3. البرومبت التنفيذي الموجه للعضو 1 (انسخه بالكامل والصقه في الـ AI)

```text
You are an expert Senior Frontend Engineer working on the Orion Security Platform using React, TypeScript, Tailwind CSS, and Lucide icons.

The Security AI Engineer (Member 3) has upgraded the backend scanning engine. You need to update the frontend components to display the rich vulnerability data and connect the live AI Copilot chatbot.

### Required Changes:

1. Update `app/src/components/ai-widget/AIAssistantWidget.tsx`:
   - Remove the mock simulation (`setTimeout` with static strings).
   - Import the real API client: `import { api } from '@/api';`
   - In `handleSend`:
     - Show the user's message immediately and set `isTyping = true`.
     - Call `await api.ai.chat({ message: input, scan_id: currentScanId, history: previousTurns })`.
     - Parse the returned `ChatResponse`:
       - Append the answer to messages.
       - Display key points as bullet tags if available.
       - Display follow-up prompt suggestion chips below the response that the user can click to ask instantly.
     - Add clean error handling showing a retry banner if the request fails.

2. Update Vulnerability Findings Details (Vulnerability Modal or Row View):
   - In `VulnerabilityItem`, ensure the `cvss_score` is displayed as a prominent badge with dynamic coloring:
     - Score >= 9.0: Red (`#e84057`) - Critical
     - Score >= 7.0: Orange (`#f97316`) - High
     - Score >= 4.0: Amber (`#f59e0b`) - Medium
     - Score < 4.0: Blue (`#3b82f6`) - Low/Info
   - For `description`, render it using Markdown (or format the headers `### 📍 Vulnerability Location`, `### 💥 Exploitation Proof & Payload`, `### 🔬 Technical Analysis & Vulnerability Mechanics`, `### 📊 Threat Severity & CVSS v3.1 Scoring` with clear visual section cards, bold subtitles, and code blocks for payloads and endpoints).
   - Render `remediation_steps` as an actionable checklist with a copy button for code snippets.

3. Update `app/src/components/scans/NewScanModal.tsx`:
   - Under scan options, add an "AI Deep Hunter" duration selector (exclusive to Advanced/Full scans):
     - Options: "Standard AI Probe (5 min)" [default: 300s], "Deep AI Audit (10 min)" [600s].
     - Pass `plan: "advanced"` and `ai_hunter_duration: selectedSeconds` in the scan initiation payload.

Make sure the UI remains responsive, dark-themed (#111116 background, #e84057 accent), and strictly matches the existing design system without broken types.
```

