# 🛡️ البرومبت التنفيذي لمسؤول الفرونت اند (Member 1)
## Orion Threat Intelligence & Dark Web Breach Report Page

> **الموجه إلى:** المهندس المسؤول عن الفرونت إند (Member 1 - Frontend Lead)  
> **التقنيات المستخدمة:** React, TypeScript, Tailwind CSS, Lucide Icons  
> **حالة الباك إند و AI:** جاهز 100% ويعمل ببيانات حقيقية حية (Real-time XposedOrNot Dark Web Analytics + AI Threat Intelligence Synthesis)  
> **الهدف:** إضافة صفحة / فيو جديد باسم **Breach Intelligence Report** داخل منصة Orion يعرض نتائج فحص تسريبات الدارك ويب لأي بريد إلكتروني كـ **تقرير أمني تنفيذي شامل (Executive Threat Intelligence Dossier)**.

---

### 📋 نص البرومبت الذي تنسخه وتبعته لمسؤول الفرونت إند:

```text
You are an expert Senior Frontend Engineer working on the Orion Security Platform using React, TypeScript, and Tailwind CSS.

The Backend (Member 2) and Security AI (Member 3) teams have integrated a 100% real-time, live Dark Web Threat Intelligence Engine using XposedOrNot Breach Analytics API combined with an AI Security Synthesizer.

We need you to build a dedicated, executive-level "Breach Intelligence Report" view/page where users can scan any email address and inspect a rich security dossier.

---

### 1. API Contract & Endpoint Details

- Endpoint: `POST /api/threats/breach-check`
- Headers: `Authorization: Bearer <token>`
- Request Body:
```json
{
  "email": "omarsilvawa@gmail.com"
}
```

- Real Live Response Schema (Tested & Verified on Live Data):
```json
{
  "email": "omarsilvawa@gmail.com",
  "breach_count": 1,
  "breaches": [
    {
      "name": "AlienStealerLogs",
      "date": "2025",
      "data_classes": [
        "Email addresses",
        "Passwords"
      ],
      "account_count": 299646818,
      "details": "ALIEN TXTBASE, a stealer log collection, was exposed in February 2025 when 23 billion rows of logs were obtained from a Telegram channel, revealing 299M unique email addresses along with the websites they were entered into and the passwords used.",
      "domain": null,
      "industry": "Miscellaneous",
      "logo": "https://xposedornot.com/static/logos/combolist.png",
      "password_risk": "plaintext",
      "verified": "Yes"
    }
  ],
  "risk_score": 17.0,
  "risk_label": "Low",
  "passwords_exposed": 1,
  "plaintext_passwords": 1,
  "easy_to_crack_passwords": 0,
  "paste_count": 0,
  "year_distribution": {
    "2025": 1
  },
  "exposed_data_types": [
    "Email addresses",
    "Passwords"
  ],
  "ai_analysis": {
    "threat_level": "CRITICAL",
    "verdict": "Critical Exposure: 1 Plaintext Password(s) Actively Circulating!",
    "summary": "Threat intelligence detected 1 dark web leak incident(s) involving omarsilvawa@gmail.com (including AlienStealerLogs). ALARM: 1 password(s) leaked in unencrypted plaintext, allowing adversaries instant access. Compromised data classes include: Email addresses, Passwords.",
    "primary_threat_vector": "Infostealer Malware Trojan (Endpoint Credential Harvesting)",
    "remediation_checklist": [
      "IMMEDIATE: Reset passwords for this email address and all linked online accounts.",
      "Ensure no password reuse across personal, financial, and corporate services.",
      "CRITICAL: Run a thorough anti-malware and EDR scan to detect and remove infostealer trojans on local machines.",
      "Revoke all active browser sessions, OAuth grant tokens, and persistent login cookies.",
      "Enable Multi-Factor Authentication (MFA / 2FA) using an Authenticator App (TOTP) or Hardware FIDO2 Key.",
      "Inspect linked financial/banking statements and email forwarding rules for unauthorized alterations."
    ]
  },
  "error": null
}
```

---

### 2. TypeScript Interfaces to Add

Add the following to `app/src/types/index.ts` and `app/src/api/index.ts`:

```typescript
export interface BreachEntry {
  name: string;
  date: string;
  data_classes: string[];
  account_count: number | null;
  details: string | null;
  domain: string | null;
  industry: string | null;
  logo: string | null;
  password_risk: string | null;
  verified: string | null;
}

export interface BreachAIAnalysis {
  threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';
  verdict: string;
  summary: string;
  primary_threat_vector: string;
  remediation_checklist: string[];
}

export interface BreachResult {
  email: string;
  breach_count: number;
  breaches: BreachEntry[];
  risk_score: number;
  risk_label: string;
  passwords_exposed: number;
  plaintext_passwords: number;
  easy_to_crack_passwords: number;
  paste_count: number;
  year_distribution: Record<string, number>;
  exposed_data_types: string[];
  ai_analysis: BreachAIAnalysis | null;
  error: string | null;
}

// In app/src/api/index.ts:
export const threatsApi = {
  checkBreach: (email: string) => api.post<BreachResult>('/api/threats/breach-check', { email }),
};
```

---

### 3. Component & Page UI Requirements (`BreachReportView.tsx`)

Create a high-end, cyberpunk dark-themed report page matching Orion's aesthetic (`#060a12` background, `#e84057` / `#00f2fe` accents, glassmorphic cards):

1. **Email Scanner Bar (Top)**:
   - Modern input field with search icon and "Analyze Identity" button with loading spinner state.
   - Support pressing `Enter` to search.
   - Quick sample tags for quick testing (e.g. `omarsilvawa@gmail.com`).

2. **Executive Summary & Threat Gauge Header**:
   - Radial / Circular Gauge showing `risk_score` (0 - 100) with color mapping:
     - 0: Green (#22c55e) "Clean"
     - 1-30: Blue/Cyan (#00f2fe) "Low"
     - 31-60: Amber/Yellow (#eab308) "Medium"
     - 61-80: Orange (#f97316) "High"
     - 81-100: Crimson Red (#ef4444) "Critical"
   - Identity Status Badge: "BREACHED" (Red/Crimson glow) or "CLEAN" (Emerald glow).
   - Export Button: "Export Executive JSON" and "Print Dossier".

3. **Key Threat Telemetry Cards (4-Column Grid)**:
   - **Card 1: Known Breaches**: Shows `breach_count` with database icon.
   - **Card 2: Plaintext Passwords Alert**:
     - If `plaintext_passwords > 0`: Highlight with a pulsing red border & alert icon: `🚨 ${plaintext_passwords} Plaintext Passwords Exposed!`.
   - **Card 3: Weak / Crackable Hashes**: Shows `easy_to_crack_passwords`.
   - **Card 4: Dark Web Pastes**: Shows `paste_count` (Pastebin, Deep Web drops).

4. **AI Security Intelligence Card (Prominent Executive Section)**:
   - Banner displaying `ai_analysis.verdict` with the corresponding `threat_level` badge (e.g., `CRITICAL` in glowing red).
   - **Primary Threat Vector**: e.g., `Infostealer Malware Trojan (Endpoint Credential Harvesting)`.
   - **Executive Narrative**: Displays `ai_analysis.summary` formatted cleanly.
   - **Actionable Remediation Checklist**: Renders `ai_analysis.remediation_checklist` as an interactive checklist where users can mark items as completed.

5. **Compromised Data Categories (Tags Cloud)**:
   - Displays `exposed_data_types` as badge chips (e.g., `Passwords`, `Email addresses`, `IP addresses`).
   - If "Passwords" is in the list, render it in red badge.

6. **Detailed Breach Dossier Cards (List / Grid)**:
   - For each breach in `breaches`:
     - **Logo**: Render `b.logo` inside an image container (with a fallback shield icon if the image fails to load).
     - **Header**: Breach Name (`b.name`), Verified Badge (`Verified: Yes`), Exposure Year (`b.date`), Industry (`b.industry`).
     - **Total Records Compromised**: Render `b.account_count` formatted with commas (e.g., `299,646,818 accounts globally`).
     - **Password Risk Badge**: Tag showing `Password Risk: ${b.password_risk}` (e.g. `plaintext` highlighted red).
     - **Detailed Narrative**: Render `b.details` explaining how the incident occurred.
     - **Compromised Data Pills**: Sub-badges for each data class in `b.data_classes`.

7. **Year Distribution Timeline**:
   - Simple bar / timeline chart showing breach frequency by year based on `year_distribution`.

8. **Clean State (When breach_count == 0)**:
   - Show a celebratory green shield illustration: "No Dark Web Exposures Detected. Identity is secure." with preventative security best practices.

---

### 4. Integration into Navigation

- In `app/src/types/index.ts`: Add `'threats'` to `ViewType`:
  `export type ViewType = 'dashboard' | 'scans' | 'reports' | 'bruteforce' | 'threats' | 'settings' | 'about';`
- In `app/src/components/sidebar/Sidebar.tsx`: Add navigation item:
  `{ id: 'threats', label: 'Dark Web Intel', icon: ShieldAlert, tooltip: 'Breach analytics & dark web dossiers' }`
- In `app/src/App.tsx`: Mount `<BreachReportView />` in the `views` dictionary under `'threats'`.
```
