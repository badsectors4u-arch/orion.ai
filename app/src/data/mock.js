// Mock data for the Orion demo frontend. No real backend — everything here is
// fixture data so the app can be clicked through and recorded end to end.

export const ROLES = {
  admin: {
    key: 'admin',
    label: 'Admin / IT Admin',
    blurb: 'Full access — users, scans, settings, integrations',
  },
  analyst: {
    key: 'analyst',
    label: 'Security Analyst',
    blurb: 'Run scans, triage findings, generate reports',
  },
  viewer: {
    key: 'viewer',
    label: 'Viewer / Auditor',
    blurb: 'Read-only — dashboards and reports, no scans',
  },
}

export const PERMISSIONS = {
  admin: { runScan: true, manageUsers: true, manageSettings: true, exportReports: true, editAssets: true },
  analyst: { runScan: true, manageUsers: false, manageSettings: false, exportReports: true, editAssets: true },
  viewer: { runScan: false, manageUsers: false, manageSettings: false, exportReports: true, editAssets: false },
}

export const ASSETS = [
  { id: 'a1', name: 'Corp HQ /24', type: 'network', value: '10.20.0.0/24' },
  { id: 'a2', name: 'customer-portal.example.com', type: 'web_app', value: 'https://customer-portal.example.com' },
  { id: 'a3', name: 'Branch DMZ', type: 'cidr', value: '192.168.40.0/26' },
  { id: 'a4', name: 'internal-api.example.com', type: 'web_app', value: 'https://internal-api.example.com' },
  { id: 'a5', name: 'payments-gateway.example.com', type: 'web_app', value: 'https://payments-gateway.example.com' },
]

export const SCANS = [
  { id: 's1', type: 'network', target: 'Corp HQ /24', status: 'completed', started: '2026-10-24 09:12', duration: '14m 02s', findings: 18, agent: 'Network Scanning' },
  { id: 's2', type: 'web', target: 'customer-portal.example.com', status: 'completed', started: '2026-10-25 11:40', duration: '8m 51s', findings: 7, agent: 'Web Scanning' },
  { id: 's3', type: 'advanced', target: 'payments-gateway.example.com', status: 'running', started: '2026-10-28 09:58', duration: '—', findings: 3, agent: 'Advanced Scanning', progress: 62 },
  { id: 's4', type: 'web', target: 'internal-api.example.com', status: 'queued', started: '—', duration: '—', findings: 0, agent: 'Web Scanning' },
  { id: 's5', type: 'network', target: 'Branch DMZ', status: 'failed', started: '2026-10-22 16:03', duration: '2m 10s', findings: 0, agent: 'Network Scanning' },
]

export const FINDINGS = [
  {
    id: 'f1', title: 'Outdated OpenSSH exposes known RCE path', asset: 'Corp HQ /24', severity: 'critical', status: 'open', confidence: 0.94, agent: 'Network Scanning', cve: 'CVE-2024-6387', discovered: '2026-10-24',
    cvss_score: 9.8,
    description: `### 📍 Vulnerability Location
- **Host:** \`10.20.0.14\`
- **Service:** \`OpenSSH 8.9p1\` on port \`22\`

### 💥 Exploitation Proof & Payload
A race condition in the signal handler allows an unauthenticated remote attacker to trigger a use-after-free, as described in CVE-2024-6387 ("regreSSHion"):
\`\`\`
ssh -o PreferredAuthentications=none <target>
\`\`\`
Repeated connection attempts within the race window can corrupt heap state.

### 🔬 Technical Analysis & Vulnerability Mechanics
The vulnerable code path runs in a signal handler that is **not async-signal-safe**, calling functions that can be interrupted mid-allocation when the client disconnects at the wrong moment.

### 📊 Threat Severity & CVSS v3.1 Scoring
**CVSS 9.8** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — CWE-362`,
    remediation_steps: [
      'Upgrade OpenSSH to 9.8 or later, which removes the unsafe signal handler.',
      'Until patched, set `LoginGraceTime 0` in `sshd_config` as a temporary mitigation.',
      'Restrict SSH exposure to a VPN or bastion host instead of the open internet.',
    ],
  },
  {
    id: 'f2', title: 'SQL injection in /search endpoint', asset: 'customer-portal.example.com', severity: 'critical', status: 'confirmed', confidence: 0.91, agent: 'Web Scanning', cve: 'CVE-2023-4511', discovered: '2026-10-25',
    cvss_score: 9.1,
    description: `### 📍 Vulnerability Location
- **URL:** \`https://customer-portal.example.com/search\`
- **Parameter:** \`q\`

### 💥 Exploitation Proof & Payload
Payload used:
\`\`\`
' UNION SELECT username, password FROM users --
\`\`\`
The response leaked hashed credentials from the \`users\` table.

### 🔬 Technical Analysis & Vulnerability Mechanics
The query is built by **string concatenation** of the \`q\` parameter, so attacker input can change the SQL logic and reach tables outside the intended scope.

### 📊 Threat Severity & CVSS v3.1 Scoring
**CVSS 9.1** (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N) — CWE-89`,
    remediation_steps: [
      'Use parameterized queries everywhere, e.g. `cursor.execute("SELECT * FROM items WHERE name = %s", (q,))`.',
      'Apply least-privilege permissions to the database account used by the web app.',
      'Add input validation and a WAF rule to block common SQLi patterns as defense in depth.',
    ],
  },
  {
    id: 'f3', title: 'TLS 1.0 still accepted on payment gateway', asset: 'payments-gateway.example.com', severity: 'high', status: 'open', confidence: 0.88, agent: 'Advanced Scanning', cve: null, discovered: '2026-10-28',
    cvss_score: 7.4,
    description: `### 📍 Vulnerability Location
- **Host:** \`payments-gateway.example.com:443\`

### 💥 Exploitation Proof & Payload
\`\`\`
openssl s_client -connect payments-gateway.example.com:443 -tls1
\`\`\`
The handshake completes successfully, confirming TLS 1.0 is still negotiable.

### 🔬 Technical Analysis & Vulnerability Mechanics
TLS 1.0 is vulnerable to BEAST and lacks modern cipher suites, and PCI-DSS requires it to be disabled on systems that handle cardholder data.

### 📊 Threat Severity & CVSS v3.1 Scoring
**CVSS 7.4** — CWE-327`,
    remediation_steps: [
      'Disable TLS 1.0 and TLS 1.1 in the web server/load balancer configuration.',
      'Require TLS 1.2 or higher, preferring AEAD cipher suites.',
      'Re-scan with an SSL/TLS auditor to confirm only modern protocols are offered.',
    ],
  },
  { id: 'f4', title: 'Default credentials on management console', asset: 'Branch DMZ', severity: 'high', status: 'open', confidence: 0.8, agent: 'Network Scanning', cve: null, discovered: '2026-10-24' },
  { id: 'f5', title: 'Outdated jQuery with known XSS', asset: 'customer-portal.example.com', severity: 'medium', status: 'false_positive', confidence: 0.55, agent: 'Web Scanning', cve: 'CVE-2020-11023', discovered: '2026-10-25' },
  { id: 'f6', title: 'Verbose server banner leaks software version', asset: 'internal-api.example.com', severity: 'low', status: 'resolved', confidence: 0.97, agent: 'Web Scanning', cve: null, discovered: '2026-10-21' },
  { id: 'f7', title: 'SMBv1 enabled on 6 hosts', asset: 'Corp HQ /24', severity: 'high', status: 'open', confidence: 0.9, agent: 'Network Scanning', cve: 'CVE-2017-0144', discovered: '2026-10-24' },
  {
    id: 'f8', title: 'Missing rate limiting on login endpoint', asset: 'payments-gateway.example.com', severity: 'medium', status: 'open', confidence: 0.72, agent: 'Advanced Scanning', cve: null, discovered: '2026-10-28',
    cvss_score: 5.3,
    description: `### 📍 Vulnerability Location
- **URL:** \`https://payments-gateway.example.com/login\`

### 💥 Exploitation Proof & Payload
10,000 login attempts were sent in 60 seconds with no lockout, throttling, or CAPTCHA triggered.

### 🔬 Technical Analysis & Vulnerability Mechanics
With no rate limiting, an attacker can run a credential-stuffing or brute-force attack at high speed against valid accounts.

### 📊 Threat Severity & CVSS v3.1 Scoring
**CVSS 5.3** — CWE-307`,
    remediation_steps: [
      'Add rate limiting per IP and per account on the login endpoint.',
      'Introduce progressive delays or a CAPTCHA after repeated failures.',
      'Alert on anomalous login volume so a credential-stuffing attempt is caught early.',
    ],
  },
  { id: 'f9', title: 'Informational: HSTS header absent', asset: 'internal-api.example.com', severity: 'info', status: 'open', confidence: 0.99, agent: 'Web Scanning', cve: null, discovered: '2026-10-21' },
]

export const SEVERITY_META = {
  critical: { label: 'Critical', color: 'var(--color-crit)', soft: 'var(--color-crit-soft)' },
  high: { label: 'High', color: 'var(--color-high)', soft: 'var(--color-high-soft)' },
  medium: { label: 'Medium', color: 'var(--color-med)', soft: 'var(--color-med-soft)' },
  low: { label: 'Low', color: 'var(--color-low)', soft: 'var(--color-low-soft)' },
  info: { label: 'Info', color: 'var(--color-info)', soft: 'var(--color-info-soft)' },
}

export const REPORTS = [
  { id: 'r1', scan: 'Corp HQ /24 — Network Scan', date: '2026-10-24', findings: 18, critical: 1, high: 2, format: 'PDF' },
  { id: 'r2', scan: 'customer-portal.example.com — Web Scan', date: '2026-10-25', findings: 7, critical: 1, high: 0, format: 'PDF' },
  { id: 'r3', scan: 'Branch DMZ — Network Scan (failed)', date: '2026-10-22', findings: 0, critical: 0, high: 0, format: 'PDF' },
]

export const NETWORK_NODES = [
  { id: 'gw', label: 'Gateway', x: 50, y: 10, kind: 'gateway', risk: 'low' },
  { id: 'fw', label: 'Firewall', x: 50, y: 28, kind: 'firewall', risk: 'low' },
  { id: 'sw1', label: 'Core Switch', x: 50, y: 46, kind: 'switch', risk: 'low' },
  { id: 'srv1', label: 'DC01', x: 20, y: 68, kind: 'server', risk: 'medium' },
  { id: 'srv2', label: 'FILE-SRV', x: 50, y: 68, kind: 'server', risk: 'critical' },
  { id: 'srv3', label: 'SSH-GW', x: 80, y: 68, kind: 'server', risk: 'critical' },
  { id: 'ws1', label: '14 workstations', x: 20, y: 90, kind: 'cluster', risk: 'high' },
  { id: 'ws2', label: 'Printers (6)', x: 50, y: 90, kind: 'cluster', risk: 'low' },
  { id: 'ws3', label: 'IoT / cameras', x: 80, y: 90, kind: 'cluster', risk: 'high' },
]
export const NETWORK_EDGES = [
  ['gw', 'fw'], ['fw', 'sw1'], ['sw1', 'srv1'], ['sw1', 'srv2'], ['sw1', 'srv3'],
  ['srv1', 'ws1'], ['srv2', 'ws2'], ['srv3', 'ws3'],
]

export const CHAT_SEED = [
  { role: 'assistant', text: "Hi, I'm Ask Orion. Ask me about any scan, finding, or how to scope a new one." },
]

export function askOrion(question) {
  const q = question.toLowerCase()
  if (q.includes('critical')) {
    return "You have 2 open critical findings: an outdated OpenSSH build with a known RCE path on Corp HQ /24, and a SQL injection in the customer portal's /search endpoint. I'd triage the SQL injection first — it's internet-facing."
  }
  if (q.includes('scan') && (q.includes('start') || q.includes('new') || q.includes('run'))) {
    return "I can help scope that. Tell me the target and I'll suggest a scan type — network, web, or advanced — and pre-fill sensible parameters before it launches."
  }
  if (q.includes('report')) {
    return "Every completed scan gets a fixed-template report under Reports — same structure every time, ready to hand to a non-specialist."
  }
  return "Noted. In the full build I reason over live scan data — for this demo my answers are canned, but the layout and flow are real."
}
