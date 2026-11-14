# Orion Security Platform — UI/UX Reference Build

A role-aware, AI-assisted frontend for the Orion Security Platform (DEPI graduation
project, Team BadSectors). This is a **frontend-only reference build** — all data
(assets, scans, findings, reports) is local fixture data in `src/data/mock.js`.
There is no real backend, no real scanning, and no real network traffic.

## Running it

```bash
npm install
npm run dev
```

Then open the local URL Vite prints (usually `http://localhost:5173`).

## What to try

1. **Register** an organization and pick a role (Admin / IT Admin, Security Analyst,
   or Viewer / Auditor). Generic placeholders only — no real names anywhere.
2. Explore the **Dashboard**, **Scans** (try the 3-step "New Scan" wizard), **Scan
   detail** (open the running scan to see the live progress pipeline), **Findings**
   (click a row for the detail drawer), **Network Map**, **Reports**, and **Settings**.
3. **Users & Roles** and the **"New Scan"** button only appear for roles permitted
   to use them — log out and register again as a Viewer / Auditor to see the
   restricted view.
4. Click the floating **Ask Orion** button (bottom right) to try the AI assistant —
   answers are scripted for this demo but the chat UI and flow are real.
5. On the **Login** screen, switch between the **Password**, **Biometric**, and
   **Security Key** tabs — the latter two are simulated (no real sensor/hardware
   access), since this is a browser demo.

## Stack

- React 19 + Vite
- Tailwind CSS v4 (token-based theme in `src/index.css`)
- React Router v7 (role-aware route guards in `src/App.jsx`)
- Recharts (dashboard charts), Lucide (icons)

## Project structure

```
src/
  components/   Shared UI (AppShell, badges, Ask Orion widget, auth shell, ...)
  data/mock.js  All fixture data + the canned "Ask Orion" responses
  pages/        One file per screen
  state/        AuthContext — the mocked session + RBAC permission checks
```
