import { Suspense, lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from './state/AuthContext.jsx'
import AppShell from './components/AppShell.jsx'

// Route-level code splitting: each page ships as its own chunk instead of
// one 700kB+ bundle, so the initial load only pays for Login/AppShell.
const Login = lazy(() => import('./pages/Login.jsx'))
const Register = lazy(() => import('./pages/Register.jsx'))
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'))
const Scans = lazy(() => import('./pages/Scans.jsx'))
const NewScan = lazy(() => import('./pages/NewScan.jsx'))
const ScanDetail = lazy(() => import('./pages/ScanDetail.jsx'))
const Findings = lazy(() => import('./pages/Findings.jsx'))
const NetworkMap = lazy(() => import('./pages/NetworkMap.jsx'))
const Reports = lazy(() => import('./pages/Reports.jsx'))
const ReportDetail = lazy(() => import('./pages/ReportDetail.jsx'))
const UsersRoles = lazy(() => import('./pages/UsersRoles.jsx'))
const Settings = lazy(() => import('./pages/Settings.jsx'))

function RequireAuth({ children }) {
  const { user } = useAuth()
  if (!user) return <Navigate to="/login" replace />
  return children
}

function RequireAdmin({ children }) {
  const { can } = useAuth()
  if (!can('manageUsers')) return <Navigate to="/dashboard" replace />
  return children
}

function RouteFallback() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', minHeight: '40vh' }}>
      <span style={{ opacity: 0.6, fontSize: 13 }}>Loading&hellip;</span>
    </div>
  )
}

export default function App() {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/new" element={<NewScan />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="findings" element={<Findings />} />
          <Route path="network" element={<NetworkMap />} />
          <Route path="reports" element={<Reports />} />
          <Route path="reports/:id" element={<ReportDetail />} />
          <Route
            path="users"
            element={
              <RequireAdmin>
                <UsersRoles />
              </RequireAdmin>
            }
          />
          <Route path="settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Suspense>
  )
}
