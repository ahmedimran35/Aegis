import { lazy, Suspense, useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import ErrorBoundary from './components/ErrorBoundary'
import { useAppStore } from './store'
import { SkipLink, A11yLiveRegion } from './a11y/Primitives'

// Lazy-loaded route chunks. Each page is a separate JS chunk so the
// initial bundle only ships Login + Layout + shared components. Heavy
// pages (Overview, ThreatCenter, Settings, AIPanel) load on demand.
const Login = lazy(() => import('./pages/Login'))
const Overview = lazy(() => import('./pages/Overview'))
const TrafficAnalytics = lazy(() => import('./pages/TrafficAnalytics'))
const ThreatCenter = lazy(() => import('./pages/ThreatCenter'))
const RuleManagement = lazy(() => import('./pages/RuleManagement'))
const AIPanel = lazy(() => import('./pages/AIPanel'))
const RequestLogs = lazy(() => import('./pages/RequestLogs'))
const Settings = lazy(() => import('./pages/Settings'))
const SecurityCenter = lazy(() => import('./pages/SecurityCenter'))
const Users = lazy(() => import('./pages/Users'))
const AuditLog = lazy(() => import('./pages/AuditLog'))
const Sessions = lazy(() => import('./pages/Sessions'))
const VirtualPatches = lazy(() => import('./pages/VirtualPatches'))
const RequestReplay = lazy(() => import('./pages/RequestReplay'))
const APISchemas = lazy(() => import('./pages/APISchemas'))
// Active Defenses: WSGuard, threat feed, CRS update, anomaly stats, k8s hints.
const ActiveDefenses = lazy(() => import('./pages/ActiveDefenses'))

// P-FIX (CWE-863): RequireAuth now consults server /auth/me via zustand
// state. The old localStorage flag could be set by XSS; now the server
// validates the HttpOnly cookie session and returns the user, or we
// redirect to login.
function RequireAuth({ children }: { children: React.ReactNode }) {
  const user = useAppStore((s) => s.user)
  const authChecked = useAppStore((s) => s.authChecked)
  const refreshAuth = useAppStore((s) => s.refreshAuth)

  useEffect(() => {
    if (!authChecked) refreshAuth()
  }, [authChecked, refreshAuth])

  if (!authChecked) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-ivory-100">
        <div className="text-slate-500 text-sm">Verifying session...</div>
      </div>
    )
  }
  if (!user) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

// RouteFallback renders a small skeleton while a lazy chunk loads.
// Used for every lazy route below.
function RouteFallback() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="flex items-center gap-3 text-slate-400 text-sm">
        <div className="w-2 h-2 rounded-full bg-forest-500 animate-pulse" />
        Loading…
      </div>
    </div>
  )
}

// Wrap each route in ErrorBoundary + Suspense so a chunk failure shows
// the error UI, not a white screen.
function routeWrap(element: React.ReactNode) {
  return <ErrorBoundary><Suspense fallback={<RouteFallback />}>{element}</Suspense></ErrorBoundary>
}

export default function App() {
  return (
    <>
      <SkipLink />
      <A11yLiveRegion />
      <Routes>
        <Route path="/login" element={routeWrap(<Login />)} />
        <Route element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={routeWrap(<Overview />)} />
          <Route path="/traffic" element={routeWrap(<TrafficAnalytics />)} />
          <Route path="/threats" element={routeWrap(<ThreatCenter />)} />
          <Route path="/rules" element={routeWrap(<RuleManagement />)} />
          <Route path="/ai" element={routeWrap(<AIPanel />)} />
          <Route path="/logs" element={routeWrap(<RequestLogs />)} />
          <Route path="/security" element={routeWrap(<SecurityCenter />)} />
          <Route path="/users" element={routeWrap(<Users />)} />
          <Route path="/audit" element={routeWrap(<AuditLog />)} />
          <Route path="/sessions" element={routeWrap(<Sessions />)} />
          <Route path="/virtual-patches" element={routeWrap(<VirtualPatches />)} />
          <Route path="/replay" element={routeWrap(<RequestReplay />)} />
          <Route path="/api-schemas" element={routeWrap(<APISchemas />)} />
          <Route path="/settings" element={routeWrap(<Settings />)} />
          <Route path="/active-defenses" element={routeWrap(<ActiveDefenses />)} />
        </Route>
      </Routes>
    </>
  )
}