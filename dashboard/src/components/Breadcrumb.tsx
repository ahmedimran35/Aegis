import { useLocation, Link } from 'react-router-dom'

const routeLabels: Record<string, string> = {
  '/traffic': 'Traffic Analytics',
  '/threats': 'Threat Center',
  '/rules': 'Rule Management',
  '/ai': 'AI Panel',
  '/logs': 'Request Logs',
  '/security': 'Security Center',
  '/users': 'Users & Roles',
  '/audit': 'Audit Log',
  '/sessions': 'Sessions',
  '/virtual-patches': 'Virtual Patches',
  '/replay': 'Request Replay',
  '/api-schemas': 'API Schemas',
  '/settings': 'Settings',
}

export default function Breadcrumb() {
  const { pathname } = useLocation()

  if (pathname === '/overview' || pathname === '/' || pathname === '/login') return null

  const label = routeLabels[pathname]
  if (!label) return null

  return (
    <div className="px-4 md:px-6 py-2">
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs">
        <Link to="/overview" className="text-slate-400 hover:text-slate-600 transition-colors">
          Overview
        </Link>
        <span className="text-slate-300" aria-hidden="true">/</span>
        <span className="text-slate-600 font-medium">{label}</span>
      </nav>
    </div>
  )
}
