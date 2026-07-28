import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  BarChart3,
  ShieldAlert,
  FileText,
  Bot,
  ScrollText,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  X,
  Users,
  Radio,
  ShieldPlus,
  RotateCcw,
  FileJson,
  Radar,
} from 'lucide-react'
import { useAppStore } from '../store'
import type { LucideIcon } from 'lucide-react'

interface NavItem {
  to: string
  icon: LucideIcon
  label: string
  hotkey?: string
}

interface NavSection {
  name: string
  label: string
  items: NavItem[]
}

const navSections: NavSection[] = [
  {
    name: 'monitor',
    label: 'Monitor',
    items: [
      { to: '/overview', icon: LayoutDashboard, label: 'Overview', hotkey: 'g o' },
      { to: '/traffic', icon: BarChart3, label: 'Traffic', hotkey: 'g t' },
      { to: '/threats', icon: ShieldAlert, label: 'Threats', hotkey: 'g h' },
      { to: '/logs', icon: ScrollText, label: 'Logs', hotkey: 'g l' },
    ],
  },
  {
    name: 'security',
    label: 'Security',
    items: [
      { to: '/rules', icon: FileText, label: 'Rules', hotkey: 'g r' },
      { to: '/security', icon: ShieldAlert, label: 'Security Center', hotkey: 'g s' },
      { to: '/active-defenses', icon: Radar, label: 'Active Defenses', hotkey: 'g d' },
      { to: '/virtual-patches', icon: ShieldPlus, label: 'Virtual Patches' },
      { to: '/api-schemas', icon: FileJson, label: 'API Schemas' },
    ],
  },
  {
    name: 'tools',
    label: 'Tools',
    items: [
      { to: '/ai', icon: Bot, label: 'AI Panel', hotkey: 'g a' },
      { to: '/replay', icon: RotateCcw, label: 'Request Replay' },
    ],
  },
  {
    name: 'admin',
    label: 'Admin',
    items: [
      { to: '/users', icon: Users, label: 'Users & Roles' },
      { to: '/audit', icon: ScrollText, label: 'Audit Log' },
      { to: '/sessions', icon: Radio, label: 'Sessions' },
      { to: '/settings', icon: Settings, label: 'Settings', hotkey: 'g ,' },
    ],
  },
]

function AegisLogo({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2L3 6v6c0 5 3.5 9.4 9 10 5.5-.6 9-5 9-10V6l-9-4z"
        fill="#4A6B47"
      />
      <path
        d="M12 2L3 6v6c0 5 3.5 9.4 9 10 5.5-.6 9-5 9-10V6l-9-4z"
        stroke="#2D472B"
        strokeWidth="0.75"
        strokeLinejoin="round"
      />
      <path
        d="M8.5 12l2.5 2.5L15.5 10"
        stroke="#FAF8F4"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
    </svg>
  )
}

export default function Sidebar() {
  const collapsed = useAppStore((s) => s.sidebarCollapsed)
  const mobileOpen = useAppStore((s) => s.mobileMenuOpen)
  const collapsedSections = useAppStore((s) => s.collapsedSections)
  const toggle = useAppStore((s) => s.toggleSidebar)
  const closeMobile = useAppStore((s) => s.closeMobileMenu)
  const toggleSection = useAppStore((s) => s.toggleSection)
  const showLabels = !collapsed || mobileOpen
  // P-FIX (CWE-863): role comes from server-validated zustand state, not localStorage.
  const user = useAppStore((s) => s.user)
  const isAdmin = user?.role === 'admin'

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-ink-800/30 z-40 md:hidden"
          onClick={closeMobile}
        />
      )}

      <aside
        data-open={mobileOpen}
        className={`mobile-sidebar fixed left-0 top-0 h-screen bg-ivory-50 border-r border-ivory-300 z-50
          transition-transform duration-200 flex flex-col w-[244px]
          ${collapsed ? 'md:w-[60px]' : 'md:w-[220px]'}`}
      >
        {/* Logo */}
        <div className="flex items-center justify-between px-4 h-14 border-b border-ivory-200">
          <div className="flex items-center gap-2.5">
            <AegisLogo size={20} />
            {showLabels && (
              <div className="flex items-baseline gap-1.5">
                <span className="text-[13px] font-semibold tracking-tight text-ink-700">Aegis</span>
                <span className="text-[10px] font-mono text-ink-500 tabular-nums">v0.1.0</span>
              </div>
            )}
          </div>
          <button
            onClick={closeMobile}
            aria-label="Close menu"
            className="md:hidden p-1 rounded text-ink-400 hover:text-ink-600 hover:bg-ivory-200"
          >
            <X size={16} />
          </button>
        </div>

        {/* Nav sections */}
        <nav className="flex-1 py-2 px-2 overflow-y-auto scrollbar-thin">
          {navSections.filter(s => s.name !== 'admin' || isAdmin).map((section) => {
            const isCollapsed = collapsedSections[section.name]
            return (
              <div key={section.name} className="mb-1">
                {showLabels && (
                  <button
                    onClick={() => toggleSection(section.name)}
                    aria-expanded={!isCollapsed}
                    aria-controls={`nav-section-${section.name}`}
                    className="nav-section-label w-full flex items-center justify-between"
                  >
                    <span>{section.label}</span>
                    <ChevronDown
                      size={10}
                      className={`transition-transform duration-150 ${isCollapsed ? '-rotate-90' : ''}`}
                    />
                  </button>
                )}
                {(!isCollapsed || !showLabels) && (
                  <div id={`nav-section-${section.name}`} className="space-y-px">
                    {section.items.map(({ to, icon: Icon, label, hotkey }) => (
                      <NavLink
                        key={to}
                        to={to}
                        onClick={closeMobile}
                        className={({ isActive }) =>
                          isActive ? 'nav-item-active' : 'nav-item'
                        }
                        title={!showLabels ? label : undefined}
                      >
                        <Icon size={15} strokeWidth={1.75} className="shrink-0" />
                        {showLabels && (
                          <>
                            <span className="truncate">{label}</span>
                            {hotkey && <span className="nav-kbd">{hotkey}</span>}
                          </>
                        )}
                      </NavLink>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </nav>

        {/* Footer status */}
        {showLabels && (
          <div className="px-4 py-2.5 border-t border-ivory-200 flex items-center gap-2 text-[10px] font-mono text-ink-500 tabular-nums">
            <span className="ws-dot bg-forest-500" />
            <span>all systems normal</span>
          </div>
        )}

        {/* Collapse toggle — desktop only */}
        <button
          onClick={toggle}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className="hidden md:flex items-center justify-center h-9 mx-2 mb-2 rounded
            text-ink-500 hover:text-ink-600 hover:bg-ivory-200 transition-colors"
        >
          {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        </button>
      </aside>
    </>
  )
}