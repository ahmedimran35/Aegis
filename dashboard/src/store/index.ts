import { create } from 'zustand'

export interface Notification {
  id: string
  type: 'threat' | 'blocked'
  message: string
  timestamp: string
  read: boolean
  path?: string
  client_ip?: string
  threat_score?: number
  classification?: string
}

export interface AuthUser {
  id: number
  username: string
  role: 'viewer' | 'analyst' | 'editor' | 'admin'
  must_change_password?: boolean
}

interface AppState {
  sidebarCollapsed: boolean
  mobileMenuOpen: boolean
  compactMode: boolean
  commandPaletteOpen: boolean
  collapsedSections: Record<string, boolean>
  notifications: Notification[]
  notificationPanelOpen: boolean
  // Auth fields (added P-FIX: components referenced user/authChecked/refreshAuth
  // that didn't exist in the store).
  user: AuthUser | null
  authChecked: boolean
  confirmOpen: boolean
  toggleSidebar: () => void
  toggleMobileMenu: () => void
  closeMobileMenu: () => void
  toggleCompactMode: () => void
  toggleCommandPalette: () => void
  openCommandPalette: () => void
  closeCommandPalette: () => void
  toggleSection: (name: string) => void
  addNotification: (n: Notification) => void
  markAllRead: () => void
  toggleNotificationPanel: () => void
  closeNotificationPanel: () => void
  clearNotifications: () => void
  setUser: (u: AuthUser | null) => void
  setAuthChecked: (v: boolean) => void
  refreshAuth: () => Promise<void>
  setConfirmOpen: (v: boolean) => void
}

export const useAppStore = create<AppState>((set, get) => ({
  sidebarCollapsed: false,
  mobileMenuOpen: false,
  compactMode: localStorage.getItem('aegis_compact') === '1',
  commandPaletteOpen: false,
  collapsedSections: {},
  notifications: [],
  notificationPanelOpen: false,
  user: null,
  authChecked: false,
  confirmOpen: false,
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  toggleMobileMenu: () => set((s) => ({ mobileMenuOpen: !s.mobileMenuOpen })),
  closeMobileMenu: () => set({ mobileMenuOpen: false }),
  toggleCompactMode: () => set((s) => {
    const next = !s.compactMode
    localStorage.setItem('aegis_compact', next ? '1' : '0')
    return { compactMode: next }
  }),
  toggleCommandPalette: () => set((s) => ({ commandPaletteOpen: !s.commandPaletteOpen })),
  openCommandPalette: () => set({ commandPaletteOpen: true }),
  closeCommandPalette: () => set({ commandPaletteOpen: false }),
  toggleSection: (name: string) => set((s) => ({
    collapsedSections: {
      ...s.collapsedSections,
      [name]: !s.collapsedSections[name],
    },
  })),
  addNotification: (n: Notification) => set((s) => ({
    notifications: [n, ...s.notifications].slice(0, 50),
  })),
  markAllRead: () => set((s) => ({
    notifications: s.notifications.map((n) => ({ ...n, read: true })),
  })),
  toggleNotificationPanel: () => set((s) => ({ notificationPanelOpen: !s.notificationPanelOpen })),
  closeNotificationPanel: () => set({ notificationPanelOpen: false }),
  clearNotifications: () => set({ notifications: [] }),
  setUser: (u: AuthUser | null) => set({ user: u }),
  setAuthChecked: (v: boolean) => set({ authChecked: v }),
  setConfirmOpen: (v: boolean) => set({ confirmOpen: v }),
  refreshAuth: async () => {
    // P-FIX: real implementation. /api/v1/auth/me returns the auth record
    // directly in `data` (NOT nested under `user`), so we map the fields
    // explicitly — the old `data?.user ?? null` fallback silently set the
    // user to null and bounced every login back to /login.
    try {
      const res = await fetch('/api/v1/auth/me', { credentials: 'include' })
      if (res.ok) {
        const json = await res.json()
        const d = json?.data ?? {}
        const u: AuthUser | null = d?.username
          ? { id: d.id, username: d.username, role: d.role, must_change_password: d.must_change_password }
          : null
        set({ user: u, authChecked: true })
      } else {
        set({ user: null, authChecked: true })
      }
    } catch {
      set({ user: null, authChecked: true })
    }
  },
}))
