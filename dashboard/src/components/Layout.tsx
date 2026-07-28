import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import ChatBubble from './ChatBubble'
import ToastContainer from './Toast'
import Breadcrumb from './Breadcrumb'
import PageTransition from './PageTransition'
import KeyboardHelp from './KeyboardHelp'
import CommandPalette from './CommandPalette'
import { useAppStore } from '../store'
import { useKeyboard } from '../hooks/useKeyboard'
import { useNotifications } from '../hooks/useNotifications'

export default function Layout() {
  const collapsed = useAppStore((s) => s.sidebarCollapsed)
  const { showHelp, setShowHelp } = useKeyboard()

  // Wire WebSocket threat/blocked events into notifications
  useNotifications()

  return (
    <div className="min-h-screen bg-ivory-100 noise-bg">
      <Sidebar />
      <div className={collapsed ? 'md:ml-[68px]' : 'md:ml-[220px]'}>
        <TopBar onShowShortcuts={() => setShowHelp(true)} />
        <Breadcrumb />
        <main className="p-4 md:p-6">
          <PageTransition>
            <Outlet />
          </PageTransition>
        </main>
      </div>
      <ChatBubble />
      <ToastContainer />
      <KeyboardHelp open={showHelp} onClose={() => setShowHelp(false)} />
      <CommandPalette />
    </div>
  )
}
