import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import './index.css'

// =============================================================================
//
// Auto-update check removed — it caused an infinite reload loop on the
// login page (10s × N reloads × X rebuilds = never-ending spinner).
// Cache invalidation is now handled entirely by the server-side
// `Cache-Control: no-store, no-cache, must-revalidate` response header.
// The user must hard-refresh manually (Cmd+Shift+R) to pick up a new
// build. The build version is visible in the topbar
// (`v0.1.0 · build-2026-07-22T...`) so the user can confirm.
//
// =============================================================================

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
)
