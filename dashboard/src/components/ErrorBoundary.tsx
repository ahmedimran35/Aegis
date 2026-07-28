import { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  errorId: string | null
}

/**
 * ErrorBoundary catches render-time errors in the React tree and shows a
 * graceful fallback instead of a blank page.
 *
 * P-FIX (L-3): we intentionally log only a sanitized error id, NOT the
 * full error object or stack trace. The previous behavior called
 * `console.error('ErrorBoundary caught', error, info.componentStack)`,
 * which dumped the raw React stack (and sometimes user-typed form
 * values captured by the offending component) into the browser
 * console and any third-party observability script that subscribes to
 * it. The new id is generated client-side and is enough for the user
 * to quote when contacting support; the developer can reproduce by
 * reproducing the steps.
 */
export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, errorId: null }
  }

  static getDerivedStateFromError(_error: Error): State {
    // Generate a short correlation id for support.
    const id = Math.random().toString(36).slice(2, 10).toUpperCase()
    return { hasError: true, errorId: id }
  }

  componentDidCatch(_error: Error, _info: ErrorInfo) {
    // P-FIX (L-3): only log the sanitized id. Do NOT log the raw
    // error object, the component stack, or any user input that may
    // have been captured by the failing render path.
    // eslint-disable-next-line no-console
    console.error(`[errorBoundary] render error (ref: ${this.state.errorId})`)
  }

  handleReset = () => {
    this.setState({ hasError: false, errorId: null })
  }

  handleReload = () => {
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div className="min-h-screen flex items-center justify-center bg-ivory-100 p-6">
          <div className="max-w-md w-full bg-white rounded-2xl shadow-lg border border-ivory-200 p-8">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-red-100 flex items-center justify-center text-red-600 font-bold">!</div>
              <h1 className="text-lg font-semibold text-slate-900">Something went wrong</h1>
            </div>
            <p className="text-sm text-slate-600 mb-4">
              An unexpected error occurred while rendering this page. The Aegis engine and API
              are still running — only this dashboard view is affected.
            </p>
            <p className="text-[11px] text-slate-400 mb-4 font-mono">
              Error reference: <span className="font-semibold text-slate-600">{this.state.errorId}</span>
            </p>
            <div className="flex gap-2">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 text-sm font-medium bg-accent-500 text-white rounded-lg hover:bg-accent-600 transition-colors"
              >
                Try again
              </button>
              <button
                onClick={this.handleReload}
                className="px-4 py-2 text-sm font-medium bg-ivory-50 text-slate-700 rounded-lg hover:bg-ivory-100 transition-colors border border-ivory-200"
              >
                Reload page
              </button>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
