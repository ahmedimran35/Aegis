import { create } from 'zustand'

export interface Toast {
  id: number
  type: 'success' | 'error' | 'info' | 'warning'
  message: string
}

interface ToastStore {
  toasts: Toast[]
  addToast: (type: Toast['type'], message: string) => void
  removeToast: (id: number) => void
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
  warning: (message: string) => void
}

let nextId = 0

export const useToast = create<ToastStore>((set, get) => ({
  toasts: [],
  addToast: (type, message) => {
    const id = ++nextId
    set((s) => ({ toasts: [...s.toasts, { id, type, message }] }))
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
    }, 4000)
  },
  removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  success: (msg) => get().addToast('success', msg),
  error: (msg) => get().addToast('error', msg),
  info: (msg) => get().addToast('info', msg),
  warning: (msg) => get().addToast('warning', msg),
}))
