import { type ReactNode, useState, useMemo } from 'react'
import { Search, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, Inbox } from 'lucide-react'

interface Column<T> {
  key: string
  header: string
  sortable?: boolean
  render?: (row: T) => ReactNode
  className?: string
}

interface DataTableProps<T> {
  columns: Column<T>[]
  data: T[]
  emptyMessage?: string | ReactNode
  emptyAction?: ReactNode
  onRowClick?: (row: T) => void
  searchable?: boolean
  pageSize?: number
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export default function DataTable<T extends Record<string, any>>({
  columns,
  data,
  emptyMessage = 'No data',
  emptyAction,
  onRowClick,
  searchable = false,
  pageSize,
}: DataTableProps<T>) {
  const rows = data || []
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [page, setPage] = useState(1)

  // Filter
  const filtered = useMemo(() => {
    if (!search || !searchable) return rows
    const q = search.toLowerCase()
    return rows.filter((row) =>
      columns.some((col) => String(row[col.key] ?? '').toLowerCase().includes(q))
    )
  }, [rows, search, searchable, columns])

  // Sort
  const sorted = useMemo(() => {
    if (!sortKey) return filtered
    return [...filtered].sort((a, b) => {
      const av = a[sortKey] ?? ''
      const bv = b[sortKey] ?? ''
      const numA = Number(av)
      const numB = Number(bv)
      if (!isNaN(numA) && !isNaN(numB)) {
        return sortDir === 'asc' ? numA - numB : numB - numA
      }
      const cmp = String(av).localeCompare(String(bv))
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [filtered, sortKey, sortDir])

  // Paginate
  const usePagination = pageSize != null && sorted.length > pageSize
  const totalPages = usePagination ? Math.ceil(sorted.length / pageSize) : 1
  const paginated = usePagination ? sorted.slice((page - 1) * pageSize, page * pageSize) : sorted

  // Reset page on filter/sort change
  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
    setPage(1)
  }

  return (
    <div className="space-y-3">
      {searchable && (
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1) }}
            placeholder="Filter..."
            aria-label="Search table"
            className="input-field pl-9 max-w-xs"
          />
        </div>
      )}

      <div className="overflow-x-auto rounded-xl border border-ivory-300 bg-white">
        <table className="w-full">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={`table-header ${col.sortable ? 'cursor-pointer select-none hover:text-slate-700' : ''} ${col.className || ''}`}
                  onClick={col.sortable ? () => handleSort(col.key) : undefined}
                >
                  <span className="inline-flex items-center gap-1">
                    {col.header}
                    {col.sortable && sortKey === col.key && (
                      sortDir === 'asc' ? <ChevronUp size={12} /> : <ChevronDown size={12} />
                    )}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center">
                  {typeof emptyMessage === 'string' ? (
                    <div className="flex flex-col items-center gap-2">
                      <Inbox size={36} className="text-ivory-400" />
                      <span className="text-sm text-slate-400">{emptyMessage}</span>
                      {emptyAction && <div className="mt-2">{emptyAction}</div>}
                    </div>
                  ) : (
                    emptyMessage
                  )}
                </td>
              </tr>
            ) : (
              paginated.map((row, i) => (
                <tr
                  key={i}
                  onClick={() => onRowClick?.(row)}
                  tabIndex={onRowClick ? 0 : undefined}
                  onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRowClick(row) }} : undefined}
                  className={`transition-colors ${onRowClick ? 'cursor-pointer hover:bg-ivory-50 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-accent-500/30' : ''}`}
                >
                  {columns.map((col) => (
                    <td key={col.key} className={`table-cell ${col.className || ''}`}>
                      {col.render ? col.render(row) : String(row[col.key] ?? '')}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {usePagination ? (
        <div className="flex items-center justify-between text-xs text-slate-500">
          <span>
            Showing {(page - 1) * pageSize! + 1}–{Math.min(page * pageSize!, sorted.length)} of {sorted.length}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
              aria-label="Previous page"
              className="p-1.5 rounded btn-secondary disabled:opacity-40"
            >
              <ChevronLeft size={14} />
            </button>
            {(() => {
              const pages: (number | string)[] = []
              if (totalPages <= 7) {
                for (let i = 1; i <= totalPages; i++) pages.push(i)
              } else {
                pages.push(1)
                if (page > 3) pages.push('...')
                for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) pages.push(i)
                if (page < totalPages - 2) pages.push('...')
                pages.push(totalPages)
              }
              return pages.map((p, i) =>
                typeof p === 'string' ? (
                  <span key={`e${i}`} className="px-1 text-slate-300">...</span>
                ) : (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`px-2 py-1 rounded text-xs ${page === p ? 'bg-accent-600 text-white' : 'hover:bg-ivory-100 text-slate-600'}`}
                  >
                    {p}
                  </button>
                )
              )
            })()}
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              aria-label="Next page"
              className="p-1.5 rounded btn-secondary disabled:opacity-40"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      ) : sorted.length > 0 ? (
        <div className="text-xs text-slate-500">{sorted.length} result{sorted.length !== 1 ? 's' : ''}</div>
      ) : null}
    </div>
  )
}
