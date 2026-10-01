import { memo, useCallback, useMemo, useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/atomic/card';
import { Button } from '@/components/atomic/button';
import { ChevronLeft, ChevronRight, Filter, Search, X } from 'lucide-react';
import { DotsLoader } from '../atomic/loader';

// Generic table column definition
export interface TableColumn<T> {
  key: keyof T | string;
  header: string;
  render?: (item: T, index: number) => React.ReactNode;
  sortable?: boolean;
  width?: string;
  hideable?: boolean; // Whether this column can be hidden
}

// Pagination configuration
export interface PaginationConfig {
  enabled: boolean;
  pageSize: number;
  showInfo?: boolean;
  showPageNumbers?: boolean;
}

// Table props interface
export interface GenericTableProps<T> {
  data: T[];
  columns: TableColumn<T>[];
  title?: string;
  loading?: boolean;
  error?: string | null;
  pagination?: PaginationConfig;
  totalItems?: number; // For server-side pagination
  currentPage?: number;
  onPageChange?: (page: number) => void;
  emptyMessage?: string;
  className?: string;
  tableClassName?: string;
  headerClassName?: string;
  rowClassName?: string | ((item: T, index: number) => string);
  onRowClick?: (item: T, index: number) => void;
  enableColumnFilter?: boolean; // Enable column filtering feature
  filterButtonVariant?: 'default' | 'outline' | 'ghost';
  filterButtonClassName?: string;
  searchable?: boolean;          // Show a search box that filters across the table's columns
  searchPlaceholder?: string;
  // When provided, search is SERVER-SIDE: the (debounced) query is handed back to
  // the parent (which refetches) instead of filtering the loaded rows client-side.
  onSearchChange?: (query: string) => void;
  // Seeds the (uncontrolled) search box, e.g. restoring a query persisted in the URL.
  initialQuery?: string;
}

const columnKey = <T,>(col: TableColumn<T>) => col.key.toString();

// Walk a possibly-dotted key ('user.name') down an item.
function readCell<T>(item: T, key: string): unknown {
  let value: unknown = item;
  for (const part of key.split('.')) {
    value = value == null ? undefined : (value as Record<string, unknown>)[part];
  }
  return value;
}

// Per-column show/hide state, seeded to all-visible from the current columns.
function useColumnVisibility<T>(columns: TableColumn<T>[]) {
  const [visibility, setVisibility] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(columns.map((col) => [columnKey(col), true])),
  );

  const toggle = useCallback((key: string) => {
    setVisibility((prev) => ({ ...prev, [key]: !(prev[key] ?? true) }));
  }, []);

  const visibleColumns = useMemo(
    () => columns.filter((col) => visibility[columnKey(col)] ?? true),
    [columns, visibility],
  );

  return { visibility, toggle, visibleColumns };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- generic row shape; callers pass their own concrete T
function GenericTableInner<T extends Record<string, any>>({
  data,
  columns,
  title,
  loading = false,
  error = null,
  pagination = { enabled: false, pageSize: 10, showInfo: true, showPageNumbers: true },
  totalItems,
  currentPage: controlledCurrentPage,
  onPageChange,
  emptyMessage = "No data available",
  className = "",
  tableClassName = "",
  headerClassName = "bg-secondary",
  rowClassName = "hover:bg-gray-50",
  onRowClick,
  enableColumnFilter = false,
  filterButtonVariant = 'outline',
  filterButtonClassName = '',
  searchable = true,
  searchPlaceholder = 'Search...',
  onSearchChange,
  initialQuery = '',
}: GenericTableProps<T>) {
  const [internalCurrentPage, setInternalCurrentPage] = useState(1);
  const [query, setQuery] = useState(initialQuery);
  const [showColumnSelector, setShowColumnSelector] = useState(false);
  const { visibility, toggle: toggleColumn, visibleColumns } = useColumnVisibility(columns);

  // Use controlled or internal pagination
  const currentPage = controlledCurrentPage || internalCurrentPage;
  const isServerSidePagination = totalItems !== undefined && onPageChange !== undefined;

  // --- Search ---
  // Server mode (onSearchChange provided): hand the debounced query to the parent
  // and render whatever it returns (no client filtering, pagination stays on).
  // Client mode: filter the loaded rows across every column's underlying value.
  const serverMode = typeof onSearchChange === 'function';
  const clientSearching = searchable && !serverMode && query.trim() !== '';
  const q = query.trim().toLowerCase();

  const baseData = useMemo(() => {
    if (!clientSearching) return data;
    return data.filter((item) =>
      columns.some((col) => {
        const v = readCell(item, columnKey(col));
        return v != null && String(v).toLowerCase().includes(q);
      }),
    );
  }, [clientSearching, data, columns, q]);

  // Server mode: emit ONLY on explicit submit (Search button / Enter), never
  // while typing, so each keystroke doesn't trigger a backend fetch.
  const submitServerSearch = useCallback(() => {
    if (serverMode) onSearchChange?.(query.trim());
  }, [serverMode, onSearchChange, query]);
  const clearSearch = useCallback(() => {
    setQuery('');
    if (serverMode) onSearchChange?.('');
  }, [serverMode, onSearchChange]);

  // Calculate pagination values (client search shows all matches, bypassing paging)
  const total = clientSearching ? baseData.length : (isServerSidePagination ? totalItems : data.length);
  const totalPages = Math.ceil(total / pagination.pageSize);

  // Get current page data (for client-side pagination)
  const currentData = useMemo(() => {
    if (clientSearching) return baseData; // show all matches across the loaded rows
    if (!pagination.enabled || isServerSidePagination) return data;
    const startIndex = (currentPage - 1) * pagination.pageSize;
    return data.slice(startIndex, startIndex + pagination.pageSize);
  }, [clientSearching, baseData, data, pagination.enabled, pagination.pageSize, isServerSidePagination, currentPage]);

  // Pagination handlers
  const goToPage = useCallback((page: number) => {
    if (page < 1 || page > totalPages) return;
    if (onPageChange) onPageChange(page);
    else setInternalCurrentPage(page);
  }, [totalPages, onPageChange]);

  // Calculate display indices
  const { start, end } = useMemo(() => {
    if (isServerSidePagination) {
      const s = (currentPage - 1) * pagination.pageSize;
      return { start: s + 1, end: Math.min(s + pagination.pageSize, total) };
    }
    const s = pagination.enabled ? (currentPage - 1) * pagination.pageSize : 0;
    const e = pagination.enabled ? Math.min(s + pagination.pageSize, total) : total;
    return { start: s + 1, end: e };
  }, [isServerSidePagination, currentPage, pagination.enabled, pagination.pageSize, total]);

  // Render cell content
  const renderCell = (item: T, column: TableColumn<T>, index: number) => {
    if (column.render) return column.render(item, index);
    const value = readCell(item, columnKey(column));
    return value?.toString() || '';
  };

  if (loading) {
    return (
      <Card className={className}>
        <CardHeader>
          {title && <h2 className="text-3xl font-bold">{title}</h2>}
        </CardHeader>
        <CardContent>
          <DotsLoader />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card className={className}>
        <CardHeader>
          {title && <h2 className="text-3xl font-bold">{title}</h2>}
        </CardHeader>
        <CardContent>
          <div className="flex justify-center items-center py-8">
            <div className="text-primary-950 dark:text-primary-300">Error: {error}</div>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={className}>
      <CardHeader>
        <div className="flex justify-between items-center gap-3 flex-wrap">
          {title && <h2 className="text-3xl font-bold">{title}</h2>}

          <div className="flex items-center gap-2 ml-auto">
          {/* Search box */}
          {searchable && (
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') submitServerSearch(); }}
                  placeholder={searchPlaceholder}
                  aria-label={searchPlaceholder}
                  className="pl-8 pr-8 py-2 text-sm rounded-lg border w-56
                    text-[#2d2d2d] dark:text-[#e5e5e5] bg-white dark:bg-[#2d2d2d]
                    border-[#e5e5e5] dark:border-[#444]
                    focus:outline-none focus:ring-2 focus:ring-[#bf0000]/40"
                />
                {query && (
                  <button
                    type="button"
                    onClick={clearSearch}
                    aria-label="Clear search"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
              {serverMode && (
                <Button
                  variant="outline"
                  onClick={submitServerSearch}
                  className="flex items-center gap-1.5"
                >
                  <Search className="w-4 h-4" />
                  Search
                </Button>
              )}
            </div>
          )}

          {/* Column Filter Button */}
          {enableColumnFilter && (
            <div className="relative">
              <Button
                variant={filterButtonVariant}
                onClick={() => setShowColumnSelector(!showColumnSelector)}
                className={`flex items-center gap-2 ${filterButtonClassName}`}
                aria-expanded={showColumnSelector}
              >
                <Filter className="w-4 h-4" />
                Customize Columns
              </Button>

              {/* Column Selector Dropdown */}
              {showColumnSelector && (
                <>
                  {/* Backdrop to close dropdown when clicking outside */}
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setShowColumnSelector(false)}
                  />

                  <div className="absolute right-0 mt-2 w-64 bg-card text-card-foreground rounded-lg shadow-xl border z-20 overflow-x-auto h-72">
                    <div className="p-4">
                      <h3 className="font-semibold mb-3">Select Columns</h3>
                      <div className="space-y-2">
                        {columns.map((column) => (
                          <label
                            key={columnKey(column)}
                            className="flex items-center gap-3 py-2 hover:bg-muted-foreground/10 rounded px-2 cursor-pointer"
                          >
                            <input
                              type="checkbox"
                              checked={visibility[columnKey(column)] ?? true}
                              onChange={() => toggleColumn(columnKey(column))}
                              className="w-4 h-4 text-red-600 rounded accent-[#bf0000] cursor-pointer"
                            />
                            <span className="text-sm">{column.header}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
          </div>
        </div>
      </CardHeader>

      <CardContent>
        <div className="shadow-md overflow-x-auto">
          <table className={`w-full text-left border rounded-lg ${tableClassName}`}>
            <thead className={headerClassName}>
              <tr>
                {visibleColumns.map((column, index) => (
                  <th
                    key={index}
                    className="px-4 py-3 border-b"
                    style={{ width: column.width }}
                  >
                    {column.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {currentData.length === 0 ? (
                <tr>
                  <td colSpan={visibleColumns.length} className="px-4 py-8 text-center">
                    {emptyMessage}
                  </td>
                </tr>
              ) : (
                currentData.map((item, index) => {
                  const actualIndex = pagination.enabled && !isServerSidePagination
                    ? (currentPage - 1) * pagination.pageSize + index
                    : index;

                  const rowClass = typeof rowClassName === 'function'
                    ? rowClassName(item, actualIndex)
                    : rowClassName;

                  return (
                    <tr
                      key={item.id || item._id || index}
                      className={`${rowClass} ${onRowClick ? 'cursor-pointer' : ''}`}
                      onClick={() => onRowClick?.(item, actualIndex)}
                    >
                      {visibleColumns.map((column, colIndex) => (
                        <td key={colIndex} className=" px-4 py-3 border-b">
                          {renderCell(item, column, actualIndex)}
                        </td>
                      ))}
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {pagination.enabled && totalPages > 1 && !clientSearching && (
          <TablePagination
            currentPage={currentPage}
            totalPages={totalPages}
            total={total}
            start={start}
            end={end}
            showInfo={pagination.showInfo}
            showPageNumbers={pagination.showPageNumbers}
            onGoToPage={goToPage}
          />
        )}
      </CardContent>
    </Card>
  );
}

interface TablePaginationProps {
  currentPage: number;
  totalPages: number;
  total: number;
  start: number;
  end: number;
  showInfo?: boolean;
  showPageNumbers?: boolean;
  onGoToPage: (page: number) => void;
}

// The windowed page-number strip: first page, up to 3 middle pages centred on the
// current page, last page, ellipses where the window is clipped.
function TablePagination({
  currentPage,
  totalPages,
  total,
  start,
  end,
  showInfo,
  showPageNumbers,
  onGoToPage,
}: TablePaginationProps) {
  const pageButton = (page: number, label: React.ReactNode = page) => (
    <Button
      key={page}
      onClick={() => onGoToPage(page)}
      className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
        currentPage === page
          ? 'bg-red-700 text-white border-[#bf0000]'
          : 'bg-white text-[#2d2d2d] dark:bg-[#3b3b3b] dark:text-[#e5e5e5] border-[#e5e5e5] dark:border-[#444] hover:bg-[#f8f9fa] dark:hover:bg-[#494949]'
      }`}
    >
      {label}
    </Button>
  );

  let middleStart = Math.max(2, currentPage - 1);
  let middleEnd = Math.min(totalPages - 1, currentPage + 1);
  if (currentPage <= 2) middleEnd = Math.min(4, totalPages - 1);
  else if (currentPage >= totalPages - 1) middleStart = Math.max(2, totalPages - 3);
  const middlePages: number[] = [];
  for (let i = middleStart; i <= middleEnd; i++) middlePages.push(i);

  return (
    <div className="flex justify-between items-center mt-6 flex-wrap gap-4">
      {showInfo && (
        <p className="text-sm text-gray-600 dark:text-[#e5e5e5]">
          Showing {start} to {end} of {total} entries
        </p>
      )}

      <div className="flex items-center space-x-2">
        <Button
          onClick={() => onGoToPage(currentPage - 1)}
          disabled={currentPage === 1}
          className="px-3 py-2 text-sm font-medium rounded-lg border disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-1 transition-colors
          text-[#2d2d2d] dark:text-[#e5e5e5] bg-white dark:bg-[#2d2d2d] border-[#e5e5e5] dark:border-[#444]
          hover:bg-[#f8f9fa] dark:hover:bg-[#3a3a3a]"
        >
          <ChevronLeft className="w-4 h-4" />
          <span>Previous</span>
        </Button>

        {showPageNumbers && (
          <div className="flex items-center space-x-1">
            {pageButton(1)}
            {currentPage > 3 && <span className="px-2 text-[#2d2d2d] dark:text-[#e5e5e5]">...</span>}
            {middlePages.map((i) => pageButton(i))}
            {currentPage < totalPages - 2 && <span className="px-2 text-[#2d2d2d] dark:text-[#e5e5e5]">...</span>}
            {totalPages > 1 && pageButton(totalPages)}
          </div>
        )}

        <Button
          onClick={() => onGoToPage(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="px-3 py-2 text-sm font-medium rounded-lg border disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-1
          bg-[#bf0000] text-white border-[#bf0000] hover:bg-[#a00000]"
        >
          <span>Next</span>
          <ChevronRight className="w-4 h-4" />
        </Button>
      </div>
    </div>
  );
}

// memo() erases the generic signature, so cast it back. Rerenders are skipped
// unless a prop identity changes — callers that pass inline `columns`/`data`
// literals still rerender, but memoised ones (the common case) don't.
export const GenericTable = memo(GenericTableInner) as typeof GenericTableInner;
