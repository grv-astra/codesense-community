import Header from '@/components/molecule/header'
import Sidebar from '@/components/molecule/sidebar'
import LicenseBanner from '@/components/molecule/license-banner'
import { EditionBadge } from '@/components/molecule/edition-badge'
import { createFileRoute, Outlet } from '@tanstack/react-router'

export const Route = createFileRoute('/_authenticated')({
  component: RouteComponent,
})

// App shell as a CSS grid: one fixed-width sidebar column spanning both rows, a
// header row, and a scrolling content cell. Replaces a position:fixed sidebar +
// header with hand-matched ml-64 / left-64 / mt-16 offsets — the grid template
// is now the single place those dimensions live.
function RouteComponent() {
  return (
    <div className="grid h-screen grid-cols-[16rem_1fr] grid-rows-[4rem_1fr] overflow-hidden bg-background">
      <div className="row-span-2 min-h-0">
        <Sidebar />
      </div>

      <Header />

      {/* min-h-0 lets this cell shrink so its own overflow-y-auto engages instead
          of the grid stretching to fit the content. */}
      <div className="min-h-0 overflow-y-auto p-4">
        <div className="mb-2 flex flex-col items-start gap-2">
          <EditionBadge />
          <LicenseBanner />
        </div>
        <Outlet />
      </div>
    </div>
  )
}
