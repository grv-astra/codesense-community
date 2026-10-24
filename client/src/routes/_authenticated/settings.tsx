import AccessControlSystem from '@/components/update/access-control'
import AiSettings from '@/components/update/ai-settings'
import { Unauthorized } from '@/components/molecule/unauthorized'
import { useAuth } from '@/hooks/use-auth'
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/_authenticated/settings')({
  component: RouteComponent,
})

function RouteComponent() {
  const { user } = useAuth()
  const isAdmin = user?.role?.toLowerCase() === 'admin'
  // Both panels change workspace-wide settings and the server only lets admins save them.
  if (!isAdmin) {
    return (
      <Unauthorized
        variant="card"
        title="Settings"
        message="Workspace settings are managed by an administrator."
        showBackButton={false}
      />
    )
  }
  return (
    <div className="space-y-6">
      <AiSettings />
      <AccessControlSystem />
    </div>
  )
}
