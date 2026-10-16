import AccessControlSystem from '@/components/update/access-control'
import AiSettings from '@/components/update/ai-settings'
import { useAuth } from '@/hooks/use-auth'
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/_authenticated/settings')({
  component: RouteComponent,
})

function RouteComponent() {
  const { user } = useAuth()
  const isAdmin = user?.role?.toLowerCase() === 'admin'
  return (
    <div className="space-y-6">
      {isAdmin && <AiSettings />}
      <AccessControlSystem />
    </div>
  )
}
