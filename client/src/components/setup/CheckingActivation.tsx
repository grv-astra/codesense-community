import { DotsLoader } from '@/components/atomic/loader';

// Shown for the brief window between assets being ready and the one-time
// activation check resolving. Previously rendered nothing at all here (to
// avoid a login-page flash), which looked like a hung/broken blank gray
// screen -- same dark shell + card as FirstRunSetup so it reads as "still
// starting up" rather than "something crashed".
//
// `slow` is set once the background service has not answered for ~20 s. It is NOT
// the activation screen: an unreachable service says nothing about activation, so
// we keep waiting (the hook keeps polling) instead of asking for a password that
// the same unreachable service could not accept anyway.
export function CheckingActivation({ slow = false }: { slow?: boolean }) {
  return (
    <div className="min-h-screen flex items-center justify-center p-4" style={{ backgroundColor: '#2D2D2D' }}>
      <div className="w-full max-w-md rounded-2xl bg-white text-black shadow-2xl overflow-hidden px-8 py-10 text-center space-y-4">
        <div className="h-10">
          <DotsLoader />
        </div>
        <p className="text-sm text-gray-600">Starting Code Sense…</p>
        {slow && (
          <p className="text-xs text-gray-500">
            This is taking longer than usual. It will continue by itself once Code Sense is ready.
            If nothing changes after a few minutes, close and reopen the app, or contact support.
          </p>
        )}
      </div>
    </div>
  );
}
