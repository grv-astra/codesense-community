type SubPhase = 'analyzing' | 'verifying';

interface PhaseStepperProps {
  subPhase: SubPhase;
  isCancelling: boolean;
}

const STEPS = [
  { key: 'uploaded', label: 'Uploaded' },
  { key: 'analyzing', label: 'Analyzing' },
  { key: 'verifying', label: 'Verifying findings' },
  { key: 'complete', label: 'Complete' },
] as const;

const ORDER = STEPS.map((s) => s.key);

function stepState(stepKey: string, subPhase: SubPhase): 'done' | 'current' | 'pending' {
  const currentIndex = ORDER.indexOf(subPhase);
  const stepIndex = ORDER.indexOf(stepKey);
  if (stepIndex < currentIndex) return 'done';
  if (stepIndex === currentIndex) return 'current';
  return 'pending';
}

export function PhaseStepper({ subPhase, isCancelling }: PhaseStepperProps) {
  return (
    <ol className="flex gap-2 mb-6 list-none" aria-label="Scan progress">
      {STEPS.map((step) => {
        const state = stepState(step.key, subPhase);
        const isCurrentAndCancelling = isCancelling && state === 'current';
        const label = isCurrentAndCancelling ? 'Cancelling…' : step.label;
        const stateClass =
          state === 'done'
            ? 'bg-green-600/10 text-green-600'
            : state === 'current'
            ? isCurrentAndCancelling
              ? 'bg-amber-600/10 text-amber-600 ring-2 ring-amber-600 ring-inset'
              : 'bg-[#bf0000]/10 text-[#bf0000] ring-2 ring-[#bf0000] ring-inset'
            : 'bg-[#e5e5e5] dark:bg-[#2d2d2d]/50 text-gray-400';

        return (
          <li
            key={step.key}
            aria-current={state === 'current' ? 'step' : undefined}
            className={`flex-1 text-center px-3 py-2 rounded-lg text-xs font-semibold ${stateClass}`}
          >
            {state === 'done' ? `✓ ${step.label}` : label}
          </li>
        );
      })}
    </ol>
  );
}
