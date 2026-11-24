import { useCallback, useEffect, useState } from 'react';
import { isTauri } from '@tauri-apps/api/core';
import { activationService } from '@/services/activation.service';

export type ActivationState =
  | { status: 'checking' }
  // The backend has not answered for ~20 s. Says nothing about activation, so the
  // activation screen must NOT be shown; keep polling until it answers.
  | { status: 'unreachable' }
  | { status: 'not_required' }
  | { status: 'locked' }
  | { status: 'unlocked' };

const MAX_RETRIES = 20;
const RETRY_DELAY_MS = 1000;
// After the quick retries, keep going at a gentler pace for as long as the screen is open
// (a slow first start, security software scanning the app, ...).
const SLOW_RETRY_DELAY_MS = 3000;

/**
 * @param ready Only start checking once true. main.rs spawns the backend
 * AFTER asset setup finishes, so checking before that is guaranteed to hit
 * a not-yet-listening backend -- pass e.g. `assetSetup.status === 'ready'`.
 */
export function useActivation(ready: boolean) {
  const [state, setState] = useState<ActivationState>({ status: 'checking' });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const check = useCallback(() => {
    // The web build (this repo's primary target) has no baked activation
    // password at all -- only a packaged desktop build can opt into the
    // gate (see main.rs::ACTIVATION_PASSWORD_HASH).
    if (!isTauri()) {
      setState({ status: 'not_required' });
      return () => {};
    }

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const attempt = (retriesLeft: number) => {
      if (cancelled) return;
      activationService.getStatus()
        .then(({ configured, activated }) => {
          if (cancelled) return;
          setState({ status: !configured || activated ? 'unlocked' : 'locked' });
        })
        .catch(() => {
          if (cancelled) return;
          // A failed request here means the backend is not answering (still
          // starting, slow, or blocked) -- NOT "not activated". The activation
          // screen is only for a definitive answer from the backend, otherwise a
          // slow or blocked backend looks like a licence problem and the password
          // form could not reach it anyway. Retry quickly at first, then keep
          // polling slowly while showing a "taking longer" note.
          if (retriesLeft > 0) {
            timer = setTimeout(() => attempt(retriesLeft - 1), RETRY_DELAY_MS);
          } else {
            setState((s) => (s.status === 'unreachable' ? s : { status: 'unreachable' }));
            timer = setTimeout(() => attempt(0), SLOW_RETRY_DELAY_MS);
          }
        });
    };
    attempt(MAX_RETRIES);

    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, []);

  useEffect(() => {
    if (!ready) return;
    return check();
  }, [ready, check]);

  const submit = useCallback((password: string) => {
    setSubmitting(true);
    setError(null);
    activationService.activate(password)
      .then(({ activated }) => {
        if (activated) {
          setState({ status: 'unlocked' });
        } else {
          setError('Incorrect activation password.');
        }
      })
      .catch((err) => {
        // No response at all = the backend could not be reached; that is not a wrong password.
        if (!err?.response) {
          setError('Could not reach Code Sense. Please wait a moment and try again.');
          return;
        }
        const detail = err.response.data?.detail;
        setError(typeof detail === 'string' ? detail : 'Incorrect activation password.');
      })
      .finally(() => setSubmitting(false));
  }, []);

  return { state, error, submitting, submit };
}
