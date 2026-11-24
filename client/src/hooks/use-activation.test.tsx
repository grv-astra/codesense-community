import { renderHook, act } from '@testing-library/react';
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest';

const getStatus = vi.fn();
const activate = vi.fn();

vi.mock('@/services/activation.service', () => ({
  activationService: {
    getStatus: (...args: unknown[]) => getStatus(...args),
    activate: (...args: unknown[]) => activate(...args),
  },
}));

const isTauri = vi.fn(() => true);
vi.mock('@tauri-apps/api/core', () => ({
  isTauri: () => isTauri(),
}));

import { useActivation } from './use-activation';

// waitFor's internal polling doesn't play well with fake timers here, so
// tests advance fake timers explicitly, wrapped in act() so the resulting
// state updates are flushed into `result.current` before assertions run.
const flush = (ms = 0) => act(async () => {
  await vi.advanceTimersByTimeAsync(ms);
});

describe('useActivation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isTauri.mockReturnValue(true);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('does not check until ready=true', async () => {
    const { result, rerender } = renderHook(({ ready }) => useActivation(ready), {
      initialProps: { ready: false },
    });
    await flush();
    expect(getStatus).not.toHaveBeenCalled();
    expect(result.current.state.status).toBe('checking');

    getStatus.mockResolvedValue({ configured: true, activated: true });
    rerender({ ready: true });
    await flush();
    expect(getStatus).toHaveBeenCalledTimes(1);
    expect(result.current.state.status).toBe('unlocked');
  });

  test('retries on failure instead of immediately locking (avoids the backend-not-up-yet false negative)', async () => {
    getStatus
      .mockRejectedValueOnce(new Error('connection refused'))
      .mockRejectedValueOnce(new Error('connection refused'))
      .mockResolvedValueOnce({ configured: true, activated: true });

    const { result } = renderHook(() => useActivation(true));

    await flush();
    expect(result.current.state.status).toBe('checking'); // first failure: still checking, not locked

    await flush(1000);
    await flush(1000);
    expect(result.current.state.status).toBe('unlocked');
    expect(getStatus).toHaveBeenCalledTimes(3);
  });

  test('an unreachable backend never shows the activation screen: it becomes "unreachable"', async () => {
    getStatus.mockRejectedValue(new Error('connection refused'));
    const { result } = renderHook(() => useActivation(true));

    await flush();
    expect(result.current.state.status).toBe('checking');

    // 20 retries * 1000ms -- run them all out.
    await flush(21 * 1000);
    expect(result.current.state.status).toBe('unreachable');
    expect(result.current.state.status).not.toBe('locked');
  });

  test('keeps polling after the quick retries and unlocks when the backend finally answers', async () => {
    getStatus.mockRejectedValue(new Error('connection refused'));
    const { result } = renderHook(() => useActivation(true));
    await flush(21 * 1000);
    expect(result.current.state.status).toBe('unreachable');

    const callsSoFar = getStatus.mock.calls.length;
    await flush(3000); // slow cadence: one more attempt per 3 s
    expect(getStatus.mock.calls.length).toBe(callsSoFar + 1);

    getStatus.mockResolvedValue({ configured: true, activated: true });
    await flush(3000);
    expect(result.current.state.status).toBe('unlocked');
  });

  test('a late definitive "not activated" answer still locks', async () => {
    getStatus.mockRejectedValue(new Error('connection refused'));
    const { result } = renderHook(() => useActivation(true));
    await flush(21 * 1000);
    expect(result.current.state.status).toBe('unreachable');

    getStatus.mockResolvedValue({ configured: true, activated: false });
    await flush(3000);
    expect(result.current.state.status).toBe('locked');
  });

  test('stops polling when unmounted', async () => {
    getStatus.mockRejectedValue(new Error('connection refused'));
    const { unmount } = renderHook(() => useActivation(true));
    await flush(21 * 1000);
    unmount();
    const calls = getStatus.mock.calls.length;
    await flush(30 * 1000);
    expect(getStatus.mock.calls.length).toBe(calls);
  });

  test('submit: no response from the backend is reported as unreachable, not as a wrong password', async () => {
    getStatus.mockResolvedValue({ configured: true, activated: false });
    activate.mockRejectedValue(new Error('Network Error')); // axios error without .response
    const { result } = renderHook(() => useActivation(true));
    await flush();
    act(() => { result.current.submit('whatever'); });
    await flush();
    expect(result.current.error).toMatch(/could not reach/i);
  });

  test('submit: a rejected password keeps the incorrect-password message', async () => {
    getStatus.mockResolvedValue({ configured: true, activated: false });
    activate.mockRejectedValue({ response: { status: 403, data: {} } });
    const { result } = renderHook(() => useActivation(true));
    await flush();
    act(() => { result.current.submit('nope'); });
    await flush();
    expect(result.current.error).toBe('Incorrect activation password.');
  });

  test('unlocked immediately when the first check succeeds and is activated', async () => {
    getStatus.mockResolvedValue({ configured: true, activated: true });
    const { result } = renderHook(() => useActivation(true));
    await flush();
    expect(result.current.state.status).toBe('unlocked');
    expect(getStatus).toHaveBeenCalledTimes(1);
  });

  test('locked when configured and not yet activated (a real, definitive answer)', async () => {
    getStatus.mockResolvedValue({ configured: true, activated: false });
    const { result } = renderHook(() => useActivation(true));
    await flush();
    expect(result.current.state.status).toBe('locked');
  });

  test('not_required on the web build (not Tauri)', async () => {
    isTauri.mockReturnValue(false);
    const { result } = renderHook(() => useActivation(true));
    await flush();
    expect(result.current.state.status).toBe('not_required');
    expect(getStatus).not.toHaveBeenCalled();
  });
});
