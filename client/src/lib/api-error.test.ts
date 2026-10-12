import { AxiosError } from 'axios';
import { describe, expect, it } from 'vitest';

import { apiErrorMessage } from './api-error';

const axiosError = (data: unknown) =>
  new AxiosError('failed', 'ERR_BAD_REQUEST', undefined, undefined, {
    status: 403, statusText: 'Forbidden', headers: {}, config: {} as never, data,
  });

describe('apiErrorMessage', () => {
  it('returns the server error text', () => {
    const msg = 'Project limit reached for this edition (1). Upgrade to add more.';
    expect(apiErrorMessage(axiosError({ error: msg }), 'x')).toBe(msg);
  });

  it('falls back through detail then message, then the fallback', () => {
    expect(apiErrorMessage(axiosError({ detail: 'd' }), 'x')).toBe('d');
    expect(apiErrorMessage(axiosError({ message: 'm' }), 'x')).toBe('m');
    expect(apiErrorMessage(axiosError({}), 'fallback')).toBe('fallback');
    expect(apiErrorMessage(new Error('boom'), 'fallback')).toBe('fallback');
  });
});
