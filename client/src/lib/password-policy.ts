// Mirrors the server's validate_strong_password (local/auth_app/utils/password.py), which every
// account password has to pass. Keeping the same messages means the form says what the API would say.

export const PASSWORD_SPECIALS = '@$!%*?&';

export const PASSWORD_HINT =
  'At least 8 characters, with an uppercase letter, a lowercase letter, a digit and one of @ $ ! % * ? &';

export function passwordPolicyError(password: string): string | null {
  if (password.length < 8) return 'Password must be at least 8 characters long';
  if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase letter';
  if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase letter';
  if (!/[0-9]/.test(password)) return 'Password must contain at least one digit';
  if (!/[@$!%*?&]/.test(password)) {
    return 'Password must contain at least one special character (@, $, !, %, *, ?, &)';
  }
  return null;
}
