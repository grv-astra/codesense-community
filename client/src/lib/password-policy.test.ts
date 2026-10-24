import { describe, expect, it } from 'vitest';
import { passwordPolicyError } from './password-policy';

describe('passwordPolicyError', () => {
  it('accepts a password that meets every rule', () => {
    expect(passwordPolicyError('Str0ng!Pass0rd9')).toBeNull();
  });

  it('reports the first rule that fails, in the server order', () => {
    expect(passwordPolicyError('Ab1!')).toMatch(/at least 8 characters/);
    expect(passwordPolicyError('alllowercase1!')).toMatch(/uppercase/);
    expect(passwordPolicyError('ALLUPPERCASE1!')).toMatch(/lowercase/);
    expect(passwordPolicyError('NoDigitsHere!')).toMatch(/digit/);
    expect(passwordPolicyError('NoSpecial1234')).toMatch(/special character/);
  });

  it('counts exactly eight characters as long enough', () => {
    expect(passwordPolicyError('Abcdef1!')).toBeNull();
    expect(passwordPolicyError('Abcde1!')).toMatch(/at least 8 characters/);
  });
});
