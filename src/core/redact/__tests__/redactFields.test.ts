import { describe, it, expect } from 'vitest';
import { redactFields } from '../redactFields';

describe('redactFields', () => {
  it('redacts top-level exact-match keys', () => {
    const input = { email: 'a@b.com', password: 'hunter2', name: 'Ada' };
    const result = redactFields(input, { fields: ['password'] });
    expect(result).toEqual({ email: 'a@b.com', password: '[REDACTED]', name: 'Ada' });
  });

  it('recurses into nested objects by default', () => {
    const input = { user: { name: 'Ada', password: 'hunter2' } };
    const result = redactFields(input, { fields: ['password'] });
    expect(result).toEqual({ user: { name: 'Ada', password: '[REDACTED]' } });
  });

  it('does not descend into nested objects when recurse is false', () => {
    const input = { password: 'top', user: { password: 'nested' } };
    const result = redactFields(input, { fields: ['password'], recurse: false });
    expect(result).toEqual({ password: '[REDACTED]', user: { password: 'nested' } });
  });

  it('traverses arrays of objects', () => {
    const input = {
      users: [
        { name: 'Ada', password: 'p1' },
        { name: 'Bo', password: 'p2' },
      ],
    };
    const result = redactFields(input, { fields: ['password'] });
    expect(result).toEqual({
      users: [
        { name: 'Ada', password: '[REDACTED]' },
        { name: 'Bo', password: '[REDACTED]' },
      ],
    });
  });

  it('is cycle-safe', () => {
    type Cyclic = { name: string; password: string; self?: Cyclic };
    const input: Cyclic = { name: 'Ada', password: 'hunter2' };
    input.self = input;

    let result!: Cyclic;
    expect(() => {
      result = redactFields(input, { fields: ['password'] });
    }).not.toThrow();

    expect(result.password).toBe('[REDACTED]');
    expect(result.self).toBeUndefined();
  });

  it('does not mutate the input', () => {
    const input = { user: { password: 'hunter2' } };
    const snapshot = JSON.parse(JSON.stringify(input));
    redactFields(input, { fields: ['password'] });
    expect(input).toEqual(snapshot);
  });

  it('returns a deep copy, not the same reference', () => {
    const input = { user: { name: 'Ada' } };
    const result = redactFields(input, { fields: ['password'] });
    expect(result).toEqual(input);
    expect(result).not.toBe(input);
    expect(result.user).not.toBe(input.user);
  });

  it('passes non-object values through unchanged', () => {
    expect(redactFields('hello', { fields: ['password'] })).toBe('hello');
    expect(redactFields(42, { fields: ['password'] })).toBe(42);
    expect(redactFields(null, { fields: ['password'] })).toBeNull();
    expect(redactFields(undefined, { fields: ['password'] })).toBeUndefined();
  });

  it('honors a custom placeholder', () => {
    const result = redactFields({ password: 'hunter2' }, { fields: ['password'], placeholder: '***' });
    expect(result).toEqual({ password: '***' });
  });

  it('fails closed: a hostile throwing getter never leaks the unredacted input', () => {
    const hostile = { safe: 1 };
    Object.defineProperty(hostile, 'password', {
      enumerable: true,
      get() {
        throw new Error('boom');
      },
    });

    const result = redactFields(hostile, { fields: ['password'], placeholder: '[REDACTED]' });

    // Must NOT return the original object (which would expose the throwing
    // secret-bearing field to a log sink). Fails closed to the placeholder.
    expect(result).not.toBe(hostile);
    expect(result).toBe('[REDACTED]');
  });
});
