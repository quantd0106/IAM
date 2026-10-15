import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthorizationRequestService,
  type AuthorizationRequestResult,
} from './authorization-request.service.js';
import { IdpSessionAuthenticationService } from '../session/idp-session-authentication.service.js';
import { AuthorizationService } from './authorization.service.js';

describe('AuthorizationService M5.4 ordering and trusted transient subject', () => {
  const validate = vi.fn<AuthorizationRequestService['validate']>();
  const authenticate = vi.fn<IdpSessionAuthenticationService['authenticate']>();
  const service = new AuthorizationService({ validate }, { authenticate });
  const validated: Extract<AuthorizationRequestResult, { ok: true }> = {
    ok: true,
    client: {
      id: 'internal',
      clientId: 'student-spa',
      name: 'Student SPA',
      clientType: 'PUBLIC',
      accessTokenTtl: 600,
      refreshTokenTtl: 2592000,
      redirectUris: ['http://localhost:3200/callback'],
    },
    request: {
      response_type: 'code',
      client_id: 'student-spa',
      redirect_uri: 'http://localhost:3200/callback',
      scope: ['profile'],
      state: 'opaque',
    },
    grantedScopes: ['profile'],
  };
  const state = {
    userId: 'trusted-user',
    authTime: 1,
    mfaLevel: 'password',
    createdAt: 1,
    lastActivityAt: 2,
    absoluteExpiresAt: 100,
  };
  beforeEach(() => {
    vi.resetAllMocks();
    validate.mockResolvedValue(validated);
    authenticate.mockResolvedValue({
      sessionId: 'trusted-session',
      userId: state.userId,
      authTime: 1,
      mfaLevel: 'password',
      state,
      now: new Date(2),
    });
  });
  it('validates OAuth first, then takes subject only from central session', async () => {
    const query = {
      userId: 'attacker',
      sessionId: 'attacker',
      state: 'attacker',
    };
    expect(await service.authorize(query, 'configured-cookie')).toEqual({
      ...validated,
      session: {
        sessionId: 'trusted-session',
        userId: 'trusted-user',
        authTime: 1,
        mfaLevel: 'password',
      },
    });
    expect(validate).toHaveBeenCalledExactlyOnceWith(query);
    expect(authenticate).toHaveBeenCalledExactlyOnceWith('configured-cookie');
    expect(validate.mock.invocationCallOrder[0]).toBeLessThan(
      authenticate.mock.invocationCallOrder[0],
    );
  });
  it.each([
    'invalid_request',
    'unsupported_response_type',
    'invalid_scope',
  ] as const)('does not authenticate/touch after %s', async (error) => {
    validate.mockResolvedValue({ ok: false, error });
    expect(await service.authorize({}, 'cookie')).toEqual({ ok: false, error });
    expect(authenticate).not.toHaveBeenCalled();
  });
  it('does not touch after an operational OAuth failure', async () => {
    validate.mockRejectedValue(new Error('private driver cause'));
    await expect(service.authorize({}, 'cookie')).rejects.toEqual(
      new Error('Authorization request failed.'),
    );
    expect(authenticate).not.toHaveBeenCalled();
  });
  it('returns authentication_required for a valid request without a central session', async () => {
    authenticate.mockResolvedValue(null);
    expect(await service.authorize({}, undefined)).toEqual({
      ok: false,
      error: 'authentication_required',
    });
  });
  it('keeps session infrastructure failures separate from unauthenticated results', async () => {
    authenticate.mockRejectedValue(
      new Error('private session/cookie/SQL', {
        cause: new Error('private cause'),
      }),
    );
    const error: unknown = await service
      .authorize({}, 'private-cookie')
      .catch((value: unknown) => value);
    expect(error).toEqual(new Error('Authorization request failed.'));
    expect(error).not.toHaveProperty('cause');
    expect((error as Error).stack).not.toContain('private');
  });
});
