import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthorizationRequestService,
  type AuthorizationRequestResult,
} from './authorization-request.service.js';
import { IdpSessionAuthenticationService } from '../session/idp-session-authentication.service.js';
import { AuthorizationService } from './authorization.service.js';
import { AuthorizationCodeService } from './authorization-code.service.js';

describe('AuthorizationService M5.4/M5.5 ordering and trusted context', () => {
  const validate = vi.fn<AuthorizationRequestService['validate']>();
  const authenticate = vi.fn<IdpSessionAuthenticationService['authenticate']>();
  const issue = vi.fn<AuthorizationCodeService['issue']>();
  const service = new AuthorizationService(
    { validate },
    { authenticate },
    { issue },
  );
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
    issue.mockResolvedValue({ code: 'transient-test-code' });
    authenticate.mockResolvedValue({
      sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
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
      authorizationCode: 'transient-test-code',
      session: {
        sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
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
    expect(authenticate.mock.invocationCallOrder[0]).toBeLessThan(
      issue.mock.invocationCallOrder[0],
    );
    expect(issue).toHaveBeenCalledExactlyOnceWith({
      clientId: 'student-spa',
      userId: 'trusted-user',
      sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
      redirectUri: validated.request.redirect_uri,
      grantedScopes: validated.grantedScopes,
      codeChallenge: null,
      nonce: null,
      authTime: 1,
    });
  });
  it.each([
    'invalid_request',
    'unsupported_response_type',
    'invalid_scope',
  ] as const)('does not authenticate/touch after %s', async (error) => {
    validate.mockResolvedValue({ ok: false, error });
    expect(await service.authorize({}, 'cookie')).toEqual({ ok: false, error });
    expect(authenticate).not.toHaveBeenCalled();
    expect(issue).not.toHaveBeenCalled();
  });
  it('does not touch after an operational OAuth failure', async () => {
    validate.mockRejectedValue(new Error('private driver cause'));
    await expect(service.authorize({}, 'cookie')).rejects.toEqual(
      new Error('Authorization request failed.'),
    );
    expect(authenticate).not.toHaveBeenCalled();
    expect(issue).not.toHaveBeenCalled();
  });
  it('returns authentication_required for a valid request without a central session', async () => {
    authenticate.mockResolvedValue(null);
    expect(await service.authorize({}, undefined)).toEqual({
      ok: false,
      error: 'authentication_required',
    });
    expect(issue).not.toHaveBeenCalled();
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
    expect(issue).not.toHaveBeenCalled();
  });
  it('preserves grants/PKCE/nonce and captures the same trusted sessionId/authTime, never query authority', async () => {
    const request = {
      ...validated.request,
      client_id: 'untrusted-re-read',
      nonce: 'opaque',
      code_challenge: 'A'.repeat(43),
    };
    validate.mockResolvedValue({
      ...validated,
      request,
      grantedScopes: ['profile', 'openid', 'email'],
    });
    await service.authorize({ userId: 'attacker', authTime: 999 }, 'cookie');
    expect(issue).toHaveBeenCalledExactlyOnceWith({
      clientId: validated.client.clientId,
      userId: 'trusted-user',
      sessionId: 'd4d7b5ef-d0a0-4c59-9fc4-70dd7773a9f3',
      redirectUri: request.redirect_uri,
      grantedScopes: ['profile', 'openid', 'email'],
      codeChallenge: request.code_challenge,
      nonce: request.nonce,
      authTime: 1,
    });
  });
  it('sanitizes code persistence failure and never returns a partial success', async () => {
    issue.mockRejectedValue(
      new Error('private code/hash/key/state', {
        cause: new Error('private driver cause'),
      }),
    );
    const failure: unknown = await service
      .authorize({}, 'cookie')
      .catch((error: unknown) => error);
    expect(failure).toEqual(new Error('Authorization request failed.'));
    expect(failure).not.toHaveProperty('cause');
    expect(issue).toHaveBeenCalledOnce();
  });
});
