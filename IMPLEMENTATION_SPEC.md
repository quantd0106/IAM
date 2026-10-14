# IMPLEMENTATION_SPEC.md

This document is the **canonical implementation specification** for the Centralized IAM System.

If README examples differ from this file, this file wins.

---

## 1. Platform

```text
Node.js: 24 LTS (minimum 24.15.0)
Package manager: pnpm
Monorepo: pnpm workspaces
Backend: NestJS + TypeScript
ORM: Prisma ORM 7.x
Database: PostgreSQL
Ephemeral state: Redis 8.x, official node-redis client (`redis` package)
```

Applications:

```text
apps/identity-server
apps/banking-web
apps/banking-api
apps/student-spa
apps/student-api
apps/admin-portal
```

Frontend choices:

```text
Banking Web / BFF: Next.js
Admin Portal / BFF: Next.js
Student SPA: React + Vite
```

---

## 2. Local Development Defaults

Canonical local URLs:

```text
Identity Server: http://localhost:3000
Banking Web:     http://localhost:3100
Banking API:     http://localhost:3101
Student SPA:     http://localhost:3200
Student API:     http://localhost:3201
Admin Portal:    http://localhost:3300
```

Issuer:

```text
http://localhost:3000
```

Production issuer must be HTTPS and environment-configurable.

---

## 3. Client Registry

### Student SPA

```text
client_id: student-spa
type: public
client_secret: none
PKCE: required
PKCE method: S256
redirect_uri: http://localhost:3200/callback
```

### Banking Web / BFF

```text
client_id: banking-web
type: confidential
client authentication: client_secret_basic
PKCE: supported
redirect_uri: http://localhost:3100/auth/callback
```

### Admin Portal / BFF

```text
client_id: admin-portal
type: confidential
client authentication: client_secret_basic
redirect_uri: http://localhost:3300/auth/callback
```

Redirect URIs are matched **exactly**. No wildcard redirect URIs in MVP.

---

## 4. OAuth / OIDC Endpoints

```text
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke

GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /oidc/userinfo
```

---

## 5. Authorization Code Flow

Supported:

```text
response_type=code
grant_type=authorization_code
```

Not supported in MVP:

```text
implicit flow
resource owner password credentials
device authorization grant
client credentials as an end-user login replacement
```

Authorization request:

```text
response_type=code
client_id
redirect_uri
scope
state
nonce            # required when openid is requested
code_challenge   # required for public client
code_challenge_method=S256
```

Authorization code policy:

```text
TTL: 2 minutes
one-time: true
storage: Redis
```

Redis shape:

```text
oauth:code:{codeHash}

clientId
userId
redirectUri
grantedScopes
codeChallenge
nonce
authTime
expiresAt
```

Token endpoint must atomically consume authorization code state so it cannot be replayed.

---

## 6. PKCE

Supported method:

```text
S256
```

Rejected:

```text
plain
```

Calculation:

```text
code_challenge =
BASE64URL(SHA256(ASCII(code_verifier)))
```

Student SPA must generate a high-entropy `code_verifier`.

---

## 7. Confidential Client Authentication

Default:

```text
client_secret_basic
```

Client secret:

- generated using cryptographically secure randomness
- displayed only when created/rotated
- persisted as a secure password-style hash
- never stored plaintext
- never logged

Public clients never receive or send a client secret.

---

## 8. JWT Signing

Algorithm:

```text
RS256
```

Signing key policy:

- private key only in Identity Server
- public key exposed via JWKS
- every signing key has `kid`
- access token and ID Token include matching `kid`
- use established JOSE/JWT libraries
- do not implement RSA/JWS manually

---

## 9. Access Token

Format:

```text
JWT
```

TTL:

```text
10 minutes
```

Canonical claims:

```json
{
  "iss": "http://localhost:3000",
  "sub": "<user-id>",
  "aud": "<resource-api-audience>",
  "iat": 0,
  "exp": 0,
  "scope": "openid banking.transactions.read",
  "roles": ["BANK_EMPLOYEE"],
  "permissions": ["transaction.view"]
}
```

Rules:

- `scope` is a space-delimited string
- `roles` is an array
- `permissions` is an array
- do not put secrets or sensitive internal metadata in tokens

Resource APIs validate locally:

```text
signature
kid/JWKS
iss
aud
exp
scope
permission
```

---

## 10. ID Token

Algorithm:

```text
RS256
```

Required claims:

```text
iss
sub
aud
iat
exp
nonce
```

Do not use ID Token as a resource API access token.

---

## 11. Refresh Token

Format:

```text
opaque token
```

Entropy:

```text
256 bits
```

TTL:

```text
30 days
```

Persistence:

```text
SHA-256(raw_refresh_token)
```

Store metadata:

```text
id
family_id
token_hash
parent_token_id
client_id
user_id
session_id
status
issued_at
expires_at
consumed_at
revoked_at
```

Never persist raw refresh token.

---

## 12. Refresh Token Rotation

For every successful refresh:

```text
RT1 -> consume RT1 -> create RT2
```

The transition must be atomic in a PostgreSQL transaction.

Required property:

```text
Only one concurrent request may successfully consume RT1.
```

If an already-consumed refresh token is presented:

```text
1. detect reuse
2. revoke token family
3. revoke related IdP session
4. write audit event
5. return invalid_grant
```

Do not issue a new token after reuse detection.

---

## 13. Token Revocation

Endpoint:

```text
POST /oauth/revoke
```

MVP behavior:

- refresh-token revocation supported
- revoke the relevant token/family according to policy
- idempotent from caller perspective
- never reveal whether an arbitrary token belonged to another user/client

---

## 14. Central IdP Session

Persistent PostgreSQL baseline: `Session` maps to `sessions`, has a Prisma-generated
UUID primary key and a required UUID `user_id` foreign key to User. One User may
have many Sessions; `user_id` is indexed, not unique. SessionStatus contains only
`ACTIVE` (default) and `REVOKED`. `ip_address` and `user_agent` are optional string
metadata. `created_at` and `last_activity_at` default to now; last activity changes
only through an explicit update, not `@updatedAt`. Required `expires_at` has no
default and represents the absolute expiry boundary supplied by a later creator.
The relation uses Prisma's default delete behavior; no account-deletion policy is
introduced.

This persistent record is not the Redis runtime session. M3.1 adds only persistence;
M3.2 adds only the Redis runtime create/read/touch service below. M3.2 does not
write PostgreSQL, including Session.lastActivityAt. Cookies belong to M3.3 and
login integration to M3.4; no session HTTP API is added by M3.2.

Runtime store:

```text
Redis
```

Key:

```text
session:<sessionId>
```

The concrete key is exactly `session:<uuid>`, built with
`buildRedisKey('session', sessionId)`. The session-state boundary validates the
UUID; angle/curly braces are placeholders, never literal key characters.

Values:

```text
userId
authTime
mfaLevel
createdAt
lastActivityAt
absoluteExpiresAt
```

Runtime JSON is a strict object containing exactly these six fields. userId is a
UUID. All four timestamps are non-negative safe-integer Unix epoch milliseconds;
absoluteExpiresAt must be after createdAt, authTime and lastActivityAt. mfaLevel
is a non-empty opaque string in M3.2, not an assurance enum; its semantic MFA
upgrade policy belongs to M10/M10.7.

TTL policy:

```text
idle timeout: 30 minutes
absolute timeout: 8 hours
```

The existing validated SESSION_IDLE_TTL_SECONDS (1800) and
SESSION_ABSOLUTE_TTL_SECONDS (28800) defaults remain unchanged. The supplied
absoluteExpiresAt is authoritative for runtime expiry. M3.4 will create the
PostgreSQL Session and Redis state from the same absolute-expiry decision;
M3.2 neither creates that row nor decides its expiresAt.

Create writes only validated state, with expiry capped at the lesser of the idle
lifetime and remaining absolute lifetime. Read does not refresh idle TTL. Touch
represents activity: one fixed Redis Lua transition checks the existing key,
validates all stored fields, obtains Redis TIME once, updates only lastActivityAt
and writes the capped millisecond expiry (PXAT). The five other fields stay
unchanged, including the absolute boundary. Missing/expired state cannot be
resurrected by touch. Malformed or absolutely expired state is invalidated and
returns null; Redis command failures throw fixed sanitized operational errors.

No persistence/in-memory fallback or offline queued writes are used. Redis
connect/reconnect remains independent of HTTP startup and process /health.

Cookie:

```text
name: iam.sid
HttpOnly: true
SameSite: Lax
Secure: true in production
Path: /
```

M3.3 provides a pure IdpSessionCookieService, exported alongside
IdpSessionStateService by SessionModule. serialize(sessionId) returns one
Set-Cookie header value; parse(cookieHeader) recognizes only the configured
session cookie. Neither operation performs Redis/Prisma work or authenticates
a user. M3.4 owns login and attaching the cookie to an HTTP response; M3.5 owns
logout/clearing.

COOKIE_NAME defaults to iam.sid and must contain only HTTP token-safe characters
without trimming. The value is exactly the opaque UUID session identifier,
validated with the canonical session-domain UUID schema; no signing/encryption,
Redis state, user metadata or access/refresh/ID tokens are included.

Path=/, HttpOnly and SameSite=Lax are always emitted. Secure follows the validated
COOKIE_SECURE boolean, not a second NODE_ENV decision in the cookie service.
Production requires Secure under the existing central configuration policy.
M3.3 adds no Domain, Expires or Max-Age: this is a browser session cookie, while
server-side expiry remains authoritative.

Parsing uses case-sensitive exact cookie-name matching and strict UUID values.
Unrelated cookies are ignored; missing, malformed or duplicate session cookies
return null. Pair-leading SP/HTAB is tolerated, but the value is never trimmed,
unquoted, URL-decoded or normalized. Recognizing a UUID does not establish that
its server-side session exists or is valid. Cookie values/headers are never logged.

M3.4 exposes POST /auth/login with strict JSON
`{identifier: {type: "email" | "username", value: string}, password: string}`.
Both strings must be non-empty and are passed unchanged (no trimming, casefolding,
Unicode normalization or email/username inference). Unknown fields are rejected.
Malformed body/JSON returns sanitized 400. Unknown user, missing Credential,
wrong password, disabled user and active lock all return the same 401
`Invalid login credentials.`; operational failures return generic 500
`Login failed.`. Failed responses never emit Set-Cookie.

IdpLoginService delegates once to LoginAttemptService, preserving existing
validation/counter/reset/lock behavior. After success it chooses one nowMs and
computes absoluteExpiresAt using validated SESSION_ABSOLUTE_TTL_SECONDS, rejecting
unsafe arithmetic or invalid Date range before session persistence. In a short
Prisma interactive transaction it creates an ACTIVE Session (selecting only the
Prisma-generated UUID), then writes Redis state for that UUID before commit.
createdAt/lastActivityAt match nowMs in both stores; authTime is nowMs,
absoluteExpiresAt matches PostgreSQL expiresAt, and mfaLevel is the opaque
`"password"` value. Optional IP/User-Agent metadata is left null; no proxy policy
is introduced.

Only after transaction commit does AuthController serialize the UUID through
IdpSessionCookieService, attach one Set-Cookie and return 204 with no response
body. Incoming cookies and body-supplied identifiers never select/reuse the new
Session ID; independent logins create independent sessions without revoking old
ones. Redis write failure rolls PostgreSQL back. PostgreSQL creation failure
does not write Redis. This is not a distributed transaction: final commit failure
after Redis success emits no cookie and can leave only a TTL-bounded unreachable
Redis orphan. No rollback deletion/revocation API is added.

Login issues no OAuth/access/refresh/ID token or authorization code, adds no
persistent audit model or login event, and does not authenticate incoming cookies
on unrelated requests. Authorization integration belongs to M5.4.

M3.5 exposes POST /auth/logout. The session identifier comes only from the standard
Cookie header via IdpSessionCookieService.parse; body/query/path/custom headers
cannot supply it. Missing, malformed or duplicate configured cookies skip
server-side invalidation and return 204 with a clearing cookie. No session-check
HTTP endpoint, tokens or logout audit event are introduced.

For a valid UUID, IdpLogoutService first awaits IdpSessionStateService.invalidate:
canonical UUID/key validation followed by Redis DEL of `session:<uuid>`, accepting
both 0 and 1 and sanitizing failures. Only then does PostgreSQL Session.updateMany
conditionally change that ID from ACTIVE to REVOKED. Count 0 is normal for unknown
or already-revoked sessions. The row is retained; userId, timestamps and optional
metadata are unchanged. Missing/expired Redis state is also a successful logout;
subsequent session-state read returns null. Repeated/concurrent logout is
idempotent and reveals no session existence, user or store state.

Only after both operations succeed does the controller return empty HTTP 204 and
attach IdpSessionCookieService.clear(). Its deterministic header is
`iam.sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`, respecting the configured
COOKIE_NAME and appending `; Secure` when COOKIE_SECURE is true. No Domain,
dynamic Expires or metadata is added; login serialization/parsing stay unchanged.

No distributed transaction exists between stores. Redis failure prevents DB
revocation; DB failure after DEL leaves runtime state deleted. Either operational
failure returns generic HTTP 500 `Logout failed.` without Set-Cookie, retaining
the browser identifier for retry. Redis state is never recreated as rollback;
retry accepts DEL=0 and can complete persistent revocation before clearing the
cookie. No OAuth tokens are involved. M3.6 owns own-session listing/selected
revocation; privileged session revocation remains M3.7.

M3.6 exposes only GET /auth/sessions and DELETE /auth/sessions/:sessionId for the
authenticated user's own sessions. A dedicated IdpOwnSessionService obtains the
subject from the configured Cookie parser, existing runtime touch, then a matching
PostgreSQL current Session: same UUID/userId, ACTIVE and expiresAt > now. Runtime
createdAt/absoluteExpiresAt must match persistent createdAt/expiresAt; an absent,
expired, revoked, orphan or incoherent current session returns the same 401
`Authentication required.`. Redis/Prisma operational failures instead return
generic 500 `Session management failed.`. No caller-supplied userId, alternate
current-session identifier or Bearer token is an authority. There is no global
guard/middleware, Passport strategy or generic current-user decorator.

GET returns 200 `{sessions: [...]}` with exactly id, createdAt, lastActivityAt,
expiresAt, nullable ipAddress/userAgent and current. Dates are ISO-8601; activity
comes from Redis, not the persistent snapshot. Candidate rows are restricted to
the subject, ACTIVE and future expiresAt, ordered createdAt DESC then id DESC.
Non-current candidates use read only, never touch; current reuses its single
authentication touch result. Missing/corrupt/wrong-user or immutable-timestamp
incoherent runtime entries are excluded without PostgreSQL cleanup writes. A
genuine runtime error fails the whole list; unexpected omission of the current
session fails closed. Listing emits no Set-Cookie, userId, runtime JSON/keys or
secret/token fields. This is a live management view, not session history or an
atomic cross-store snapshot.

DELETE validates the canonical target UUID before any touch/mutation (400
`Invalid session identifier.` for malformed input). Authentication is still only
the current cookie. Ownership lookup is constrained by BOTH target ID and trusted
subject userId before any target invalidation: target.userId must equal the
authenticated subject. Unknown/cross-user targets share 404 `Session not found.`
and never invoke logout/invalidation. Once proven, revoke reuses IdpLogoutService
with the persistent row's canonical UUID; no duplicate revocation algorithm exists.
Owned revoked or runtime-missing targets remain idempotent successes.

Successful DELETE returns empty 204. Only self-revoke emits the existing clear()
cookie; another-own revoke leaves the current cookie/session usable. Failures
never clear the cookie or recreate Redis state. After self-revoke's partial DB
failure, the runtime is gone and the next management request may return 401;
POST /auth/logout retains its separate M3.5 retry behavior. Concurrent revokes
that already authenticated remain safe/idempotent; a later request with a
self-revoked cookie receives 401. No OAuth tokens, IP/device capture redesign,
audit infrastructure or admin authority are added. M3.7 alone owns privileged
target-user revocation.

---

## 15. SSO

SSO behavior:

```text
Client A -> /authorize
        -> user login/MFA
        -> create central IdP session
        -> code

Client B -> /authorize
        -> valid existing IdP session
        -> no password prompt unless re-auth policy requires it
        -> code
```

SSO is not token sharing between clients. Each client receives its own authorization result/tokens.

---

## 16. Password Security

Credential persistence uses a PostgreSQL UUID primary key and a unique `user_id`
foreign key to User (at most one Credential per User). Password material is stored
only in `password_hash`; `password_updated_at` defaults to creation time and is
not automatically updated for arbitrary record changes.

Password change is an internal trusted-subject operation: verify the current
password, reject exact unchanged input, then hash the new opaque password before
a single compare-and-swap update matching `userId` and the previously read hash.
The successful update explicitly sets `passwordUpdatedAt`; stale updates fail
without retry. Only after success, emit the provisional Nest Logger event
`{event: 'PASSWORD_CHANGED', userId}`. No public route, login-counter mutation,
session/token revocation policy or persistent audit storage is added here.

Hash:

```text
Argon2id
```

Use a maintained library and reviewed parameters.

Never:

- encrypt passwords for later decryption
- log passwords
- store plaintext password
- return password hash

Password reset token:

- cryptographically random
- short-lived
- one-time
- store only hash/state

Reset requests (`POST /auth/password-reset/request`) accept a strict email-only
body, trim surrounding whitespace and preserve case. Every syntactically valid
email receives HTTP 202 `{"status":"accepted"}`, including unknown, disabled or
Credential-less accounts and operational failures; this does not promise equal
timing. Only ACTIVE accounts with a Credential are eligible; temporary login
locks and failed-login counters remain unchanged.

Generate `randomBytes(32)` (256 bits), encode as base64url, then SHA-256 the raw
token to lowercase hex. Store only `{"userId":"..."}` with explicit TTL under
`buildRedisKey('pwdreset', tokenHash)` (runtime `pwdreset:<tokenHash>`, no literal
braces). `PASSWORD_RESET_TTL_SECONDS` defaults to 900 (15 minutes), validated as a
positive safe integer. Raw tokens are never persisted, logged or returned through
HTTP. Deliver only after Redis persistence through an internal out-of-band
boundary, currently a safe no-op placeholder without an email provider.
Persistence failure prevents delivery; delivery failure leaves state until TTL
expiry, both with generic 202 and only fixed sanitized operational logging.
Multiple requests may create independent entries. M2.9 owns atomic one-time
consumption/replay enforcement and completed-reset audit; M2.8 emits no reset
audit event and does not replace passwords.

Reset consumption (`POST /auth/password-reset/consume`) accepts strict JSON
`{token, newPassword}`, both non-empty opaque strings without trimming,
normalization or password complexity/history policy. Success is HTTP 204 with
no body/cookie. Unknown, expired, replayed tokens, malformed/mismatched reset state
and a missing Credential share HTTP 400 `Invalid or expired password reset token.`
Malformed requests use a fixed sanitized 400; operational failures use safe 500.

SHA-256 the exact raw token to the same lowercase-hex `pwdreset:<tokenHash>` key.
A cheap Redis GET and strict `{userId}` UUID precheck happen before PasswordService
hashing (Argon2id). Then official atomic GETDEL on the same key determines exclusive
one-time ownership; revalidate consumed state and its match to the preview.
Hashing failure occurs before consumption; after successful GETDEL the token is
never restored, including PostgreSQL failure. Update only the existing Credential
with `passwordHash` and explicit `passwordUpdatedAt`, requiring exactly one
affected row. Emit `{event: 'PASSWORD_RESET', userId}` only after persistence.
Raw tokens/passwords/hashes/Redis keys are never logged or returned. Account status,
login locks and failure counters remain unchanged; no session/token revocation is
implemented here. Redis failures fail closed without fallback.

---

## 17. TOTP

Canonical profile:

```text
algorithm: SHA-1
digits: 6
period: 30 seconds
```

Secret storage:

```text
AES-256-GCM
```

Encryption key comes from environment configuration.

Enrollment:

```text
reauthenticate
generate secret
encrypt/store secret
show otpauth URI / QR
verify first TOTP
mark factor enabled
```

MFA challenge:

```text
mfa:challenge:{challengeId}
TTL: 5 minutes
max attempts: 5
```

---

## 18. OAuth Scope Model

Client registration defines `allowed_scopes`.

Authorization request defines `requested_scopes`.

Granted scope:

```text
granted_scopes =
requested_scopes ∩ client_allowed_scopes
```

If request includes an unknown or forbidden scope, return `invalid_scope`.

OIDC scopes:

```text
openid
profile
email
```

Example resource scope:

```text
banking.transactions.read
```

---

## 19. RBAC Model

Canonical relationship:

```text
User
 -> UserRole
 -> Role
 -> RolePermission
 -> Permission
```

Example:

```text
Role: BANK_EMPLOYEE
Permission: transaction.view
```

Permission and OAuth Scope are separate.

Example Banking API policy:

```text
GET /transactions

audience: banking-api
scope: banking.transactions.read
permission: transaction.view
```

---

## 20. Resource API Audiences

```text
Banking API: banking-api
Student API: student-api
```

A token intended for one API must not automatically be accepted by another.

---

## 21. Account State

User primary IDs use PostgreSQL UUID, with Prisma's `uuid()` default.

Suggested statuses:

```text
ACTIVE
DISABLED
```

Temporary lock:

```text
locked_until
```

Authentication rejects disabled or currently locked users.

Brute-force baseline:

```text
5 failed attempts
15-minute lock
```

---

## 22. Redis Keys

```text
session:{sessionId}
oauth:code:{codeHash}
mfa:challenge:{challengeId}
rate:{subject}:{action}
pwdreset:{tokenHash}
```

All ephemeral entries require explicit TTL where applicable.

Failed password attempts for a known ACTIVE/unlocked User use
`rate:{userId}:login-failure`. An atomic increment sets the TTL to
`LOGIN_LOCK_SECONDS` only on the first failure; later failures preserve this fixed
window. At `LOGIN_MAX_FAILURES`, a conditional PostgreSQL update establishes
`User.lockedUntil` without extending an already-active lock. Successful password
authentication deletes the counter before returning success; expired lock
timestamps need not be cleared. Redis counter/reset or lock-write failures fail
closed with sanitized internal errors.

Redis connects/reconnects in the background and is not a prerequisite for basic
HTTP startup or process-level `/health`. Offline commands are not queued;
authentication operations requiring Redis state must fail closed while Redis is
unavailable. No in-memory fallback is used.

---

## 23. Audit Events

At minimum:

```text
USER_REGISTERED
LOGIN_SUCCEEDED
LOGIN_FAILED
ACCOUNT_LOCKED
LOGOUT
PASSWORD_CHANGED
PASSWORD_RESET
MFA_ENABLED
MFA_DISABLED
CLIENT_CREATED
CLIENT_UPDATED
ROLE_ASSIGNED
ROLE_REMOVED
SESSION_REVOKED
TOKEN_REVOKED
REFRESH_TOKEN_REUSE_DETECTED
```

Never store secret values in audit logs.

---

## 24. HTTP / OAuth Errors

OAuth endpoints use protocol-appropriate errors:

```text
invalid_request
invalid_client
invalid_grant
unauthorized_client
unsupported_grant_type
invalid_scope
```

Account/management APIs may use normal NestJS/HTTP error conventions.

Do not leak stack traces.

---

## 25. Environment Variables

Canonical names:

```text
NODE_ENV
IDENTITY_SERVER_PORT
DATABASE_URL
REDIS_URL
ISSUER_URL

ACCESS_TOKEN_TTL_SECONDS
AUTH_CODE_TTL_SECONDS
REFRESH_TOKEN_TTL_SECONDS

SESSION_IDLE_TTL_SECONDS
SESSION_ABSOLUTE_TTL_SECONDS

JWT_PRIVATE_KEY_PATH
JWT_PUBLIC_KEY_PATH
JWT_KEY_ID

TOTP_ENCRYPTION_KEY

COOKIE_NAME
COOKIE_SECURE

LOGIN_MAX_FAILURES
LOGIN_LOCK_SECONDS
PASSWORD_RESET_TTL_SECONDS
```

`.env.example` contains only names and safe development placeholders.

The Identity Server loads its package-local `.env`, with shell variables taking
precedence, and validates the complete configuration before listening.
`IDENTITY_SERVER_PORT` is the only application port variable.
URLs and signing/TOTP configuration are mandatory; errors identify variable names
without printing values. Canonical security defaults above apply; `COOKIE_SECURE`
defaults to false outside production and true in production. Production rejects
`COOKIE_SECURE=false` and a non-HTTPS issuer. JWT key-file existence and TOTP key
encoding/strength are validated only in their respective implementation tasks.

Never commit production secrets.

---

## 26. Test Boundaries

Unit:

- pure helpers/policies
- PKCE
- scope calculation
- permission resolution
- JWT helpers
- TOTP

Integration:

- PostgreSQL/Prisma
- Redis
- IdP session
- authorization-code consume semantics
- refresh-token rotation transaction

E2E:

- login
- Authorization Code + PKCE
- OIDC
- refresh
- revoke
- MFA
- SSO
- RBAC

---

## 27. Performance Metrics

Required:

```text
requests/sec
average latency
P50
P95
P99
error rate
```

Scenarios:

```text
login
/oauth/authorize
/oauth/token
refresh token
protected API request
```

---

## 28. Change Policy

If implementation requires changing a frozen decision:

1. stop
2. explain why
3. update this document first
4. update dependent code/tests/docs together

Do not silently diverge from this specification.
