# IMPLEMENTATION_SPEC.md

This document is the **canonical implementation specification** for the Centralized IAM System.

If README examples differ from this file, this file wins.

---

## 1. Platform

```text
Node.js: 22 LTS
Package manager: pnpm
Monorepo: pnpm workspaces
Backend: NestJS + TypeScript
ORM: Prisma
Database: PostgreSQL
Ephemeral state: Redis
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

Runtime store:

```text
Redis
```

Key:

```text
session:{sessionId}
```

Values:

```text
userId
authTime
mfaLevel
createdAt
lastActivityAt
absoluteExpiresAt
```

TTL policy:

```text
idle timeout: 30 minutes
absolute timeout: 8 hours
```

Cookie:

```text
name: iam.sid
HttpOnly: true
SameSite: Lax
Secure: true in production
Path: /
```

Do not store access tokens in the central IdP session cookie.

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

Planned names:

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
```

`.env.example` contains only names and safe development placeholders.

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
