# TASKS — Centralized IAM System

This file is the **single source of truth for implementation milestones, dependencies, task state and acceptance criteria**.

Tasks are intentionally small enough to be assigned to Codex one at a time.

## Status

```text
[ ] Not started
[~] In progress
[x] Done
[!] Blocked
```

## Agent rule

Do not assign “implement M6” or “finish OAuth”.

Assign one atomic task, for example:

```text
Implement M6.3 — PKCE verification.
Read AGENTS.md and IMPLEMENTATION_SPEC.md first.
Do not work on later tasks.
Run the verification commands listed in the task.
```

---

# M0 — Baseline & Repository Contract

## M0.1 — Freeze architecture

Status: [x]

Completed:

- System Architecture
- NestJS Modular Monolith
- ERD
- Authorization Code + PKCE/OIDC sequence
- Refresh Token Rotation
- MFA flow
- SSO flow
- RBAC + Scope model
- Deployment Architecture

## M0.2 — Codex repository instructions

Status: [x]

Deliverables:

- `AGENTS.md`
- `IMPLEMENTATION_SPEC.md`
- revised `README.md`
- revised `TASKS.md`

---

# M1 — Foundation

Depends on: M0

## M1.1 — Initialize pnpm workspace

Status: [x]

Deliverables:

```text
package.json
pnpm-workspace.yaml
apps/
packages/
docs/
```

Requirements:

- pnpm workspace
- Node >=24.15.0 <25 engine declaration
- root scripts placeholder for lint/typecheck/test

Acceptance criteria:

- `pnpm install` succeeds
- workspace packages are discovered

Verification:

```bash
pnpm install
pnpm -r list --depth -1
```

## M1.2 — Bootstrap Identity Server

Status: [x]

Path:

```text
apps/identity-server
```

Requirements:

- NestJS application
- TypeScript strict
- base AppModule
- `/health`

Acceptance criteria:

- app starts
- `GET /health` returns success
- no database dependency required for basic process startup

Verification:

```bash
pnpm --filter identity-server build
pnpm --filter identity-server test
```

## M1.3 — Configure lint, format and typecheck

Status: [x]

Requirements:

- ESLint
- Prettier
- TypeScript strict
- root scripts for lint/typecheck

Acceptance criteria:

- `pnpm lint` exits 0
- `pnpm typecheck` exits 0

## M1.4 — Add PostgreSQL + Prisma

Status: [x]

Requirements:

- PostgreSQL Docker service
- Prisma in Identity Server
- PrismaModule / PrismaService
- database connection

Acceptance criteria:

- Prisma validates and connects locally

Verification:

```bash
pnpm --filter identity-server prisma validate
```

## M1.5 — Add Redis

Status: [x]

Requirements:

- Redis Docker service
- Redis module/service
- reconnect/error handling
- key-prefix helper

Acceptance criteria:

- set/get works
- TTL works

## M1.6 — ConfigModule + env validation

Status: [x]

Requirements:

- typed env validation
- config matches implementation spec
- fail fast on missing mandatory secrets

## M1.7 — Docker Compose baseline

Status: [ ]

Services:

```text
identity-server
postgres
redis
```

Acceptance criteria:

```bash
docker compose up
```

starts all services.

## M1.8 — Seed infrastructure

Status: [ ]

Requirements:

- deterministic local seed command
- idempotent
- no production secrets

---

# M2 — User & Credential

Depends on: M1.4, M1.6

## M2.1 — User Prisma model

Status: [ ]

Fields:

```text
id
email
username
status
locked_until
created_at
updated_at
```

Acceptance criteria:

- unique email
- unique username
- migration created
- disabled state supported

## M2.2 — Credential Prisma model

Status: [ ]

Requirements:

- one credential per user for MVP
- password hash only
- password update timestamp

Acceptance criteria:

- no plaintext password column

## M2.3 — Argon2 password service

Status: [ ]

Acceptance criteria:

- Argon2id
- correct password verifies
- incorrect password fails
- no password logging

## M2.4 — Registration API

Status: [ ]

Requirements:

- validation
- reject duplicate email/username
- create User + Credential
- audit event

Acceptance criteria:

- no password hash in response

## M2.5 — Login password validation

Status: [ ]

Requirements:

- username/email lookup
- password verification
- disabled-user rejection
- locked-user rejection

Important:

```text
This task does NOT issue OAuth tokens.
```

## M2.6 — Failed-login counter and temporary lock

Status: [ ]

Policy:

```text
5 failed attempts
15-minute lock
```

Acceptance criteria:

- threshold locks account
- successful login resets relevant failure state

## M2.7 — Change password

Status: [ ]

Acceptance criteria:

- current password required
- old password stops working
- new password works
- audit event written

## M2.8 — Password reset request

Status: [ ]

Acceptance criteria:

- random one-time token
- short TTL
- hash/state stored, not raw token
- response avoids user enumeration

## M2.9 — Password reset consume

Status: [ ]

Acceptance criteria:

- valid token resets password
- replay fails
- expired token fails

---

# M3 — Central IdP Session

Depends on: M2.5, M1.5

## M3.1 — Session Prisma model

Status: [ ]

Fields:

```text
id
user_id
status
ip_address
user_agent
created_at
last_activity_at
expires_at
```

## M3.2 — Redis IdP session state

Status: [ ]

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

Acceptance criteria:

- idle TTL
- absolute expiry

## M3.3 — IdP session cookie

Status: [ ]

Cookie:

```text
iam.sid
HttpOnly
SameSite=Lax
Secure=true in production
```

Acceptance criteria:

- cookie contains only session identifier

## M3.4 — Complete login into IdP session

Status: [ ]

Acceptance criteria:

- valid login creates central session
- `/auth/login` returns no OAuth access token

## M3.5 — Logout

Status: [ ]

Acceptance criteria:

- Redis state invalidated
- cookie cleared
- later session check fails

## M3.6 — Own-session management

Status: [ ]

Functions:

- list own sessions
- revoke selected own session

## M3.7 — Admin session revocation service

Status: [ ]

Acceptance criteria:

- privileged service can revoke target user's sessions

---

# M4 — OAuth Client & Scope Registry

Depends on: M1.4

## M4.1 — Client Prisma model

Status: [ ]

Fields:

```text
id
client_id
name
client_type
client_secret_hash
enabled
access_token_ttl
refresh_token_ttl
```

## M4.2 — Client redirect URI model

Status: [ ]

Acceptance criteria:

- multiple URIs
- exact matching
- no wildcard

## M4.3 — Scope + ClientScope models

Status: [ ]

Acceptance criteria:

- unique scope names
- allowed scopes represented

## M4.4 — Client secret lifecycle

Status: [ ]

Acceptance criteria:

- secure generation
- raw secret shown once
- hash persisted
- public client has no secret

## M4.5 — Seed demo clients/scopes

Status: [ ]

Seed:

```text
student-spa
banking-web
admin-portal
openid
profile
email
banking.transactions.read
```

## M4.6 — Client/scope lookup services

Status: [ ]

Acceptance criteria:

- disabled client rejected
- allowed scopes query available

---

# M5 — Authorization Endpoint

Depends on: M3.4, M4.6

## M5.1 — Parse and validate `/oauth/authorize`

Status: [ ]

Validate:

```text
response_type=code
client_id
redirect_uri
scope
state
nonce when openid requested
code_challenge for public client
code_challenge_method=S256
```

Acceptance criteria:

- unknown/disabled client rejected
- invalid redirect URI is never redirected to

## M5.2 — PKCE authorization-request policy

Status: [ ]

Acceptance criteria:

- Student SPA requires PKCE
- S256 accepted
- `plain` rejected

## M5.3 — Granted-scope calculation

Status: [ ]

Rule:

```text
granted = requested ∩ allowed
```

Acceptance criteria:

- unknown/forbidden scope returns `invalid_scope`

## M5.4 — Integrate IdP session check

Status: [ ]

Acceptance criteria:

- authenticated session continues
- unauthenticated request enters login flow
- request resumes after login

## M5.5 — Authorization-code generation/storage

Status: [ ]

Redis:

```text
oauth:code:{codeHash}
TTL: 2 minutes
```

Acceptance criteria:

- random code
- stores client/user/redirect/scopes/PKCE/nonce
- TTL exists

## M5.6 — Authorization response

Status: [ ]

Acceptance criteria:

- callback includes `code`
- preserves original `state`
- only validated redirect URI used

---

# M6 — Token Endpoint & JWT

Depends on: M5.5, M5.6

## M6.1 — Token endpoint request validation

Status: [ ]

Support:

```text
grant_type=authorization_code
```

## M6.2 — Authorization-code atomic consumption

Status: [ ]

Acceptance criteria:

- first consume succeeds
- replay fails
- expired code fails

## M6.3 — PKCE verification

Status: [ ]

Acceptance criteria:

- S256 only
- valid verifier succeeds
- wrong verifier -> `invalid_grant`
- missing verifier fails
- no `plain` fallback

Verification:

```bash
pnpm --filter identity-server test
pnpm --filter identity-server test:integration
```

## M6.4 — Confidential-client authentication

Status: [ ]

Method:

```text
client_secret_basic
```

Acceptance criteria:

- Banking/Admin valid secret succeeds
- wrong secret -> `invalid_client`
- Student SPA needs no secret

## M6.5 — RS256 signing-key service

Status: [ ]

Acceptance criteria:

- private/public key loading
- `kid`
- no hand-written crypto
- public key can become JWK

## M6.6 — Access-token claim builder

Status: [ ]

Claims:

```text
iss
sub
aud
iat
exp
scope
roles
permissions
```

Acceptance criteria:

- default TTL 10 minutes
- explicit audience
- no sensitive values

## M6.7 — Authorization-code token response

Status: [ ]

Return:

```text
access_token
token_type=Bearer
expires_in
scope
```

## M6.8 — Authorization-code E2E

Status: [ ]

Acceptance criteria:

- authorize → login/session → code → token works
- code replay fails

---

# M7 — OpenID Connect

Depends on: M6.5, M6.7

## M7.1 — Discovery endpoint

Status: [ ]

Acceptance criteria:

- issuer correct
- endpoint metadata correct
- RS256 advertised

## M7.2 — JWKS endpoint

Status: [ ]

Acceptance criteria:

- public key only
- correct `kid`
- correct JWK metadata

## M7.3 — ID Token builder

Status: [ ]

Claims:

```text
iss
sub
aud
iat
exp
nonce
```

## M7.4 — UserInfo endpoint

Status: [ ]

Acceptance criteria:

- Bearer access token required
- scope-limited claims

## M7.5 — OIDC scopes/profile mapping

Status: [ ]

Scopes:

```text
openid
profile
email
```

## M7.6 — OIDC E2E

Status: [ ]

Acceptance criteria:

- client validates signature/issuer/audience/nonce
- UserInfo succeeds

---

# M8 — Refresh Token Rotation

Depends on: M6.6, M3

## M8.1 — RefreshTokenFamily model

Status: [ ]

## M8.2 — RefreshToken model

Status: [ ]

Fields:

```text
token_hash
parent_token_id
status
issued_at
expires_at
consumed_at
revoked_at
```

Acceptance criteria:

- no raw token column

## M8.3 — Opaque refresh-token generator

Status: [ ]

Acceptance criteria:

- 256-bit secure random
- SHA-256 persistence hash

## M8.4 — Initial refresh-token issuance

Status: [ ]

Acceptance criteria:

- family created
- linked to session/client/user
- configured expiry

## M8.5 — `grant_type=refresh_token`

Status: [ ]

Acceptance criteria:

- hash lookup
- client binding
- status/expiry validation

## M8.6 — Atomic rotation transaction

Status: [ ]

Operation:

```text
consume RT1 + create RT2
```

Acceptance criteria:

- only one concurrent consume succeeds
- RT2 links to parent
- new access token issued

## M8.7 — Reuse detection

Status: [ ]

Acceptance criteria:

- replay detected
- family revoked
- related IdP session revoked
- audit written
- `invalid_grant`

## M8.8 — `/oauth/revoke`

Status: [ ]

Acceptance criteria:

- refresh token revocation
- caller-visible idempotence
- no cross-client leakage

## M8.9 — Refresh security integration tests

Status: [ ]

Cases:

- RT1 → RT2
- RT1 replay
- concurrent RT1
- expired token
- revoked family

---

# M9 — RBAC & Resource Authorization

Depends on: M2.1, M4.3, M6.6

## M9.1 — Role + Permission models

Status: [ ]

Models:

```text
Role
Permission
UserRole
RolePermission
```

## M9.2 — Role assignment services

Status: [ ]

## M9.3 — Permission resolution

Status: [ ]

Flow:

```text
User → Roles → Permissions
```

## M9.4 — Add roles/permissions to access token

Status: [ ]

Acceptance criteria:

- claim format matches implementation spec
- authorization-code and refresh issuance use same resolver

## M9.5 — Shared JWT validation package

Status: [ ]

Path:

```text
packages/auth-client
```

Acceptance criteria:

- cached Discovery/JWKS
- RS256
- issuer/audience/expiry validation
- no per-request Identity Server validation

## M9.6 — Scope guard

Status: [ ]

Acceptance criteria:

- missing required scope -> 403

## M9.7 — Permission guard

Status: [ ]

Acceptance criteria:

- missing permission -> 403

## M9.8 — Banking authorization policy test

Status: [ ]

Policy:

```text
GET /transactions
aud = banking-api
scope = banking.transactions.read
permission = transaction.view
```

---

# M10 — MFA TOTP

Depends on: M2.5, M3.4

## M10.1 — MFAFactor model

Status: [ ]

## M10.2 — AES-256-GCM secret protection service

Status: [ ]

Acceptance criteria:

- encrypt/decrypt
- IV/auth tag
- env key
- no secret logging

## M10.3 — TOTP service

Status: [ ]

Profile:

```text
SHA-1
6 digits
30 seconds
```

## M10.4 — MFA enrollment start

Status: [ ]

Acceptance criteria:

- reauthentication
- generate/encrypt secret
- return otpauth/QR
- factor still disabled

## M10.5 — Verify first TOTP / enable MFA

Status: [ ]

Acceptance criteria:

- valid code enables
- invalid code keeps disabled

## M10.6 — MFA challenge state

Status: [ ]

Redis:

```text
mfa:challenge:{challengeId}
TTL 5 minutes
max attempts 5
```

## M10.7 — MFA during login

Status: [ ]

Acceptance criteria:

- password-valid MFA user must verify TOTP
- session `mfaLevel` upgraded after success

## M10.8 — MFA E2E

Status: [ ]

---

# M11 — Central SSO

Depends on: M3.4, M5, M6

## M11.1 — Banking confidential-client login flow

Status: [ ]

## M11.2 — Student SSO flow

Status: [ ]

Acceptance criteria:

- existing IdP session detected
- no password prompt
- Student performs its own `/authorize`
- code exchanged with PKCE

## M11.3 — SSO isolation test

Status: [ ]

Acceptance criteria:

- Banking token is not reused as Student token
- independently issued authorization results
- logout/revocation invalidates SSO session per policy

---

# M12 — Audit Logging

Depends on: M2 onward

## M12.1 — AuditLog model

Status: [ ]

## M12.2 — Audit service

Status: [ ]

## M12.3 — Authentication audit events

Status: [ ]

Events include registration/login/account/password/MFA.

## M12.4 — IAM/admin audit events

Status: [ ]

Events include client/role/session/token/reuse actions.

## M12.5 — Sensitive-data regression test

Status: [ ]

Acceptance criteria:

- no password/raw token/auth code/TOTP secret/client secret/reset token

---

# M13 — Management API

Depends on: M2, M4, M9, M12

## M13.1 — Admin authorization guard

Status: [ ]

## M13.2 — User management API

Status: [ ]

## M13.3 — Client management API

Status: [ ]

## M13.4 — RBAC management API

Status: [ ]

## M13.5 — Session management API

Status: [ ]

## M13.6 — Audit-query API

Status: [ ]

---

# M14 — Banking Demo

Depends on: M7, M9, M11.1

## M14.1 — Banking Web/BFF bootstrap

Status: [ ]

Path:

```text
apps/banking-web
```

## M14.2 — Banking OAuth/OIDC login

Status: [ ]

Acceptance criteria:

- authorization redirect
- state handling
- server-side code exchange
- `client_secret_basic`

## M14.3 — Banking BFF session

Status: [ ]

Acceptance criteria:

- client secret remains server-side
- tokens remain server-side where appropriate

## M14.4 — Banking API bootstrap

Status: [ ]

## M14.5 — Protected `GET /transactions`

Status: [ ]

Requires:

```text
aud = banking-api
scope = banking.transactions.read
permission = transaction.view
```

## M14.6 — Banking E2E

Status: [ ]

---

# M15 — Student Demo

Depends on: M7, M9.5, M11.2

## M15.1 — Student SPA bootstrap

Status: [ ]

Path:

```text
apps/student-spa
```

Technology:

```text
React + Vite
```

## M15.2 — SPA PKCE/state/nonce generation

Status: [ ]

## M15.3 — Authorization redirect + callback

Status: [ ]

Acceptance criteria:

- state validated before code use

## M15.4 — Token exchange

Status: [ ]

Acceptance criteria:

- no client secret
- sends client_id/code/redirect_uri/code_verifier

## M15.5 — ID Token validation

Status: [ ]

Validate:

- signature
- issuer
- audience
- expiry
- nonce

## M15.6 — Student API bootstrap

Status: [ ]

## M15.7 — Student protected endpoint

Status: [ ]

Acceptance criteria:

- local JWT validation
- `aud = student-api`
- required scope

## M15.8 — Student OAuth/OIDC E2E

Status: [ ]

Cases include invalid state and invalid nonce.

---

# M16 — Admin Portal

Depends on: M13

## M16.1 — Admin Portal bootstrap

Status: [ ]

## M16.2 — Admin OIDC login

Status: [ ]

## M16.3 — User management UI

Status: [ ]

## M16.4 — Client/scope management UI

Status: [ ]

## M16.5 — Role/permission management UI

Status: [ ]

## M16.6 — Session management UI

Status: [ ]

## M16.7 — Audit viewer

Status: [ ]

Priority:

```text
functionality > UI polish
```

---

# M17 — Cross-Cutting Automated Tests

## M17.1 — Unit coverage gap review

Status: [ ]

## M17.2 — Integration coverage gap review

Status: [ ]

## M17.3 — E2E happy-path suite

Status: [ ]

Required:

- registration/login
- PKCE/OIDC
- refresh/revoke
- MFA
- SSO
- RBAC

## M17.4 — CI-friendly test commands

Status: [ ]

Acceptance criteria:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:e2e
```

have defined behavior.

---

# M18 — Security Regression Suite

## M18.1 — Account attacks

Status: [ ]

Cases:

- wrong password
- brute-force
- locked
- disabled

## M18.2 — Authorization endpoint attacks

Status: [ ]

Cases:

- invalid redirect URI
- unknown client
- unauthorized scope
- missing/invalid PKCE

## M18.3 — State / nonce attacks

Status: [ ]

Cases:

- invalid state
- invalid nonce

## M18.4 — Authorization-code attacks

Status: [ ]

Cases:

- replay
- expiry
- wrong verifier
- wrong redirect URI

## M18.5 — JWT attacks

Status: [ ]

Cases:

- invalid signature
- wrong issuer
- wrong audience
- expiry
- missing scope
- missing permission

## M18.6 — Refresh attacks

Status: [ ]

Cases:

- replay
- concurrent use
- revoked family
- expiry

## M18.7 — MFA attacks

Status: [ ]

Cases:

- invalid TOTP
- expired challenge
- attempt exhaustion

---

# M19 — Performance Evaluation

## M19.1 — Benchmark harness

Status: [ ]

## M19.2 — Environment record

Status: [ ]

Document CPU/RAM/OS/Node/PostgreSQL/Redis/concurrency.

## M19.3 — Login benchmark

Status: [ ]

## M19.4 — `/oauth/authorize` benchmark

Status: [ ]

## M19.5 — `/oauth/token` benchmark

Status: [ ]

## M19.6 — Refresh benchmark

Status: [ ]

## M19.7 — Protected API benchmark

Status: [ ]

## M19.8 — Metrics report

Status: [ ]

Metrics:

- requests/sec
- average latency
- P50
- P95
- P99
- error rate

---

# M20 — Thesis & Defense

## M20.1 — Architecture chapter

Status: [ ]

## M20.2 — Database design chapter

Status: [ ]

## M20.3 — OAuth/OIDC + PKCE explanation

Status: [ ]

## M20.4 — Refresh Token Rotation explanation

Status: [ ]

## M20.5 — MFA + SSO explanation

Status: [ ]

## M20.6 — RBAC vs OAuth Scope explanation

Status: [ ]

## M20.7 — Security evaluation

Status: [ ]

## M20.8 — Performance evaluation

Status: [ ]

## M20.9 — Demo script

Status: [ ]

## M20.10 — Defense slides

Status: [ ]

---

# Critical Path

```text
M1 Foundation
  ↓
M2 User/Credential
  ↓
M3 Session
  ↓
M4 Client/Scope
  ↓
M5 /authorize
  ↓
M6 /token + JWT
  ↓
M7 OIDC
  ↓
M8 Refresh Rotation
  ↓
M9 RBAC
  ↓
M10 MFA
  ↓
M11 SSO
  ↓
M13 Management
  ↓
M14/M15/M16 Demo Applications
  ↓
M17/M18 Testing
  ↓
M19 Evaluation
  ↓
M20 Thesis
```

---

# Codex Task Assignment Template

```text
Read AGENTS.md and IMPLEMENTATION_SPEC.md first, then TASKS.md and README.md.

Implement only the assigned atomic TASKS.md item: <task ID — title>.

Check its dependencies and acceptance criteria before coding.
Do not implement other tasks or expand the assigned scope.
Before coding, inspect the repository and provide a short plan.
After implementation, run the task's verification commands.
Report files changed, commands run, results, and unresolved issues.
Only mark the assigned task done if every acceptance criterion passes.
```
