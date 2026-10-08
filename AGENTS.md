# AGENTS.md

This repository is a graduation-thesis implementation of a centralized Identity and Access Management system based on OAuth 2.0 and OpenID Connect.

This file contains **persistent instructions for coding agents** working in this repository.

## 1. Source of Truth

Read these files before implementing any task:

1. `AGENTS.md`
2. `IMPLEMENTATION_SPEC.md`
3. `TASKS.md`
4. `README.md`

Priority when documents disagree:

```text
AGENTS.md
    ↓
IMPLEMENTATION_SPEC.md
    ↓
TASKS.md
    ↓
README.md
```

Do not silently invent a new architecture or protocol policy.

## 2. Architecture Constraints

The Identity Server is a **NestJS modular monolith**.

Do not introduce:

- Kafka
- Kubernetes
- API Gateway
- Service Mesh
- microservices
- SAML
- LDAP / Active Directory
- social login
- external IAM products as the implementation

unless the task explicitly changes scope.

Use:

- Node.js 22 LTS
- TypeScript
- NestJS
- Prisma
- PostgreSQL
- Redis
- pnpm workspaces

## 3. Application Boundaries

Canonical applications:

```text
apps/identity-server
apps/banking-web
apps/banking-api
apps/student-spa
apps/student-api
apps/admin-portal
```

Do not rename them without updating all docs and references.

## 4. Authentication Rules

- `/auth/login` authenticates a user into the Identity Server session.
- `/auth/login` MUST NOT directly return OAuth access tokens.
- OAuth access tokens are issued only by `/oauth/token`.
- Student SPA is a **public client**.
- Student SPA MUST NOT use a client secret.
- Banking Web/BFF and Admin Portal/BFF are **confidential clients**.
- Confidential client authentication uses `client_secret_basic`.
- SSO is based on the central IdP session.

## 5. OAuth / OIDC Rules

- Authorization Code flow only for the main interactive flow.
- PKCE uses **S256 only**.
- Reject `plain` PKCE.
- Redirect URI matching is **exact**.
- Authorization codes are short-lived and one-time.
- Validate OAuth `state` at the client.
- Validate OIDC `nonce`.
- OIDC Discovery and JWKS must be exposed.
- Resource APIs validate JWT locally using cached JWKS.
- Do not call the Identity Server for every protected API request.

## 6. Token Rules

Access token:

- JWT
- RS256
- short-lived
- contains appropriate `iss`, `sub`, `aud`, `iat`, `exp`, `scope`
- contains permission claims required by the resource API

Refresh token:

- opaque random token
- never store raw token
- persist SHA-256 token hash + metadata
- use token family
- rotate on every successful refresh
- old-token consumption and new-token creation must be atomic
- token reuse revokes the family and related session

Never manually implement cryptographic primitives.

## 7. Password / MFA Rules

Passwords:

- Argon2id
- never plaintext
- never logged

TOTP:

- SHA-1
- 6 digits
- 30-second period
- secret encrypted at rest using AES-256-GCM
- do not mark MFA enabled until the first TOTP is verified
- never log TOTP secret

## 8. Authorization Rules

Keep these concepts separate:

```text
Role
Permission
OAuth Scope
```

Example:

```text
Role: BANK_EMPLOYEE
Permission: transaction.view
Scope: banking.transactions.read
```

A protected resource may require both:

```text
scope = banking.transactions.read
permission = transaction.view
```

Do not treat permission and scope as interchangeable strings.

## 9. Session Rules

IdP session:

- server-side session state
- Redis runtime state
- secure cookie identifier
- HttpOnly
- SameSite=Lax
- Secure=true in production
- idle timeout: 30 minutes
- absolute timeout: 8 hours

Logout/revocation must invalidate server-side session state.

## 10. Data & Logging Rules

Never log:

- passwords
- raw refresh tokens
- raw access tokens unless explicitly redacted for local debugging
- authorization codes
- TOTP secrets
- client secrets
- password-reset tokens

Audit security events, but store only safe metadata.

## 11. Coding Style

- TypeScript strict mode.
- Prefer explicit types at module boundaries.
- Keep controllers thin.
- Put business logic in services/use-case-oriented services.
- Keep protocol validation close to OAuth/OIDC modules.
- Keep persistence behind Prisma service/repository abstractions where useful.
- Avoid premature generic abstractions.
- Do not create a class/interface solely to look “enterprise”.
- Prefer small focused modules and functions.
- Use meaningful domain names from the architecture docs.

## 12. Error Handling

OAuth/OIDC endpoints must return protocol-appropriate errors.

Examples:

- `invalid_request`
- `invalid_client`
- `invalid_grant`
- `unauthorized_client`
- `unsupported_grant_type`
- `invalid_scope`

Do not replace OAuth errors with arbitrary generic REST errors when the protocol requires an OAuth error response.

Management/account APIs may use normal HTTP/NestJS error conventions.

## 13. Task Execution Contract

When assigned a task:

1. Read its dependency list in `TASKS.md`.
2. Inspect existing code before changing it.
3. Produce a short implementation plan.
4. Modify only the required scope unless a dependency bug blocks the task.
5. Add/update tests.
6. Run verification commands.
7. Summarize:
   - files changed
   - behavior implemented
   - tests run
   - unresolved risks
8. Update task checkbox only if all acceptance criteria pass.

Do not mark a task done just because code compiles.

## 14. Verification Contract

Before finishing a task, run the relevant subset of:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:e2e
```

If the repository does not yet provide a command, create it in the foundation task where appropriate.

Do not claim a command passed unless it actually ran successfully.

## 15. Dependency Discipline

Do not skip required foundation tasks.

Examples:

- Do not implement `/oauth/token` before authorization-code persistence exists.
- Do not implement SSO before central session exists.
- Do not implement refresh reuse detection without token-family state.
- Do not implement permission guards before token-claim format is defined.

## 16. Scope Discipline

If a task can be completed without adding a new technology, do not add one.

Do not expand the thesis scope for “enterprise realism”.

A simpler implementation that correctly demonstrates the protocol/security property is preferred over unnecessary infrastructure.

## 17. Documentation Discipline

When behavior changes:

- update `IMPLEMENTATION_SPEC.md` if a canonical technical decision changes
- update `README.md` if project-level behavior/scope changes
- update `TASKS.md` only for task state, acceptance criteria, or roadmap changes

Do not duplicate source-of-truth technical constants in many files unless needed for readability.

## 18. Stop Conditions

Stop and ask for clarification rather than guessing if a requested change would:

- contradict OAuth/OIDC architecture
- change public ↔ confidential client classification
- change token/session authority
- replace the modular monolith
- add a new protocol
- alter a frozen security policy
- require a breaking schema change not described by the task
