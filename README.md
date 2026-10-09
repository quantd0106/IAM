# Centralized IAM System

> **DATN:** Xây dựng hệ thống quản lý định danh và truy cập tập trung dựa trên OAuth 2.0 và OpenID Connect  
> **English:** Design and Implementation of a Centralized Identity and Access Management System based on OAuth 2.0 and OpenID Connect

## 1. Overview

Hệ thống là một **Identity Server tập trung** cho nhiều ứng dụng client. Mục tiêu là tách authentication/authorization khỏi từng ứng dụng riêng lẻ và cung cấp một nền tảng IAM nhẹ để minh họa các cơ chế cốt lõi của OAuth 2.0, OpenID Connect và quản lý truy cập tập trung.

Hệ thống **không nhằm clone Keycloak/Auth0**. Scope được giới hạn để phù hợp DATN nhưng vẫn tập trung vào các phần có giá trị kỹ thuật cao:

- Centralized authentication
- OAuth 2.0 Authorization Code
- PKCE S256
- OpenID Connect
- Central IdP session + SSO
- JWT access token
- Refresh Token Rotation + reuse detection
- RBAC + OAuth Scope
- MFA TOTP
- Client management
- Audit logging
- Rate limiting / brute-force protection

## 2. Architecture Baseline

Architecture hiện tại đã được freeze và là baseline implementation.

### Demo applications

- **Banking Web / BFF** — Confidential Client
- **Student SPA** — Public Client
- **Admin Portal / BFF** — Confidential Client
- **Banking API** — Protected Resource Server
- **Student API** — Protected Resource Server

### High-level flow

```text
End User
   |
   +------------------------+
   |                        |
   v                        v
Banking Web / BFF        Student SPA
Confidential Client      Public Client
   |                        |
   | Authorization Code     | Authorization Code + PKCE
   | + client auth          | OIDC
   +-----------+------------+
               |
               v
        +-------------------+
        |  Identity Server  |
        | OAuth 2.0 / OIDC  |
        | Auth / MFA        |
        | Token / Session   |
        | RBAC / Management |
        +---------+---------+
                  |
         +--------+--------+
         |                 |
         v                 v
    PostgreSQL           Redis
```

Resource APIs validate JWT **locally** bằng cached OIDC Discovery/JWKS. Không gọi Identity Server để introspect access token ở mỗi request.

## 3. Frozen Technology Decisions

Các quyết định dưới đây là mặc định implementation. Không tự thay đổi khi code nếu chưa cập nhật `IMPLEMENTATION_SPEC.md`.

### Repository

- Package manager: **pnpm**
- Monorepo: **pnpm workspaces**
- Node.js: **24 LTS** (minimum **24.15.0**)
- TypeScript: strict mode
- Backend framework: **NestJS**
- ORM: **Prisma**
- Database: **PostgreSQL**
- Runtime/ephemeral state: **Redis**

### Applications

- `apps/identity-server` — NestJS
- `apps/banking-web` — Next.js BFF/confidential client
- `apps/banking-api` — NestJS
- `apps/student-spa` — React + Vite public client
- `apps/student-api` — NestJS
- `apps/admin-portal` — Next.js BFF/confidential client

### Security defaults

- Password hashing: **Argon2id**
- JWT signing: **RS256**
- PKCE: **S256 only**
- Confidential client authentication: **client_secret_basic**
- Access Token TTL: **10 minutes**
- Authorization Code TTL: **2 minutes**
- Refresh Token TTL: **30 days**
- IdP session idle timeout: **30 minutes**
- IdP session absolute timeout: **8 hours**
- Refresh token: **opaque 256-bit random token**
- Refresh token persistence: **SHA-256 hash only**
- TOTP: **SHA-1 / 6 digits / 30-second period**
- TOTP secret at rest: **AES-256-GCM**
- Session cookie: **HttpOnly**, `SameSite=Lax`, `Secure=true` in production

Chi tiết canonical nằm trong [`IMPLEMENTATION_SPEC.md`](IMPLEMENTATION_SPEC.md).

## 4. Scope

### Included

- Register / login / logout
- Password change / reset
- Account lock / unlock / disable
- Argon2 password hashing
- Failed-login tracking
- Central IdP session
- OAuth Authorization Code
- PKCE S256
- Exact redirect URI validation
- Public/confidential client registration
- OAuth scopes
- Access Token
- ID Token
- Refresh Token
- Refresh Token Rotation
- Token family + reuse detection
- Token/session revocation
- OIDC Discovery
- JWKS
- UserInfo
- OAuth `state`
- OIDC `nonce`
- RBAC
- Permission claims
- MFA TOTP
- SSO
- Audit logs
- Rate limiting / brute-force protection
- Management APIs
- Banking demo
- Student demo
- Admin portal
- Unit / integration / E2E / security / performance tests

### Out of Scope

- SAML
- LDAP / Active Directory
- Social login
- Biometrics
- Kubernetes
- Kafka
- API Gateway
- Service Mesh
- Full enterprise federation
- Full Keycloak/Auth0 feature parity

## 5. Authentication vs Authorization

### Authentication

Trả lời: **Người dùng là ai?**

Cơ chế:

- Username/password
- Central IdP session
- TOTP MFA
- OpenID Connect ID Token

### Authorization

Trả lời: **Người dùng/client được phép làm gì?**

Cơ chế:

- Role
- Permission
- OAuth Scope
- Access-token claims

Ví dụ:

```text
Role:
BANK_EMPLOYEE

Permission:
transaction.view

OAuth Scope:
banking.transactions.read
```

Permission và OAuth Scope là hai khái niệm khác nhau.

Resource Server kiểm tra:

- JWT signature
- `iss`
- `aud`
- `exp`
- OAuth scope
- permission claim

## 6. OAuth 2.0 + OpenID Connect

### Student SPA — Authorization Request

```text
GET /oauth/authorize

response_type=code
client_id=...
redirect_uri=...
scope=openid profile email ...
state=...
nonce=...
code_challenge=...
code_challenge_method=S256
```

Student SPA tạo:

```text
code_verifier
code_challenge = BASE64URL(SHA256(code_verifier))
```

Sau callback:

- Validate `state`
- Exchange authorization code
- Gửi `code_verifier`
- Validate ID Token
- Validate `nonce`

### Token Request

```text
POST /oauth/token

client_id=...
grant_type=authorization_code
code=...
redirect_uri=...
code_verifier=...
```

Banking/Admin confidential clients authenticate bằng `client_secret_basic`.

### OIDC endpoints

```text
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke
GET  /oidc/userinfo
```

## 7. Refresh Token Rotation

Rotation:

```text
RT1
 |
 | refresh
 v
Identity Server
 |
 | atomic transaction
 | consume RT1
 | create RT2
 v
RT2
```

Reuse:

```text
Reuse RT1
   |
   v
RT1 already consumed
   |
   +--> revoke token family
   +--> revoke related IdP session
   +--> write security audit event
   |
   v
invalid_grant
```

Rules:

- Không lưu raw refresh token
- Lưu hash + metadata
- Token family bắt buộc
- Consume-old/create-new phải atomic
- Replay/reuse phải được detect
- Access token ngắn hạn để giới hạn stale authorization claims

## 8. MFA TOTP

Enrollment:

```text
Re-authenticate
   ↓
Generate TOTP secret
   ↓
Encrypt secret with AES-256-GCM
   ↓
Generate otpauth URI / QR
   ↓
Scan QR
   ↓
Submit first TOTP
   ↓
Verify first TOTP
   ↓
Mark MFA enabled
```

TOTP secret không được lưu như password hash một chiều vì server cần secret để verify TOTP.

## 9. Central Session & SSO

Sau login thành công, Identity Server tạo central IdP session.

Khi client thứ hai gọi `/authorize`:

```text
Identity Server
   ↓
Check existing IdP session
   ↓
Session valid
   ↓
Skip password/MFA unless policy requires re-authentication
   ↓
Issue authorization code
```

SSO dựa trên central authenticated session, không phải do client tự bỏ bước login.

## 10. Core Data Model

- User
- Credential
- MFAFactor
- Client
- ClientRedirectUri
- Scope
- ClientScope
- Role
- Permission
- UserRole
- RolePermission
- Session
- RefreshTokenFamily
- RefreshToken
- AuditLog

Redis dùng cho ephemeral/runtime state:

- central session
- authorization code
- MFA challenge
- rate-limit counters
- password-reset tokens

## 11. Repository Structure

```text
iam-system/
├── apps/
│   ├── identity-server/
│   ├── banking-web/
│   ├── banking-api/
│   ├── student-spa/
│   ├── student-api/
│   └── admin-portal/
├── packages/
│   ├── shared-types/
│   ├── shared-config/
│   └── auth-client/
├── docs/
│   ├── architecture/
│   ├── api/
│   └── thesis/
├── AGENTS.md
├── IMPLEMENTATION_SPEC.md
├── TASKS.md
├── docker-compose.yml
├── pnpm-workspace.yaml
└── README.md
```

## 12. Identity Server Modules

```text
src/
├── auth/
├── users/
├── credentials/
├── mfa/
├── oauth/
├── oidc/
├── clients/
├── scopes/
├── tokens/
├── sessions/
├── rbac/
├── audit/
├── security/
├── prisma/
├── redis/
└── config/
```

## 13. Security Rules

- Never store plaintext passwords
- Never store raw refresh tokens
- Never log passwords, TOTP secrets, auth codes, raw tokens, client secrets
- Exact redirect URI validation
- Authorization code: short-lived + one-time
- PKCE S256 for public clients
- Validate OAuth `state`
- Validate OIDC `nonce`
- Validate JWT signature / issuer / audience / expiry
- Resource API validates JWT locally
- Short-lived access token
- Refresh-token rotation + reuse detection
- Rate-limit authentication endpoints
- Encrypt TOTP secrets at rest
- Audit sensitive operations
- Do not implement cryptographic primitives manually
- `/auth/login` does **not** return OAuth access tokens
- OAuth tokens are issued only by `/oauth/token`

## 14. Testing Strategy

### Unit

- Argon2 helpers
- PKCE
- scope calculation
- permission resolution
- JWT helpers
- TOTP helpers

### Integration

- Prisma
- Redis
- IdP session
- Authorization Code
- Refresh-token family

### E2E

- Register/login
- OAuth Authorization Code
- PKCE
- OIDC
- MFA
- SSO
- Refresh Rotation
- Revocation
- RBAC

### Security

- Invalid redirect URI
- Invalid state
- Invalid nonce
- Authorization-code replay
- Invalid PKCE verifier
- Wrong audience
- Expired JWT
- Refresh-token replay
- Brute-force login

## 15. Performance Evaluation

Metrics:

- Throughput
- Average latency
- P50
- P95
- P99
- Error rate

Scenarios:

- Login
- `/oauth/authorize`
- `/oauth/token`
- Refresh Token
- Protected API request

## 16. Implementation Roadmap

`TASKS.md` là **source of truth duy nhất cho milestone numbering, dependency, trạng thái và acceptance criteria**.

Không duplicate milestone numbering trong README để tránh lệch giữa hai tài liệu.

Xem:

- [`TASKS.md`](TASKS.md) — execution backlog
- [`AGENTS.md`](AGENTS.md) — coding-agent rules
- [`IMPLEMENTATION_SPEC.md`](IMPLEMENTATION_SPEC.md) — canonical technical decisions

## 17. Definition of Done

Một task chỉ được coi là hoàn thành khi:

- implementation xong
- acceptance criteria pass
- validation/security edge cases liên quan được xử lý
- lint pass
- typecheck pass
- tests liên quan pass
- không log sensitive data
- tài liệu cần thiết được cập nhật
- có thể verify bằng test hoặc demo flow

## 18. Current Status

**Architecture baseline: frozen.**

Current phase:

```text
Repository docs / implementation contract
        ↓
Foundation
        ↓
Identity / Session
        ↓
OAuth/OIDC
        ↓
Token Security
        ↓
RBAC / MFA / SSO
        ↓
Demo Applications
        ↓
Testing / Benchmark / Thesis
```

## 19. Local Docker Compose startup

Chạy từ repository root với Docker đang hoạt động:

```bash
docker compose up -d --build --wait
docker compose ps
```

Identity Server dùng Node 24.15.0 và pnpm 11.25.0; image tự install frozen
lockfile, generate Prisma Client rồi build ứng dụng. PostgreSQL/Redis phải healthy
trước khi Identity Server khởi động. Kiểm tra `http://localhost:3000/health`:
HTTP 200, `{"status":"ok"}`.

Compose cấp cấu hình development riêng với hostname `postgres`/`redis`, issuer
public `http://localhost:3000` và JWT/TOTP placeholders (không phải key thật).
Không cần copy `.env` cho Compose; `.env.example` vẫn dành cho chạy trên host.
Không chạy seed hay migrations khi khởi động.

Để dừng stack mà giữ PostgreSQL development data:

```bash
docker compose stop
```

Không dùng `docker compose down -v` nếu muốn giữ development database.

## 20. Explicit local seed infrastructure

Với PostgreSQL local đang healthy và `DATABASE_URL` trong package-local `.env`
(hoặc shell environment), chạy từ repository root:

```bash
pnpm --filter identity-server seed
```

Lệnh tự generate Prisma Client rồi gọi `prisma db seed`, dùng `tsx prisma/seed.ts`.
CLI chỉ cần database configuration, không bootstrap NestJS hoặc yêu cầu Redis/JWT/TOTP.
M1.8 chỉ cung cấp infrastructure: kết nối thật, chạy `SELECT 1`, đóng connection
và báo `Seed completed: 0 datasets applied.`; dataset hiện tại cố ý để trống.
Chạy hai lần an toàn/idempotent, không ghi domain data hoặc thay đổi schema.
Domain/demo seed data sẽ được thêm bởi các task sau khi models tương ứng tồn tại.
Seed luôn explicit, không tự chạy khi install, build, start, migrations hoặc Compose startup.
