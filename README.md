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
Seed kết nối thật, chạy `SELECT 1`, áp dụng atomic một demo-registry dataset rồi
đóng connection và báo `Seed completed: 1 datasets applied.` (kể cả rerun không đổi).
Dataset gồm ba demo clients, bốn scopes và exact redirect/allowed-scope mappings
trong `IMPLEMENTATION_SPEC.md` mục 3. Seed lại không tạo duplicates hoặc rotate
confidential secrets đã provision; giữ nguyên unrelated clients/scopes và TTL hiện có.
Student SPA không có secret. Confidential secrets chỉ được provision khi hash NULL
qua ClientSecretService; plaintext return bị bỏ ngay, không hiển thị/log/lưu và
không thể lấy lại bằng seed. Chưa có operator delivery channel.
Kiểm tra PostgreSQL local explicit: `pnpm --filter identity-server seed:check`;
probe chạy seed hai lần trong transaction rồi rollback, giữ nguyên dữ liệu có trước.
Seed luôn explicit, không tự chạy khi install, build, start, migrations hoặc Compose startup.

Kiểm tra lookup read-only trên dataset đã seed:
`pnpm --filter identity-server client-lookup:check`. Probe kiểm tra ba clients/scopes
qua module nội bộ, không mở HTTP server; fixture và disabled-state thử nghiệm đều
rollback, không đổi canonical seed data. Không có OAuth endpoint mới.

## 21. Local registration API

`POST /auth/register` nhận JSON `{email, username, password}` và trả HTTP 201
với đúng các field `{id, email, username, status, createdAt}`. Email/username được
trim nhưng giữ nguyên case; password phải là string không rỗng và được giữ nguyên,
không trim/normalize hoặc áp dụng complexity policy. Unknown fields bị từ chối.
Body không hợp lệ trả 400 an toàn; email/username trùng theo DB uniqueness trả 409.

PasswordService hash Argon2id trước transaction; User và Credential được tạo atomic
với defaults hiện có. Sau commit, Nest Logger phát event tạm thời
`{event: 'USER_REGISTERED', userId}`; chưa có persistent audit storage.
Registration chỉ tạo tài khoản, không login, tạo session/cookie hoặc trả token.
`GET /health` vẫn là process health độc lập với DB; registration cần PostgreSQL.

## 22. Local password reset request API

`POST /auth/password-reset/request` nhận strict JSON `{email}` (trim, giữ case).
Email hợp lệ luôn nhận HTTP 202 `{"status":"accepted"}`, không cookie/token/account
state, kể cả tài khoản không tồn tại, bị disabled hoặc lỗi xử lý nội bộ.
ACTIVE User có Credential được tạo reset state `{userId}` trong Redis, lookup bằng
SHA-256 của token random 256-bit/base64url; `PASSWORD_RESET_TTL_SECONDS` mặc định
900 giây. Login lock/counter không thay đổi. Delivery hiện là internal no-op:
chưa gửi email, không log/return raw token. Chi tiết canonical nằm trong
`IMPLEMENTATION_SPEC.md`.

## 23. Local password reset consume API

`POST /auth/password-reset/consume` nhận strict JSON `{token, newPassword}`;
cả hai là string không rỗng, giữ nguyên whitespace/Unicode, không thêm complexity
policy. Thành công trả 204 không body/cookie. Token unknown/expired/replay hoặc
Credential không còn tồn tại trả cùng 400 `Invalid or expired password reset token.`
GET precheck trước Argon2; atomic GETDEL quyết định one-time ownership. Sau GETDEL,
token không được khôi phục kể cả DB lỗi; người dùng cần yêu cầu token mới.
Chỉ cập nhật Credential và phát event `PASSWORD_RESET` sau DB success, không đổi
account status/lock/counter hay revoke session/token. Delivery vẫn là no-op.

## 24. Local IdP login API

`POST /auth/login` nhận strict JSON
`{identifier: {type: "email" | "username", value}, password}`; hai string không
rỗng được giữ nguyên, không tự suy luận email/username. Thành công trả 204 không
body và một session cookie chứa UUID mới do PostgreSQL cấp, dùng cùng ID/absolute
expiry cho Redis. Cookie chỉ được phát sau khi PostgreSQL transaction và Redis
state creation thành công.

Lỗi xác thực dùng chung 401, body/JSON sai dùng 400, lỗi nội bộ dùng 500; không phát
cookie khi lỗi. Incoming cookie không được tái sử dụng làm ID mới. Không trả OAuth
tokens hay tạo global session middleware.
Session-management và valid authorize xác thực/touch cookie riêng trong phạm vi đó;
chưa có global session middleware.
Sau build, chạy probe local explicit với PostgreSQL/Redis và Compose API đang up:
`pnpm --filter identity-server login:check`. Probe dùng dữ liệu tạm và cleanup;
chi tiết consistency/rollback nằm trong implementation spec.

## 25. Local IdP logout API

`POST /auth/logout` chỉ nhận session ID từ configured IdP cookie (`iam.sid` mặc
định), qua parser hiện có. Thành công trả 204 không body và clearing Set-Cookie:
`iam.sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` (thêm Secure theo config).
Thiếu/malformed/duplicate cookie vẫn trả 204 và clear cookie, không gọi stores.

Logout xóa Redis runtime state trước, rồi đổi Session ACTIVE thành REVOKED; giữ
row, timestamps và metadata. Lặp/đồng thời hoặc session đã thiếu/revoked đều an
toàn/idempotent. Lỗi Redis/DB trả generic 500, không clear cookie để có thể retry;
nếu DB lỗi sau DEL, không tạo lại Redis state. Không có cross-store transaction,
OAuth token, public session-check/listing API hay logout audit mới.

Sau build và Compose startup, chạy `pnpm --filter identity-server logout:check`.
Probe kiểm tra stack thật, concurrent logout, Redis outage/reconnect và controlled
DB revoke failure/retry; chỉ cleanup dữ liệu tạm của probe và đóng app/proxy/clients.

## 26. Local own-session management API

`GET /auth/sessions` và `DELETE /auth/sessions/:sessionId` chỉ xác thực bằng IdP
cookie: parse → Redis touch → matching ACTIVE PostgreSQL session chưa hết hạn.
Không nhận userId/current session ID từ body/query/header hoặc Bearer token.
Thiếu/invalid/inconsistent session trả chung 401 `Authentication required.`;
lỗi hạ tầng trả 500 `Session management failed.`.

GET trả `{sessions: [...]}` với id, ISO createdAt/lastActivityAt/expiresAt,
nullable ipAddress/userAgent và current. Chỉ list session ACTIVE còn runtime live
của subject, theo createdAt DESC/id DESC; activity lấy từ Redis. Không refresh
TTL của session khác, write PostgreSQL, phát cookie hay trả userId/secrets/tokens.

DELETE kiểm tra UUID (400 nếu sai) và ownership trước khi reuse logout service;
target unknown/cross-user đều 404, không invalidate target. Thành công trả 204:
self-revoke clear cookie, revoke session khác không clear. Owned revoked/missing
runtime targets vẫn idempotent; self-revoked cookie không còn authenticate được.
Không có admin authority, OAuth/token, global auth guard hay persistent audit mới.

Sau build/Compose startup chạy `pnpm --filter identity-server own-sessions:check`.
Probe kiểm tra list/TTL, own revoke, cross-user IDOR, self/concurrent revoke,
Redis outage/reconnect và chỉ cleanup dữ liệu/clients/server/proxy tạm của probe.

## 27. Internal target-user session revocation

`AdminSessionRevocationService.revokeUserSessions(targetUserId)` là capability
nội bộ, chỉ được gọi sau khi future trusted management/RBAC layer đã authorize
action. Service không tự xác thực/cấp quyền admin, không có public HTTP endpoint,
admin header/secret hay Role/Permission model. Own-session API giữ nguyên ownership.

Validate UUID rồi query PostgreSQL ACTIVE session IDs của target theo id ASC,
không scan/pre-read Redis. Reuse logout service tuần tự; unknown/zero-session
target thành công idempotent. Chỉ revoke snapshot đã discover, không disable
account hoặc ngăn login mới. Lỗi dừng xử lý, giữ các revoke đã hoàn tất; không
khôi phục Redis. Retry discover lại ACTIVE rows và hoàn tất phần còn lại/partial.

Sau build/Compose startup, chạy `pnpm --filter identity-server admin-sessions:check`.
Probe gọi service nội bộ với PostgreSQL/Redis thật, kiểm tra isolation, partial
failure/retry, concurrency, snapshot và HTTP admin paths vẫn 404; chỉ cleanup data
của probe và đóng clients, không tạo admin endpoint/server.

## 28. Authorization endpoint

`GET /oauth/authorize` hiện validate request rồi gate bằng central IdP session
(M5.1-M5.6), sau đó generate/store code và trả callback 302; chưa issue token. OAuth request lỗi vẫn trả 400 trước
mọi session touch. Request OAuth hợp lệ nhưng chưa xác thực trả chung 401
`Authentication required.`. Cookie configured -> Redis touch -> matching ACTIVE,
unexpired/coherent PostgreSQL Session là authority; không dùng query/Bearer hay
một store riêng lẻ. Lỗi hạ tầng trả safe 500, không bị hiểu thành logged out.
Session hợp lệ và code đã persist trả 302 Found, Location chứa đúng code M5.5 đã
issue và state gốc, body rỗng, không Set-Cookie hoặc subject data.
Idle activity/TTL có thể advance theo M3, không đổi absolute expiry hay PostgreSQL.
Chưa có login UI/return_to/continuation state: gọi existing POST /auth/login rồi
gửi lại ĐÚNG authorize request ban đầu với iam.sid để resume. Logout/revocation
ngăn cookie đó tiếp tục authorize. M6 token endpoint/consume vẫn chưa triển khai.
Client/redirect được kiểm tra exact. Sau PKCE, allowed scopes được đọc từ
ClientScope bằng internal Client.id; mọi requested scope phải thuộc allowed set
exact, nếu không trả `invalid_scope` (400), không drop scope rồi tiếp tục.
Granted scopes loại duplicate theo thứ tự requested đầu tiên; M5.5 lưu đúng kết quả
này trong code state sau khi xác thực, không trả HTTP body. Lỗi scope lookup trả safe 500.
State bắt buộc, exact `openid` cần nonce. PUBLIC bắt buộc đủ cặp PKCE;
confidential được bỏ cả hai field hoặc gửi đủ cặp. Method phải exact `S256`,
challenge đúng 43 ký tự `[A-Za-z0-9_-]`, không padding/trim/repair. Chưa xử lý hay
hash/verify `code_verifier`; việc đó thuộc M6.3.

Lỗi validation trả trực tiếp HTTP 400 JSON OAuth với description cố định, không
echo query values hoặc redirect tới URI do caller cung cấp. Lỗi nội bộ trả 500 an
toàn. Mọi lỗi 400/401/500 vẫn không Location hoặc code/state echo, kể cả invalid
redirect. Không có OAuth error redirects, token hoặc session mechanism mới.

M5.6 chỉ dùng redirect_uri/state đã validate và raw code đã issue từ internal
AuthorizationResult, không đọc lại raw query/header hay lookup registry lần nữa.
Callback builder giữ nguyên URI text/query ordering/percent encoding, chỉ append
query-component encoded code/state (trước fragment nếu có). Không serialize lại
toàn bộ URL. Không ghi/read/touch/delete code Redis để dựng callback, không phát
code thứ hai hay log Location. Delivery lỗi không rollback code; entry tự expire.

M5.5 dùng random 256-bit (`randomBytes(32)`, base64url không padding), SHA-256 raw
code thành lowercase hex và reserve `oauth:code:{codeHash}` bằng SET EX 120 NX.
Strict JSON chỉ có clientId/userId/redirectUri/grantedScopes/codeChallenge/nonce/
authTime/expiresAt; protocol clientId và exact validated values được giữ nguyên,
userId/authTime lấy từ central session, PKCE/nonce vắng mặt hợp lệ dùng null.
Expiry = một issue instant + 120000 ms; TTL cố định 120 giây. Collision không ghi đè,
retry fresh code tối đa 3 lần, lỗi trả cùng safe 500. Raw code chỉ transient nội bộ,
không nằm trong Redis/log/error/HTTP body; M5.6 chỉ đưa raw code vào validated
Location. Chưa có consume/GETDEL, verifier hay token endpoint.

Sau build và Compose startup chạy `pnpm --filter identity-server authorize:check`.
Probe kiểm tra M5.1-M5.3 regressions trước session, login -> cookie -> same request
resume trên PostgreSQL/Redis/HTTP thật, idle/absolute/coherence/logout và controlled
infrastructure failures. Authorize không write PostgreSQL; login dùng fixture
User/Credential/Session riêng có cleanup. Probe kiểm tra real hash-only code state,
TTL, hai code độc lập, collision/retry/exhaustion và disconnected code Redis failure;
M5.6 đối chiếu code từ Location với Redis hash/state/TTL, exact registered query/
fragment và reserved/Unicode state bằng registry fixture riêng, không sửa demo seed;
chỉ xóa code/session keys thuộc probe. Disabled fixture rollback; snapshot DB/Redis
được khôi phục sau probe, giữ nguyên seed và đóng servers/clients tạm.
