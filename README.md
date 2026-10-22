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
public `http://localhost:3000` và TOTP placeholder (không phải key thật).
JWT keys được provision explicit (mục 32), mount read-only từ host, không COPY vào
image. Chưa có keys vẫn startup/health được; token signing sẽ fail closed.
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
ngăn cookie đó tiếp tục authorize. M6.7 hiện đổi code lấy signed access token qua POST /oauth/token.
Client/redirect được kiểm tra exact. Sau PKCE, allowed scopes được đọc từ
ClientScope bằng internal Client.id; mọi requested scope phải thuộc allowed set
exact, nếu không trả `invalid_scope` (400), không drop scope rồi tiếp tục.
Granted scopes loại duplicate theo thứ tự requested đầu tiên; M5.5 lưu đúng kết quả
này trong code state sau khi xác thực, không trả HTTP body. Lỗi scope lookup trả safe 500.
State bắt buộc, exact `openid` cần nonce. PUBLIC bắt buộc đủ cặp PKCE;
confidential được bỏ cả hai field hoặc gửi đủ cặp. Method phải exact `S256`,
challenge đúng 43 ký tự `[A-Za-z0-9_-]`, không padding/trim/repair. M6.3 hiện verify
`code_verifier` tại token endpoint, sau atomic code consumption.

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
Location. M6.2 consume/GETDEL, M6.3 verify PKCE và M6.7 issue access token tại token endpoint.

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

## 29. Token request boundary, client authentication, consumption and PKCE (M6.1–M6.4)

`POST /oauth/token` chỉ nhận form `application/x-www-form-urlencoded` từ body:
`grant_type`, `client_id`, `code`, `redirect_uri` là scalar string không rỗng;
`code_verifier` optional, nếu có phải là scalar string, kể cả chuỗi rỗng để M6.3
phân loại sau consumption. Strict schema
reject unknown/repeated/structured fields; giữ nguyên decoded values, không trim,
normalize hay decode lần hai. Chỉ exact `authorization_code` được chấp nhận.
Shape/parser/media-type lỗi trả fixed 400 `invalid_request` / `Invalid token request.`;
grant khác nhưng đúng shape trả fixed 400 `unsupported_grant_type` / `Unsupported grant type.`.
TokenRequestService vẫn chỉ validate, không I/O. Request hợp lệ qua M6.4 trước M6.2:
lookup exact body `client_id`, không trim/case-fold/Unicode normalize/fallback.
PUBLIC Student SPA không cần secret và chỉ đi tiếp khi không gửi Authorization;
gửi Basic hoặc authentication khác bị reject. Banking/Admin CONFIDENTIAL bắt buộc
`client_secret_basic`: scheme không phân biệt hoa thường, strict standard Base64/UTF-8,
split colon đầu tiên rồi form-decode từng component đúng một lần; Basic client_id phải
exact-match body client_id. Verify secret bằng Argon2 với persisted Argon2id hash,
không trả hash khỏi capability, không gọi issuance/rotation. Unknown/disabled/missing/
malformed/unsupported/mismatch/absent hash/wrong secret cùng fixed **401 `invalid_client`** /
`Client authentication failed.` và `WWW-Authenticate: Basic realm="oauth/token"`.
Auth lỗi không hash/GETDEL/burn code hoặc thay expiry; DB/Argon2/internal lỗi cùng fixed
500 `server_error` / `Token request failed.`, không native cause hay private logs.
Sau auth thành công mới vào M6.2:
SHA-256 exact raw code → `oauth:code:<lowercase hex>` → một native Redis GETDEL
→ canonical JSON/schema → expiresAt > safe current time → exact client_id/redirect_uri
binding. Consume capability không trim/normalize/decode lần hai hoặc tự lookup DB/registry. Unknown code, replay,
Redis/logical expiry hoặc sai binding cùng trả fixed 400 `invalid_grant` /
`Invalid authorization grant.`. JSON/schema hỏng, hashing/Redis/clock lỗi trả fixed
500 `server_error` / `Token request failed.`. Sau GETDEL không restore, kể cả sai binding.
Sau consume, M6.3 yêu cầu verifier dài 43..128 ký tự ASCII unreserved `[A-Za-z0-9._~-]`
khi stored challenge khác null; tính SHA-256 ASCII/base64url không padding và so sánh
exact, không plain fallback/trim/normalize/decode lại. Thiếu/rỗng/sai syntax/sai verifier
cùng trả fixed `invalid_grant` và code vẫn bị burn; retry không cứu được code.
Challenge null không yêu cầu PKCE và bỏ qua verifier optional; không bỏ qua M6.4 client auth.
Auth thành công phải có registry audience không rỗng và TTL positive safe integer
trước GETDEL; thiếu/hỏng trả safe 500, không burn code, không phải invalid_client.
Consume/PKCE thành công tiếp tục M6.7: HTTP 200 JSON access token (mục 32),
`Cache-Control: no-store`, `Pragma: no-cache`, không Location/Set-Cookie.
`GET /oauth/token` vẫn 404.

Sau build/Compose startup chạy `pnpm --filter identity-server token-request:check`:
synthetic malformed/unsupported requests phải giữ nguyên matching code sentinel;
well-shaped unknown code của enabled PUBLIC client đi qua GETDEL và trả invalid_grant,
unknown client trả invalid_client trước GETDEL. Code-value/expiry
snapshots và fingerprint 8 bảng DB không đổi; probe chỉ cleanup key của chính nó.

Chạy `pnpm --filter identity-server authorization-code-consume:check` để kiểm tra
first consume/replay/unknown, đúng 1/12 concurrent winner, Redis TTL và logical expiry,
exact binding/burn, opaque code, S256 verifier 43/128, PKCE failure burn/replay,
null-challenge và malformed state trên Nest/Redis thật. Chỉ dùng
synthetic code/state và một PUBLIC client fixture riêng, không consume M5 codes,
không flush/xóa unrelated keys; fingerprint DB được restore sau cleanup fixture,
unrelated code snapshots không đổi, owned keys được cleanup.
Redis/hash failures được kiểm tra deterministic bằng unit/HTTP tests; không gây outage
cho shared Compose. Không in code/verifier/hash/state hoặc private driver details.

Chạy `pnpm --filter identity-server client-authentication:check` để kiểm tra PUBLIC,
Banking/Admin-like và opaque client fixtures với Argon2id thật, các auth lỗi giữ nguyên
code/value/expiry rồi retry valid thành công, PKCE lỗi vẫn burn sau auth, null challenge
vẫn cần confidential auth. Probe chỉ tạo/xóa UUID-owned clients/codes, restore fingerprint
8 bảng DB và giữ nguyên unrelated codes; không thay canonical seed hashes hay giải quyết
one-time demo secret delivery. Unit/HTTP tests cover DB/Argon2 faults, no logs/leaks,
safe metadata projection, không gọi secret issuance và PUBLIC không chạy Argon2.

## 30. Internal signing-key capability

`SigningKeyModule` cung cấp lazy `SigningKeyService` bằng `jose`, được M6.7 gọi sau
consume/PKCE. Dùng ba biến JWT key hiện có; private phải là RSA PKCS#8 PEM, public
là SPKI PEM cùng key pair, modulus tối thiểu 2048 bit. Chi tiết canonical/API/JWK
nằm ở `IMPLEMENTATION_SPEC.md` mục 8.

Lần gọi đầu load/validate pair; concurrent calls chia sẻ một initialization. Bộ key
hợp lệ được cache suốt lifetime; lỗi chỉ trả `Signing key initialization failed.`,
không native cause/PEM/path logs, không cache key set dở dang. Public JWK chỉ có
`kty`, `kid`, `alg`, `use`, `n`, `e`; private key chỉ dành cho nội bộ Identity Server.

Key paths trong `.env.example`/Compose không được load lúc startup hay
`GET /health`. Provision development explicit theo mục 32; không có production
rotation; public JWKS có ở mục 34, Discovery metadata ở mục 33. Không commit private key.
Tests dùng ephemeral keys và cleanup temporary files, không cần operational key.

## 31. Internal access-token claim capability

`TokensModule` cung cấp `AccessTokenClaimsService.build(...)`, chỉ dựng đúng payload
`iss/sub/aud/iat/exp/scope/roles/permissions`; chỉ issuer M6.7 mới ký/trả token. Issuer lấy từ
config; subject UUID và audience explicit do trusted caller cung cấp. Time dùng
một clock instant, NumericDate seconds; TTL từ access-token config (default 600s)
hoặc positive safe-integer override. Scope dùng granted values giữ nguyên order;
roles/permissions là input riêng (được []), không resolve RBAC hay map từ scope.
Chi tiết validation/defensive copies nằm ở `IMPLEMENTATION_SPEC.md` mục 9.

Capability không đọc DB/Redis/network/key files, không import/call signing service
hay JOSE. M9.1-M9.3 mới persist/resolve RBAC, M9.4 mới cung cấp resolved values.
M6.7 kết hợp claims và signing qua service riêng; Discovery/JWKS có ở mục 33–34.

## 32. Authorization-code access-token issuance (M6.7)

Thứ tự: M6.1 shape/grant → M6.4 client auth → validate registry audience/TTL
→ M6.2 GETDEL/binding/expiry → M6.3 PKCE → claims → JOSE RS256 → HTTP 200.
Client auth chọn audience/TTL cùng query hiện có, chỉ trả metadata an toàn.
`Client.accessTokenAudience` nullable không default/backfill; NULL vẫn authenticate
được nhưng chưa cấu hình issuance. Explicit seed converges:
student-spa → student-api; banking-web → banking-api; admin-portal → identity-server.
Seed giữ nguyên IDs, secrets, redirects/scopes và TTL; unrelated records không đổi.

`AccessTokenIssuerService` dùng subject/grantedScopes từ consumed state, audience/TTL
từ authenticated client và roles=[]/permissions=[] cho tới M9.4. JWT có đúng tám
claims mục 31, header đúng `{alg: 'RS256', kid}`; không typ hoặc clock thứ hai.
Response JSON đúng bốn field: `access_token`, `token_type: "Bearer"`,
`expires_in: exp-iat`, `scope`. Không ID/refresh token, kể cả scope openid.
Key/claims/signing failure sau GETDEL trả fixed 500 `server_error` /
`Token request failed.`; code vẫn burn, retry trả invalid_grant, không restore.

Provision local development/test một lần trước live signing probes:

```bash
pnpm --filter identity-server dev-keys:generate
```

Lệnh explicit tạo RSA-2048 PKCS#8 `dev-keys/private.pem` và SPKI `dev-keys/public.pem`
trong package; thư mục ignored, từ chối overwrite kể cả partial provisioning.
Không chạy tự động khi install/build/start/seed. Private mode 0600 và directory 0700
nơi được hỗ trợ; trên Windows cần bảo vệ ACL thư mục. Đây không phải production
key management/rotation. Compose mount read-only; không đưa PEM vào image/Git.
Nếu `.env` cũ dùng placeholder filenames, cập nhật hai JWT paths theo `.env.example`
hoặc override bằng shell; giữ JWT_KEY_ID nhất quán giữa server và probe.

Sau migration, explicit seed, build và Compose rebuild, chạy ba M6 probes ở mục 29.
Các probe success verify chữ ký bằng public dev key với algorithms=['RS256'],
audience/TTL/grants/subject/header/claim allowlists; không in compact JWT.
Vẫn giữ fingerprint 8 bảng, unrelated Redis code value/absolute expiry và cleanup
chỉ fixture sở hữu. Full OAuth authorize/login E2E hiện có riêng ở M6.8:

```bash
pnpm --filter identity-server authorization-code-e2e:check
```

Probe dùng canonical PUBLIC student-spa, scope profile và user đăng ký qua API thật:
register → authorize 401 → login/cookie → cùng authorize request → callback/state
→ PKCE token → verify RS256/public key → replay invalid_grant. Cần stack/seed/keys
đã sẵn sàng; không tự seed, generate/rotate keys hoặc follow callback tới frontend.
Cleanup chỉ user/session/code của lần chạy; fingerprint 8 bảng và unrelated Redis
values/absolute expiry phải giữ nguyên. Chạy trên stack local yên tĩnh, không in
password/cookie/code/verifier/JWT. Đây chỉ là OAuth E2E, chưa kiểm chứng full OIDC
hoặc ID/refresh token.

## 33. Public OpenID Provider Discovery (M7.1)

`GET /.well-known/openid-configuration` trả 200 JSON public, no-store, không yêu cầu
login hoặc phát cookie/redirect. Metadata chỉ đọc ConfigService, không truy cập
PostgreSQL/Redis/signing keys và không cần provision key files để fetch Discovery.
Issuer giữ nguyên validated ISSUER_URL; endpoints dựng bằng URL API với root paths.
Query/fragment/credentials trong issuer bị từ chối bằng safe 500 tại Discovery,
không silently normalize hoặc thay global validation/M6 behavior.

Advertise đúng openid/profile/email, code/query, authorization_code, public subject,
RS256, client_secret_basic + none và S256. claims/request/request_uri đều unsupported.
Không advertise application-specific banking scope hoặc refresh grant.
Chi tiết exact allowlist/issuer-path behavior nằm trong implementation spec mục 4.

JWKS URL đã live trong M7.2 (mục 34); UserInfo vẫn 404 cho tới M7.4.
Chưa phát ID Token qua HTTP, map profile/email claims hoặc hoàn tất OIDC E2E. M6.8 vẫn kiểm tra
OAuth pipeline cũ, chỉ cập nhật expectation Discovery/JWKS từ 404 sang 200.

```bash
pnpm --filter identity-server discovery:check
```

Live check chỉ dùng issuer và HTTP, không mở DB/Redis clients, login hoặc đọc key
files trực tiếp. Assertion JWKS 200 yêu cầu server đã có signing pair hợp lệ;
fetch Discovery riêng vẫn không cần key files.

## 34. Public JWKS (M7.2)

`GET /.well-known/jwks.json` trả public 200 JSON với đúng một current public key:
`{keys: [{kty: "RSA", kid, alg: "RS256", use: "sig", n, e}]}`. Top-level chỉ có
keys; JWK chỉ sáu fields đó, không private RSA parameters, PEM, paths hoặc native
key objects. kid/n/e lấy nguyên vẹn qua `SigningKeyService.getPublicJwk()`;
kid khớp protected header của access token M6.7. Không lựa chọn key theo query,
headers hoặc cookie, không auth/redirect/Set-Cookie.

Cache thành công là `public, max-age=300` (MVP: 300 giây); không ETag,
Last-Modified hay conditional GET. Discovery giữ `no-store`. JWKS request mới
gọi lazy M6.5 để load/validate cả signing pair; startup/health/Discovery không
gọi key getters. Thiếu/hỏng pair trả fixed 500 `server_error` /
`JWKS request failed.`, `no-store`, không native detail hoặc sensitive logs.
Không đọc PEM/export JWK lần nữa ở JWKS layer, không second cache, rotation,
multi-key, auto-generation hoặc DB/Redis dependency. UserInfo/ID Token/refresh
và full OIDC E2E chưa được implement bởi M7.2.

```bash
pnpm --filter identity-server jwks:check
```

Probe HTTP read-only kiểm tra shape/allowlist, kid, cache/headers và JOSE import
public JWK để verify RS256; cần stack và signing pair có sẵn, không tạo/rotate
keys, mutate stores hoặc in key material/configuration.

## 35. Internal ID Token capability (M7.3)

OidcModule có `IdTokenClaimsService` và `IdTokenIssuerService` nội bộ, không export
hoặc thêm HTTP route. Builder chỉ tạo sáu claims `iss/sub/aud/iat/exp/nonce`:
issuer giữ nguyên config với OIDC URL policy như Discovery; subject là UUID User.id;
audience là OAuth **client_id**, ví dụ student-spa, không phải student-api.
Nonce bắt buộc không rỗng và giữ nguyên opaque value. TTL là input positive safe
integer bắt buộc, không env/default/access-token TTL ngầm định; dùng một clock
instant và NumericDate seconds, reject overflow.

Issuer trả `{idToken}`, ký JOSE RS256 với header đúng `{alg: "RS256", kid}` qua
SigningKeyService hiện có, cùng key/kid được JWKS publish. Không thêm auth_time,
azp, at_hash hoặc profile/email claims, không key path/cache mới hay eager loading.
Lỗi chỉ fixed sanitized message, không native cause hoặc token/key/nonce logs.
Chi tiết canonical nằm ở implementation spec mục 10.

`POST /oauth/token` vẫn chỉ trả bốn access-token fields, không id_token kể cả
grant openid. M7.6 mới tích hợp ID Token vào HTTP response; UserInfo và profile
mapping vẫn thuộc M7.4/M7.5. Không refresh token hoặc OIDC E2E mới.
