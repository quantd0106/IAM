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

M4.1 persistence baseline: standalone `Client` maps to `clients`, with a
Prisma-generated internal UUID `id` (not the OAuth identifier), exact unique text
`client_id`, required text `name`, and required explicit `client_type` enum
`PUBLIC` / `CONFIDENTIAL` without a default. Strings are not normalized.
`client_secret_hash` is nullable; public clients may have NULL, and M4.1 does not
require a secret hash for confidential clients. `enabled` defaults to true.
`access_token_ttl` and `refresh_token_ttl` are integer seconds, defaulting to 600
and 2592000 respectively; explicit values persist unchanged. No other columns,
relations or custom CHECK policies are added.

M4.1 creates no client secret or OAuth endpoint. Secret lifecycle belongs to
M4.4, redirect URIs to M4.2, scopes to M4.3, demo clients to M4.5, and
lookup/disabled-client rejection logic to M4.6. The client classes below describe
those future registrations, not seed data introduced by M4.1.

M4.2 persistence baseline: `Client.redirectUris` represents zero, one or many
`ClientRedirectUri` rows in `client_redirect_uris`. Each row has only a
Prisma-generated UUID `id`, required UUID `client_id` referencing internal
`Client.id` (not the OAuth client_id string), and required exact text
`redirect_uri`. The composite `(client_id, redirect_uri)` is unique; different
clients may register the same URI. Prisma's default FK behavior is ON DELETE
RESTRICT / ON UPDATE CASCADE; no client-deletion lifecycle is introduced.

Registry equality is exact only, without normalization or wildcard/pattern
interpretation. URI values are opaque persistence strings in M4.2, with no new
registration URI policy or custom CHECK constraints. No demo client/redirect
rows, runtime lookup service or HTTP endpoint are added; runtime lookup and
authorization-request validation belong to M4.6/M5.1 respectively.

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

### M4.5 explicit demo seed

The existing `pnpm --filter identity-server seed` command applies one logical
demo-registry dataset per successful invocation (also 1 on an unchanged rerun):

| client_id | name | type | exact redirect URI | allowed scopes |
| --- | --- | --- | --- | --- |
| student-spa | Student SPA | PUBLIC | http://localhost:3200/callback | openid, profile, email |
| banking-web | Banking Web / BFF | CONFIDENTIAL | http://localhost:3100/auth/callback | openid, profile, email, banking.transactions.read |
| admin-portal | Admin Portal / BFF | CONFIDENTIAL | http://localhost:3300/auth/callback | openid, profile, email |

All three are enabled. Upsert exact identifiers and the four scope names above
without normalization. Creation uses existing UUID/TTL defaults; preserve existing
TTLs and IDs. Converge canonical name/type/enabled and each canonical client's
exact redirect/allowed-scope set, removing only extra registrations belonging to
those three clients. Never delete unrelated clients/scopes or change unrelated
registrations. Student SPA's hash is always NULL.

Connect, check `SELECT 1`, then apply the complete registry in one PostgreSQL
transaction and disconnect. Provision only NULL confidential hashes through the
existing M4.4 ClientSecretService on that same transaction, preserving CAS and
rollback on failure. Already provisioned hashes never rotate on seed reruns.
There is no safe operator delivery channel yet: discard the service's one-time
plaintext return immediately, without logging, output, retention or plaintext
persistence. It is not recoverable; later authorized rotation/delivery is separate
work, not a seed rerun. Seed failure exposes only sanitized errors. Seeding is
explicit, never startup/install/migration behavior; it adds no runtime lookup,
OAuth authentication, endpoint, schema or migration.

### M4.6 internal read-only lookup

ClientRegistryModule exports ClientLookupService and ScopeLookupService alongside
the unchanged ClientSecretService; it remains non-global and imports only
PrismaModule. Both lookup services use injected PostgreSQL/Prisma delegates with
no writes, Redis, cache or logging.

`ClientLookupService.requireEnabledClient(clientId): Promise<EnabledClient>`
looks up the unique exact OAuth `client_id`, not internal UUID, without trimming,
case conversion, Unicode normalization, aliases, patterns or fallback queries.
Unknown and disabled clients both throw `Client unavailable.`; database failures
throw `Client lookup failed.` without identifiers, SQL or attached driver causes.
EnabledClient contains only id, clientId, name, clientType, accessTokenTtl,
refreshTokenTtl and registered redirectUris (exact strings, code-unit sorted).
No secret hash is selected/read/exposed. This is not client authentication or
redirect URI validation; future M5 validation consumes these registrations.

`ScopeLookupService.getAllowedScopeNames(clientRecordId): Promise<string[]>`
accepts internal Client.id using the existing UUID convention (`z.uuid()`),
querying ClientScope -> Scope and selecting names only. Malformed UUID fails
before querying with `Invalid client record identifier.`; database failures use
`Scope lookup failed.` without private causes. Return unique exact names in
JavaScript code-unit order, without normalization, default scopes, permission
mapping or requested/allowed intersection. No assignments (including unknown
valid UUID) yields []. The normal caller first resolves an enabled client; this
capability does not repeat enabled validation or make the two reads atomic.
OAuth error mapping/authorization policy remain M5+ work, not internal lookup
errors or new HTTP endpoints.

### M6.7 access-token audience configuration

M6.7 extends the historical M4 Client baseline with nullable exact text
`accessTokenAudience` mapped to `access_token_audience`, without a default or
migration backfill. NULL is an authenticated but unconfigured issuance client,
not invalid credentials. Explicit demo seed now converges only these audiences:
student-spa -> student-api; banking-web -> banking-api; admin-portal -> identity-server.
Existing IDs, TTLs, secrets, redirects, scopes and unrelated records stay unchanged.

---

## 4. OAuth / OIDC Endpoints

```text
GET  /oauth/authorize
POST /oauth/token
POST /oauth/revoke

GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /oidc/userinfo
POST /oidc/userinfo
```

### M7.1 OpenID Provider Discovery

GET /.well-known/openid-configuration returns public HTTP 200 application/json,
Cache-Control: no-store, without authentication, Location or Set-Cookie.
DiscoveryController -> DiscoveryService -> ConfigService remains Config-only;
building metadata performs no PostgreSQL, Redis, filesystem, signing-key, token,
registry, request-header or network access and never mutates state.

The exact allowlist is issuer, authorization_endpoint, token_endpoint,
userinfo_endpoint, jwks_uri, scopes_supported, response_types_supported,
response_modes_supported, grant_types_supported, subject_types_supported,
id_token_signing_alg_values_supported, token_endpoint_auth_methods_supported,
code_challenge_methods_supported, claims_parameter_supported,
request_parameter_supported and request_uri_parameter_supported. No other metadata
or environment fields are returned.

Issuer is the exact existing validated ISSUER_URL string, shared with token iss;
never derive it from Host/forwarded headers/Origin/query or normalize it here.
Use new URL(rootPath, issuer).href for /oauth/authorize, /oauth/token,
/oidc/userinfo and /.well-known/jwks.json. Trailing slash and issuer path values
remain unchanged in issuer; endpoint paths are deliberately root-absolute, not
issuer-path-prefixed, and no extra route aliases/mounts are introduced. The URL API
may canonicalize endpoint URLs but must not rewrite the issuer property.

The existing global URL validator remains unchanged. At the Discovery boundary,
reject query/fragment components (including empty ?/#) and URL credentials
instead of stripping/echoing them. This avoids invalid issuer metadata or credential
disclosure, following the no-query/no-fragment issuer requirement in
[OpenID Connect Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata).
Local HTTP remains the explicit development exception; production HTTPS is enforced
by existing env validation. Invalid metadata/config/internal failures return fixed
HTTP 500 {error: 'server_error', error_description: 'Discovery request failed.'}
without native causes, configuration values or sensitive logs.

Advertise exactly: scopes [openid, profile, email] (not banking.transactions.read),
response types [code], response modes [query], grants [authorization_code], subjects
[public], ID-token signing algorithms [RS256], token auth methods
[client_secret_basic, none] and PKCE [S256]. claims_parameter_supported,
request_parameter_supported and request_uri_parameter_supported are all false.
No refresh grant, implicit/hybrid, other algorithms/auth methods, dynamic
registration, revocation, request objects, encryption, logout or other capabilities.

The advertised jwks_uri is live in M7.2 below; userinfo_endpoint is live in M7.4
as a Bearer-protected resource (401 without credentials). M7.5 supplies scope-limited
UserInfo mapping below; M7.6 integrates the M7.3 ID Token capability and real OIDC
Authorization Code E2E in section 10, without changing Discovery metadata.
Discovery works without provisioned key files. Explicit discovery:check fetches
the live metadata and verifies the exact allowlist/staged routes without store
clients, login or direct key-file reads. Its JWKS HTTP assertion now requires the
server's existing valid signing pair; Discovery itself still needs no key files.

### M7.2 public JWKS

GET /.well-known/jwks.json is public, unauthenticated HTTP 200 application/json.
The exact response is {keys: [{kty: 'RSA', kid, alg: 'RS256', use: 'sig', n, e}]}:
only keys at the top level, exactly one current key, and exactly those six JWK
fields. No private RSA parameters (d/p/q/dp/dq/qi/oth), PEM, native key objects,
paths, certificates or other export/config metadata are published.

The existing non-global OidcModule imports SigningKeyModule and wires
JwksController -> JwksService -> SigningKeyService.getPublicJwk(). The JWKS service
has only that dependency, uses an explicit six-field projection (no arbitrary
spread), and creates a fresh document/array/JWK on each build. Preserve kid/n/e
exactly from M6.5; kid is the same configured identifier used by the M6.7 access
token protected header. No direct filesystem, JOSE conversion, key math, second
cache, database, Redis or session access is introduced at the JWKS boundary.
Headers, credentials, cookies and query parameters never select/change the key.

An explicit JWKS request lazily requires the complete M6.5 validated RSA signing
pair (matching PKCS#8 private/SPKI public, RS256, >=2048 bits), not just a public
PEM. M6.5 retains the sole loading/validation/lifetime cache boundary. Module
construction, startup, /health and Discovery never request keys. Unavailable or
invalid signing material/internal failures return fixed HTTP 500
{error: 'server_error', error_description: 'JWKS request failed.'}, Cache-Control:
no-store, without native causes, configuration values or sensitive logs.

Successful JWKS responses use exactly Cache-Control: public, max-age=300, an MVP
300-second public verification-metadata cache choice. No Set-Cookie, Location or
WWW-Authenticate; no ETag, Last-Modified or conditional-GET behavior is added.
There is no rotation, multiple-key publication, auto-generation or reload.
Discovery keeps no-store and its unchanged metadata. M7.4 adds protected UserInfo,
extended by M7.5 below. M7.6 integrates ID Token HTTP issuance and OIDC E2E using
these unchanged public keys and the existing M7.3 capability.

Explicit jwks:check performs only HTTP reads and JOSE public-JWK import against
the existing local stack/signing pair; it never generates keys, opens store
clients or prints key material. Crypto regression verifies a real M6.7 access
token against the M7.2 public JWK, including identical kid values.

### M7.4 UserInfo protected-resource authentication

GET and POST /oidc/userinfo share identical authentication and response semantics.
M7.4 added UserInfoController and UserInfoAccessTokenService using the existing
ConfigModule/SigningKeyModule. M7.5 adds only PrismaModule and the internal
UserInfoClaimsService for optional read-only profile resolution below. There is
no Redis/OAuth/Tokens module import, current-user status check, session touch,
introspection, denylist, revocation or store write.
Tokens remain stateless until expiry. Startup, health and Discovery stay lazy;
only explicit credential validation requests the signing-key capability.

Authorization is the only token transport. Accept a case-insensitive Bearer
scheme followed by one or more SP and one token68 value, without trimming,
decoding or changing the compact token, following
[RFC 6750 section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1)
and [HTTP authentication scheme semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.1).
Reject malformed/structured/duplicate Authorization fields; never fall back to
cookies, Basic, query access_token or POST body access_token. Host/Origin/forwarded
headers, query and body fields cannot change authentication or response claims.

Read the exact validated ISSUER_URL from ConfigService. Reuse only M6.5
getPublicVerificationKey() and getKeyId(); do not fetch own JWKS, read/export PEM,
use a private signing getter, create another cache or implement crypto. jwtVerify
restricts algorithms to ['RS256'], verifies signature/exact issuer/expiry and
requires all eight M6.6 claim names. After verification require exact protected
kid equality and exactly the canonical payload iss/sub/aud/iat/exp/scope/roles/
permissions. Validate nonempty string issuer/audience, UUID sub, nonnegative safe
integer NumericDates with exp > iat, canonical RFC 6749 scope syntax via the
existing parser, and arrays of nonempty opaque role/permission strings ([] valid).
Do not transform claims or infer privileges. ID Tokens fail this access-token
shape check despite their valid shared issuer/key/signature/subject/expiry.

MVP audience compatibility decision: aud must be a present nonempty scalar
string, but UserInfo does NOT enforce a fixed endpoint-specific audience. M6.7
currently issues one business resource audience per client (student-api,
banking-api or identity-server); M7.4 neither changes that model nor adds another
audience/token or hard-coded mapping. The boundary is trusted RS256 issuer-signed
canonical access token + exact issuer/kid/expiry + exact openid scope. This is an
explicit MVP policy, NOT a claim of RFC 9068 JWT Access Token Profile compliance.
Business resource APIs must still check their own expected audience. A future
multi-audience/resource-indicator design may tighten UserInfo separately.

Require tokenized, case-sensitive openid, never a substring/alias/default. A valid
request returns HTTP 200 application/json with sub from verifiedToken.sub and
only the M7.5 scope-limited claims below. No schema/profile columns are added.

All UserInfo responses set Cache-Control: no-store and Pragma: no-cache, without
Set-Cookie or Location. Missing Authorization returns empty 401 with
WWW-Authenticate: Bearer realm="userinfo" (no error parameter). Malformed Bearer,
invalid JWT/signature/algorithm/issuer/expiry/kid/claims or ID Token confusion
returns fixed 401 {error: 'invalid_token', error_description: 'Invalid access token.'}
with Bearer realm="userinfo", error="invalid_token". A valid token without openid
returns fixed 403 {error: 'insufficient_scope', error_description:
'The access token does not grant UserInfo access.'} with Bearer realm="userinfo",
error="insufficient_scope", scope="openid", and no subject.

Key loading/configuration/unexpected internal failures are not invalid credentials:
return fixed 500 {error: 'server_error', error_description: 'UserInfo request failed.'}
without Bearer challenge or native causes/details. Only recognized credential JOSE
errors map to invalid_token; all other faults fail closed as server errors.
Never log headers, compact JWTs, token claims or key/config material.

Explicit userinfo:check uses the existing M6.7 issuer and configured signing pair
to create request-local test tokens, then checks GET/POST success, missing auth,
insufficient_scope and real M7.3 ID Token rejection. M7.5 adds one uniquely owned
temporary User fixture with finally cleanup and removal verification; no credentials,
sessions, registry or Redis mutations. It does not generate/rotate keys and is not
full OIDC E2E. Discovery:check checks
the advertised UserInfo URL for 401 + Bearer challenge; metadata remains unchanged.
POST /oauth/token preserves four access-token fields for OAuth-only grants;
M7.6 conditionally adds id_token for exact openid grants, never refresh_token.

### M7.5 scope-limited UserInfo claims

After complete M7.4 authentication, return internal subject plus a defensive copy
of the canonical parsed access-token scopes, preserving order/duplicates. Only
these verified grants authorize disclosure; query/body/cookies/other headers,
registry scope allowances and database values never supply grants.

UserInfoController delegates to internal UserInfoClaimsService.resolve({subject,
scopes}). Always return sub. Exact case-sensitive profile adds only
preferred_username = User.username; exact email adds only email = User.email.
Ignore application/unknown scopes, aliases and substrings. Construct a fresh
explicit allowlisted response: only sub, preferred_username and email can appear.
Never spread a User row, JWT, request or arbitrary input. Preserve persisted values
exactly, without trimming, casefolding, normalization or repair.

Without profile/email (including openid-only or openid + banking.transactions.read),
return {sub} without querying User, even for a subject with no current row. When
either scope is granted, perform at most one Prisma User.findUnique query with
where: {id: verifiedSubject}, select: {username: true, email: true}. No relations,
Credential/Session, metadata, status or lockedUntil are selected. Use the existing
PrismaModule/PrismaService; no schema/migration, Redis dependency, store writes,
current-account revocation or session policy is introduced. Tokens remain stateless
until expiry; this lookup obtains requested claim values only.

A missing requested-claim User row has a distinct internal invalid_token result,
mapped to exactly M7.4's fixed 401 body/challenge, never "User not found". Unexpected
database failure or malformed selected data is an operational failure, mapped to
the existing fixed 500 server_error / UserInfo request failed., with no challenge,
native cause, SQL, identifiers, PII or sensitive logs. Validate selected username as
a nonempty string and email with the same z.email() expectation used after trimming
at registration; here do not trim or repair either persisted value.

The supported subset is intentionally limited by the current User schema. Omit
all unavailable standard profile claims (including name, given_name, family_name,
nickname, profile, picture, website, gender, birthdate, zoneinfo, locale and
updated_at), not null placeholders. Omit email_verified entirely: verification
state is not modeled, so neither true nor false is justified. No email-verification
workflow or new column is added.

Discovery's exact metadata/scopes remain unchanged, without claims_supported.
The internal M7.3 ID Token remains exactly iss/sub/aud/iat/exp/nonce; profile/email
are supplied only through UserInfo. M7.5 did not change token issuance; M7.6 below
conditionally adds id_token to the four M6.7 access-token fields for exact openid
grants. No refresh_token is implemented.

---

## 5. Authorization Code Flow

M6.1 adds POST /oauth/token inside the existing non-global OAuthModule, accepting
only application/x-www-form-urlencoded body input. A strict schema requires nonempty
scalar strings grant_type, client_id, code, redirect_uri; code_verifier is optional
and must be a scalar string when supplied, including the empty string. Its
non-empty/syntax checks now belong to M6.3 after consumption, not M6.1.
Unknown/repeated/structured
fields are rejected. Opaque framework-decoded values are preserved exactly: no
trimming, normalization, second decoding, URI parsing or PKCE policy at this boundary.
Shape/parser/media-type errors return HTTP 400
{error: 'invalid_request', error_description: 'Invalid token request.'}; well-shaped
grants other than exact authorization_code return HTTP 400
{error: 'unsupported_grant_type', error_description: 'Unsupported grant type.'}.
Parser errors are sanitized only for this token route; existing auth contracts remain.
Successful validation now continues into M6.4 client resolution/authentication before M6.2 below, rather than directly returning
the original M6.1 staged 204. TokenRequestService itself has no I/O: no code hashing/storage access, registry lookup, client
authentication or PKCE verification. Unexpected failures return fixed HTTP 500
{error: 'server_error', error_description: 'Token request failed.'} without causes.
M6.2 implements atomic authorization-code consumption/binding; M6.3 owns PKCE verification;
M6.4 owns confidential-client authentication; M6.5+ own signing/claims/token issuance.
M6.4-M6.6 preserved temporary 204; M6.7 replaces it with signed access-token JSON.
GET /oauth/token remains absent.

M6.4 adds a read-only ClientAuthenticationService exported by ClientRegistryModule.
The mandatory token endpoint order is M6.1 shape/grant validation -> M6.4 client
resolution/authentication -> M6.7 issuance metadata validation -> M6.2 code
hashing/GETDEL/binding -> M6.3 PKCE -> access claims -> RS256 access signing ->
M7.6 conditional ID Token -> single HTTP 200.
Resolve the exact body client_id against Client.clientId: no trim, case conversion,
Unicode normalization, alias or fallback. Unknown/disabled clients fail authentication.
PUBLIC clients (Student SPA) require no secret and proceed only without an Authorization
header; supplied authentication, including client_secret_basic, is rejected. Their
path never uses/verifies a secret hash. CONFIDENTIAL clients (Banking/Admin BFFs)
require client_secret_basic. The Basic scheme is case-insensitive; require a strict,
canonical standard-Base64 credential value containing client identifier and secret.
Decode UTF-8 strictly, split at the first colon, then application/x-www-form-urlencoded
decode each component exactly once, as required by OAuth client_secret_basic. Both
components must be nonempty. Compare decoded Basic client_id with body client_id
exactly; do not transform the already framework-decoded body or trim/normalize/repair
either credential. Other schemes and malformed/missing credentials are rejected.
Verify the presented secret using installed Argon2 against the persisted Argon2id hash.
The stored hash stays private to this capability; M6.7 success returns only
id/clientId/clientType/accessTokenTtl/accessTokenAudience, selected in that same query.
ClientLookupService's safe metadata projection and ClientSecretService's issuance/
rotation lifecycle are unchanged; authentication never calls issueSecret().

Every expected authentication failure (unknown/disabled client, PUBLIC supplied auth,
missing/malformed/unsupported Basic, Basic/body mismatch, absent hash or wrong secret)
returns the same HTTP 401 {error: 'invalid_client',
error_description: 'Client authentication failed.'} and WWW-Authenticate:
Basic realm="oauth/token". Do not reveal which condition failed. No code hashing,
GETDEL or PKCE is attempted on authentication failure: the code/value/expiry remain
available for a later correctly authenticated attempt. Unexpected DB/Argon2/internal
failures, including a corrupt stored hash, use fixed token HTTP 500 server_error above,
without native causes or private details; they also precede consumption. Do not log
credentials, hashes, challenges or authorization codes. M6.4 added no token issuance
or secret delivery channel. Canonical demo seed hashes remain unchanged; local probes
use only isolated known-secret Argon2id fixtures and clean up their own state.

M6.2 extends the same OAuth-internal AuthorizationCodeService with
consume({code, clientId, redirectUri}): Promise<{ok: true, state: AuthorizationCodeState}
| {ok: false, error: 'invalid_grant'}>. After successful M6.1 validation/exact
grant dispatch and M6.4 authentication, hash the exact framework-decoded code using
createHash('sha256').update(code).digest('hex'), then buildRedisKey('oauth:code', hash).
Exactly one RedisService.getAndDelete (native GETDEL) is the consumption authority:
no GET/DEL pair, TTL read, script, retry write or restoration. Parse returned JSON
and validate through the unchanged authorizationCodeStateSchema. Validate Date.now()
as a non-negative safe integer, require state.expiresAt > now, then compare exact
state.clientId === request.client_id and state.redirectUri === request.redirect_uri.
The stored clientId is the external OAuth identifier, not Client.id; no DB/registry
lookup, URI normalization, extra decoding or comparison against registered URI rows.

Null GETDEL (unknown/replayed/naturally expired), logical expiry or either binding
mismatch returns fixed HTTP 400 {error: 'invalid_grant',
error_description: 'Invalid authorization grant.'}. Hash/Redis/JSON/schema/clock or
unexpected failures return the existing fixed token HTTP 500 server_error above.
After GETDEL returns a value, every failure burns the code permanently, including
wrong bindings and corrupted state; a lost Redis reply is never retried/restored.
Success returns only validated consumed state internally. M6.2 initially returned
temporary empty HTTP 204; M6.7 now continues through M6.3 and signed-token issuance.
Concurrent requests have exactly one winner. The consume capability itself remains
verifier-agnostic and performs no client authentication/secret access or signing.

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

M5.1-M5.6 expose GET /oauth/authorize through a non-global OAuthModule importing
ClientRegistryModule, SessionAuthenticationModule and RedisModule. M5.1-M5.3 validate
the OAuth request before M5.4 authenticates the existing central IdP session, then
M5.5 issues/stores a code. M5.6 changes only the final success response to HTTP 302
Found with Location and an empty body. All responses set Cache-Control: no-store;
none emit Set-Cookie. Errors remain direct fixed 400/401/500 without Location.
No consent, token issuance, request-continuation state or PostgreSQL writes are
added; authenticated subject remains internal, while the raw code is returned only
in the validated success callback.

M5.4 order: parse -> response_type -> enabled client -> exact redirect -> PKCE
-> allowed-scope lookup -> granted-scope policy -> central-session authentication.
Any earlier request/policy failure returns its existing 400 OAuth error without
parsing/touching a session. OAuth validation or session infrastructure failure
returns the existing safe 500 server_error with description Authorization request failed.

SessionAuthenticationModule exports one internal IdpSessionAuthenticationService,
also reused by M3.6 own-session management. Configured cookie parsing is the only
browser identifier authority, followed by the existing Redis touch and matching
ACTIVE PostgreSQL Session with expiresAt > now. UUID/userId, createdAt and absolute
expiry must match runtime/persistent state exactly. Cookie recognition or either
store alone is not authentication; query/body/custom headers/Bearer/state are never
session or subject authorities. No global middleware, guard or session-check route.

Missing/malformed/duplicate cookie, absent/expired runtime or missing/revoked/
expired/incoherent persistent state return the same HTTP 401
`{statusCode: 401, error: "Unauthorized", message: "Authentication required."}`.
Redis/Prisma failures instead throw sanitized internal errors, not unauthenticated
results. Touch may advance only existing Redis idle activity/TTL, capped by the
same absolute expiry; authTime, createdAt, mfaLevel and PostgreSQL lastActivityAt
are unchanged. Missing state is never recreated and there is no store fallback.

There is no IdP HTML login UI yet. The M5.4 login/resume contract is: valid
authorize without a session -> 401 -> existing POST /auth/login -> iam.sid ->
resubmit the SAME original authorize request with that cookie -> authenticated
continuation (the M5.6 success callback now replaces the staged 204). No redirect
to a new login route, return_to cookie, stored
request, Redis continuation key or new database object is introduced. Internal
continuation exposes only trusted sessionId/userId/authTime/mfaLevel alongside
validated OAuth data; M5.5 adds a transient authorizationCode only after persistence.
The subject is never returned; M5.6 uses only the code and validated redirect/state.

One Zod boundary accepts framework-decoded scalar strings only. Base fields
response_type, client_id, redirect_uri, scope and state are required/non-empty;
nonce is non-empty when present. PKCE pair/method/format checks follow resolved
client policy in section 6. Unknown parameters are ignored, not aliased.
Repeated recognized parameters (arrays) and object values
are rejected. No trimming, case conversion, Unicode normalization or additional
URL decoding/re-encoding occurs. Only response_type=code is supported.

Scope uses RFC 6749 section 3.3 syntax: non-empty ASCII scope tokens separated
by one SP, with no leading/trailing/repeated spaces, tabs, quotes, backslashes
or control characters. Preserve token order, duplicates and exact case/content;
parsing does not apply client-specific membership. M5.3 validates that membership
after client/redirect/PKCE checks as defined in section 18. Exact
openid requires a non-empty opaque nonce. State is always opaque/non-empty;
neither is generated or logged. M5.6 returns state unchanged only in the success
callback; nonce is never echoed. OAuth state is never persisted; M5.5
stores the supplied nonce only in the canonical authorization-code context below.

Resolve only through ClientLookupService.requireEnabledClient. Compare the
supplied redirect_uri to its exact registered strings using membership, without
patterns, URL parsing/canonicalization or redirect fallback. Unknown/disabled
clients and all invalid/unregistered redirects receive the same direct HTTP 400
JSON `{error: "invalid_request", error_description: "Invalid authorization request."}`.
Other shape/nonce/PKCE failures use that same response. A well-shaped
unsupported response_type receives HTTP 400 unsupported_response_type with the
same description. Lookup operational/unexpected failures receive fixed HTTP 500
`{error: "server_error", error_description: "Authorization request failed."}`.
Errors never return/log query values, internal UUID, private cause or driver detail.

M5.2 finalizes the authorization-request PKCE policy in section 6 below, replacing
M5.1's minimum presence/method checks without changing the interim HTTP behavior.
M5.3 enforces allowed/granted scopes and invalid_scope as defined in section 18.

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

M5.5 implements only OAuth-internal AuthorizationCodeService.issue(input), returning
`{code}` after persistence. Generate `randomBytes(32).toString('base64url')` (256-bit
input, URL-safe, unpadded); hash the exact raw code with SHA-256 to lowercase hex.
Use `buildRedisKey('oauth:code', codeHash)`: concrete `oauth:code:<64-hex-hash>` with
no literal braces. Raw codes exist only transiently in memory, never in Redis,
PostgreSQL, logs, errors or HTTP bodies. The service is not exported by OAuthModule.

Strict JSON contains exactly the eight fields above. clientId is the validated
protocol Client.clientId, not internal Client.id; userId/authTime come from the
authenticated IdP session. Preserve exact validated redirectUri, M5.3 grantedScopes
and their order, PKCE challenge and nonce. Absent permitted confidential PKCE or
non-openid nonce is explicit null. No state, sessionId/cookie, profile or token fields.
Validate non-empty opaque strings, UUID userId, exact scope-token syntax, nullable
43-character S256 challenge and non-negative safe-integer epoch-ms timestamps.

Capture one issue clock; expiresAt = issue instant + 120000 ms, safely after issue.
The fixed M5.5 AUTHORIZATION_CODE_TTL_SECONDS policy is 120, not a new env setting;
the existing configuration surface remains unchanged. RedisService reserves using
one SET with EX 120 and NX, never a permanent key or overwrite. Retry collisions
with fresh randomness for at most three attempts; never delete/scan a collided
entry. Crypto/serialization/Redis/exhaustion failures fail closed with sanitized
internal errors and the same HTTP 500 server_error boundary. No generation/write
happens before all M5.1-M5.4 checks succeed. Valid session idle touch may already
have occurred when code persistence fails; there is no cross-store transaction.
A lost Redis reply may leave only a hash-keyed TTL-bounded entry, never a success
response or raw code disclosure.

M5.6 uses only successful AuthorizationResult.request.redirect_uri/state and its
already-issued authorizationCode. A small pure textual builder preserves the exact
validated URI spelling/case/percent encoding/query ordering, without URL parsing or
reserialization. Append encodeURIComponent(code) and encodeURIComponent(state) as
code/state query parameters, using ? without an existing query and & with one
(no extra separator after a trailing ? or &). Insert before the first literal #,
preserving the fragment unchanged. No new registration/matching policy is added.

OAuthController sets Location through the existing HTTP adapter/passthrough pattern
and returns void with HTTP 302, avoiding redirect-helper HTML/code duplication.
Never reconstruct from raw query/body/headers, look up the client again, reissue a
code, or read/write/touch/delete code state to construct a response. No Location,
code/state echo or Set-Cookie on errors; invalid redirect URIs never redirect.
Response-construction failures use the same sanitized server_error boundary. A
lost/failed HTTP delivery may leave the existing TTL-bounded entry; no rollback or
network transaction is attempted. A request retry goes through normal validation
and new issuance, not code reuse. Location/raw code/state are never logged.

M6.2 now atomically consumes authorization-code state as described above; M5.5/M5.6
issuance/callback behavior is unchanged. M6.3 verifier handling follows consumption.

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

M5.2 uses a pure authorization-request policy after enabled client resolution and
exact redirect validation. The Zod query boundary checks scalar string shape for
code_challenge/code_challenge_method only, without coercion; all PKCE pair,
method and challenge-format decisions belong to the policy, not duplicate schema
refinements.

PUBLIC clients (including student-spa) require BOTH code_challenge and
code_challenge_method. CONFIDENTIAL clients (banking-web/admin-portal) may omit
BOTH; if either field is supplied, BOTH are required. A supplied method must be
exactly S256, case-sensitive, without a plain fallback.

For either client type, a supplied challenge must be exactly 43 ASCII characters
from A-Z, a-z, 0-9, hyphen and underscore. Reject padding (=), +, /, dot, tilde,
whitespace, controls, Unicode, other lengths and percent signs in the
framework-decoded value. Preserve the exact input string; never trim,
normalize, decode again, pad or
repair it. All PKCE failures return the existing direct HTTP 400 invalid_request
JSON with fixed description, no Location/Set-Cookie or query/challenge logging.

This authorization boundary validates received challenge syntax only: no hashing,
code_verifier handling, verifier comparison, persistence, session integration,
authorization code or token is introduced. Actual S256 calculation/verification
belongs to M6.3 at the token endpoint, not M5.2.

M6.3 runs a focused token PKCE policy only after successful M6.2 GETDEL, canonical
state/expiry and exact client/redirect binding. A non-null stored codeChallenge
requires code_verifier with length 43..128 and ASCII unreserved characters only
(A-Z, a-z, 0-9, -, ., _, ~). Preserve the framework-decoded verifier exactly: no
trim, Unicode normalization, case conversion, extra decoding or repair. Compute
Node.js SHA-256 over ASCII verifier bytes and digest as unpadded base64url; compare
against the exact stored challenge using the standard timing-safe comparison.
Only S256 is implemented; no method override or plain fallback is accepted.

Missing, empty, malformed or mismatched verifier returns the same fixed HTTP 400
{error: 'invalid_grant', error_description: 'Invalid authorization grant.'}.
The code was already consumed and is never restored, so retry also fails. When
stored codeChallenge is null, PKCE is not required and any optional scalar verifier
is ignored; this does not classify/authenticate the client. Structural non-string,
array/object/repeated verifier values remain M6.1 invalid_request before GETDEL.
Unexpected crypto/internal failures use the existing fixed HTTP 500 server_error
with description Token request failed., without causes or sensitive logs. M6.7
continues successful PKCE into issuance, replacing the historical empty 204.
M6.4 authenticates the client before consumption. No storage-format or M5.2 policy change.

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

M4.4 adds only the internal `ClientSecretService.issueSecret(clientRecordId)`
capability, exported by ClientRegistryModule (PrismaModule only, no controller
or AuthModule dependency). The caller must authorize the action beforehand;
clientRecordId is internal Client.id, validated as the existing UUID format.
Unknown/PUBLIC clients are rejected before randomness or hashing. CONFIDENTIAL
clients may begin with a NULL hash; the same method issues first or rotates an
existing secret without introducing an enabled/disabled authentication policy.

Generate `randomBytes(32).toString('base64url')`: 32 bytes / 256 bits of random
input entropy, no prefix or normalization. Hash directly with the installed
Argon2 library using Argon2id and its default costs/fresh salt. Only the encoded
hash is written to the existing nullable Client.clientSecretHash field; no
schema change, separate salt or other secret field exists.

Use one compare-and-swap update matching internal id, CONFIDENTIAL type and the
previously read hash (including NULL), requiring count = 1. A stale concurrent
candidate fails without automatic retry. Return only `{clientSecret}` after
persistence succeeds; plaintext is transient, never persisted, cached or logged,
and cannot be recovered later. A subsequent successful issuance replaces the
hash, not a retained old-secret history. Invalid input, unknown/PUBLIC client,
crypto/read/write failure and CAS loss expose only `Client secret issuance failed.`
without sensitive values or attached causes.

No HTTP management API, secret retrieval API or client-secret verification is
added. M4.5 will use this lifecycle for demo confidential clients; M6.4 owns
`client_secret_basic` authentication. Runtime lookup remains M4.6.

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

M6.5 adds the internal non-global SigningKeyModule/SigningKeyService under
`src/security/signing`, using the runtime `jose` library. AppModule imports this
module, which exports only the service and has no controllers or startup hooks.
M6.7 now requests signing keys only after successful consumption/PKCE. M6.5 added no claims
builder, JWKS/Discovery endpoint, key generation, provisioning or rotation.

Read the existing validated JWT_PRIVATE_KEY_PATH, JWT_PUBLIC_KEY_PATH and JWT_KEY_ID
only on first explicit service access. The existing config trims these three
strings and requires nonempty values; preserve the resulting kid exactly, including
case/Unicode, without another normalization policy. Relative paths resolve from the
Identity Server process working directory. Missing/unreadable files do not affect
construction, basic startup or process /health; development placeholder paths remain
valid configuration until this capability is explicitly requested.

Canonical inputs are an unencrypted RSA PKCS#8 PEM private key
(`-----BEGIN PRIVATE KEY-----`) and a matching RSA SPKI PEM public key
(`-----BEGIN PUBLIC KEY-----`), minimum 2048-bit modulus. Import both with JOSE for
RS256 only. Reject EC/symmetric keys, certificates, PKCS#1/encrypted formats,
malformed inputs, weak RSA keys or anything not importable for RS256. The cached
private CryptoKey is non-extractable and used only by trusted in-process consumers;
no API returns raw private PEM or a private JWK.

Derive the public KeyObject from the imported private CryptoKey using Node's
established KeyObject.from/createPublicKey APIs. Check its RSA type/modulus strength,
export only its public JWK metadata, and compare n/e exactly with JOSE's public-key
JWK export. Both parameters must match before any getter succeeds. No hand-written
ASN.1/RSA/JWS, private JWK export, or production-style JWT signature is used to
establish pair equality.

The asynchronous internal getters are getPrivateSigningKey(),
getPublicVerificationKey(), getPublicJwk() and getKeyId(); all await the same complete
validated key set. getPublicJwk() returns a defensive copy of exactly
`{kty: 'RSA', kid: <configured kid>, alg: 'RS256', use: 'sig', n, e}`.
No d/p/q/dp/dq/qi/oth or other private parameters/extra export fields cross this
boundary. M7.2 exposes only this public projection through JWKS as specified above.

Concurrent first access shares one in-flight initialization. Read/import once and
cache a successful complete set for this service lifetime; do not re-read files
on future getter calls. A failed attempt publishes no partial keys, clears the
in-flight promise and permits a later explicit retry. There is no automatic retry,
fallback/replacement-key generation, file watcher or hot reload after success.
Every initialization failure, including missing/invalid kid and native fs/JOSE/
OpenSSL errors, rejects only `Signing key initialization failed.` without an
attached cause. Do not log key contents, PEMs, private parameters, configured paths
or native details. Tests generate ephemeral keys in owned temporary directories;
never commit operational private keys or generate them on normal startup.

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

M6.6 adds internal non-global TokensModule/AccessTokenClaimsService under
`src/tokens`. Its synchronous build({subject, audience, scopes, roles, permissions,
ttlSeconds?}) returns exactly iss/sub/aud/iat/exp/scope/roles/permissions, constructed
explicitly. Unknown input properties are ignored and cannot become claims or override
issuer. No kid/alg/typ/jti, nonce/auth_time/session/profile data, credentials, code,
PKCE, refresh token, request or persistence metadata is included.

Issuer is the existing validated ConfigService ISSUER_URL value, preserved exactly;
the caller cannot supply it. Subject is an explicit trusted internal User.id,
validated using the existing z.uuid() convention without lookup/normalization.
Audience is required explicit trusted input, a nonempty scalar opaque string:
preserve case/Unicode/whitespace exactly, including whitespace-only nonempty strings.
No URI parsing, aliases or inference from client_id, redirect, scope/prefix, Host,
origin or issuer. M6.6 itself introduced no Client audience column or mapping;
M6.7 supplies the explicit registered audience described above.

Capture Date.now() once; require nonnegative safe-integer milliseconds, compute
iat = floor(nowMs / 1000), exp = iat + ttlSeconds. Both claims are integer seconds;
reject unsafe expiry arithmetic. TTL defaults to configured ACCESS_TOKEN_TTL_SECONDS
(the existing 600-second default), never another token/session TTL. An explicit
trusted ttlSeconds override must be a positive safe-integer number and is used
exactly; no coercion, skew policy or second clock read.

Scopes are already granted input, validated by the existing code-state grantedScopes
schema (at least one RFC 6749 scope token) and joined with one SP. Preserve order,
case and any supplied duplicates; do not recalculate intersection, sort/deduplicate,
add/drop grants or map scopes to permissions. M5.3's grant calculation remains the
earlier deduplication authority; M6.6 does not reinterpret already-granted state.

Roles and permissions are separate explicit trusted arrays of nonempty opaque
strings, with [] valid. Preserve exact values/order/duplicates and return defensive
copies; do not trim, normalize, sort, infer roles/permissions or hard-code demo
privileges. M6.6 defines only the payload capability. M9.1-M9.3 own RBAC persistence/
resolution; M9.4 later supplies real resolved roles/permissions to token issuance.

The builder has only ConfigService and schema validation dependencies: no Prisma,
Redis, HTTP/network, filesystem, SigningKeyService or JOSE signing. Malformed input,
config/clock/internal failures throw only `Access token claims build failed.` with
no native cause or logs of subject/audience/grants/RBAC/config values. TokensModule
has no controller; AppModule imports it without invoking build or loading keys.
M6.7 alone combines these claims with M6.5 keys/JOSE protected headers/signing and
the token response; M6.5 stays lazy/unchanged. M7.1 Discovery remains Config-only;
M7.2 publishes the current public signing JWK without changing access-token claims.

### M6.7 issuance boundary

Before hashing/GETDEL, validate authenticated registry audience as a nonempty
scalar string (opaque, no trimming/normalization/inference/fallback) and access
TTL as positive safe-integer seconds. Missing/corrupt metadata returns fixed
HTTP 500 server_error / Token request failed., never invalid_client, without
consuming the code. No second registry lookup or request-supplied audience exists.

After GETDEL, binding/expiry and PKCE, AccessTokenIssuerService in TokensModule
builds claims using consumed userId/grantedScopes, authenticated client audience/TTL,
and explicit roles=[]/permissions=[] until M9.4. TokensModule now imports
SigningKeyModule. Sign the exact claims with jose.SignJWT and the M6.5 private key,
protected header exactly {alg: 'RS256', kid: configured key ID}. No typ, additional
claims, claim-replacing helpers or second issuance clock. Return internally only
accessToken, expiresIn=claims.exp-claims.iat and scope=claims.scope.

POST /oauth/token returns HTTP 200 application/json with exactly access_token,
token_type='Bearer', expires_in and scope; Cache-Control: no-store and
Pragma: no-cache, without Location/Set-Cookie. This remains exact for OAuth-only
grants; M7.6 adds only id_token for exact consumed openid grants. No refresh token.
Claims/key/signing/internal failures after consumption return the same sanitized
500; code stays permanently burned, with no restoration/retry write. A retry of
that code returns invalid_grant before reaching claims/keys/signing. Existing
401 invalid_client + Basic challenge and 400 invalid_grant contracts stay unchanged.

Explicit development/test-only `dev-keys:generate` provisions RSA-2048 PKCS#8 private
and SPKI public PEM under ignored apps/identity-server/dev-keys, refusing overwrite.
Private permissions are restricted where supported; Windows operators must protect
the local directory ACL. Compose mounts it read-only, never copies PEM into images.
This command never runs on startup/install/build/seed and is not production rotation.
Without provisioned keys basic startup/health still works; issuance fails closed.

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

### M7.3 internal claim builder and signed ID Token

OidcModule registers IdTokenClaimsService and IdTokenIssuerService, originally
internal in M7.3. M7.6 exports only IdTokenIssuerService for OAuthModule; there is
no new ID Token controller/route or eager call. Discovery/JWKS metadata, startup and
health behavior remain unchanged; construction never loads signing files.

IdTokenClaimsService.build({subject, audience, nonce, ttlSeconds}) explicitly
returns exactly {iss, sub, aud, iat, exp, nonce}. Its only runtime configuration
dependency is ConfigService for ISSUER_URL. Preserve the exact configured issuer
and apply the equivalent M7.1 OIDC URL policy: valid HTTP/HTTPS hostname, no URL
credentials, query or fragment (including empty ?/#). Reject rather than repair;
do not change global env validation or M6 access-token issuer semantics.

Subject is a trusted User.id using the existing UUID convention, preserved exactly
without querying users. Audience is an explicit trusted OAuth client_id
(student-spa/banking-web/admin-portal), NOT the access-token resource audience
(student-api/banking-api/identity-server). Require a nonempty scalar string;
do not infer, look up, trim, normalize or map it. Nonce is a required nonempty
scalar opaque string, preserved exactly without generation, decoding or hashing.
Null/missing/empty nonce fails closed. The builder never reads authorization-code
state, registry, sessions, stores, key files or network.

ttlSeconds is required explicit trusted positive safe-integer input: no env
variable/default or implicit reuse of accessTokenTtl. Capture Date.now() once,
require nonnegative safe-integer milliseconds, then iat=floor(nowMs/1000) and
exp=iat+ttlSeconds as integer NumericDates. Reject unsafe expiry arithmetic.
Unknown input fields cannot become claims; no scope/roles/permissions, profile,
auth_time, acr/amr/azp, at_hash/c_hash/s_hash, jti/nbf or session/grant/secret data.
Malformed/config/clock failures throw only `ID token claims build failed.` without
attached causes or sensitive logs.

IdTokenIssuerService.issue uses that builder, then the existing M6.5
getPrivateSigningKey() and getKeyId(), signing through jose.SignJWT with protected
header exactly {alg: 'RS256', kid}. Return only {idToken}; no typ, extra headers,
claim-setting helpers, second issuance clock, alternative key path/cache or manual
crypto. The same validated SigningKeyService pair supplies M7.2 JWKS, including
an identical kid. Failures throw only `ID token issuance failed.` without native
causes, input/key/JWT details or sensitive logs.

M7.3 originally added only this capability. M7.6 connects it to the OIDC token
response below without modifying either frozen ID Token builder/issuer. Their
tests continue to verify real RS256 ID Tokens against M7.2 public JWKs and exact
client_id/nonce/kid consistency.

### M7.6 Authorization Code OIDC integration and client E2E

The non-global OidcModule exports ONLY IdTokenIssuerService. OAuthModule imports
OidcModule and OAuthController injects that issuer, with no reverse module import,
forwardRef, new signing path, key cache or constructor-time work. All other OIDC
services remain unexported. Startup, process health and Discovery remain unchanged;
no new eager key loading or database query is introduced.

Preserve the token pipeline: request shape/grant -> client authentication ->
validate registered access-token audience/TTL -> atomic GETDEL, binding/expiry ->
PKCE -> access-token claims/signing -> conditional ID Token -> one HTTP response.
Only consumed grant.state.grantedScopes.includes('openid') selects OIDC, with exact
case-sensitive token matching, AFTER consumption/PKCE and access-token issuance.
Request body/query/headers, allowed scopes, client/redirect or nonce presence alone
cannot select OIDC. A non-openid grant with nonce still receives OAuth-only output.

For OIDC call the existing issuer with subject = state.userId, audience =
state.clientId, nonce = state.nonce unchanged and ttlSeconds = issuance.ttlSeconds
from the already validated authenticated client's accessTokenTtl. Require non-null
stored nonce; null in an openid grant is a server/state invariant failure, not
invalid_client/invalid_grant. No User/session lookup, nonce generation, decoding,
normalization, separate TTL env or schema column is added. Each builder retains
its own single clock: exp-iat equals the same TTL independently, without requiring
identical iat values. expires_in describes only the access-token lifetime.

OAuth-only HTTP 200 has exactly access_token, token_type='Bearer', expires_in and
scope. OIDC HTTP 200 has exactly those four plus id_token. Both set no-store and
Pragma no-cache, without Set-Cookie or Location. Never return refresh_token or
profile/session/nonce metadata separately. ID Token remains exactly the six M7.3
claims: iss/sub/aud/iat/exp/nonce, even for openid profile email. No at_hash,
auth_time, RBAC or profile claims are added; profile/email remain UserInfo-only.
Canonical Student audiences deliberately differ: access-token aud=student-api,
ID Token aud=student-spa (OAuth client_id).

Pre-GETDEL validation/client/issuance-metadata errors do not burn code. After
successful GETDEL, all failures leave it consumed, including null OIDC nonce,
access-token failure or ID-token claims/signing failure. Return only existing fixed
HTTP 500 {error:'server_error', error_description:'Token request failed.'}; never a
partial access token, new error class, native cause or sensitive log. A generated
access token may remain transient in memory but is not delivered on ID-token
failure. Never restore/reinsert code; retry receives fixed 400 invalid_grant.
Existing 401 invalid_client and 400 grant/PKCE contracts remain unchanged.

Explicit oidc-e2e:check is separate from frozen OAuth-only M6.8 profile E2E. Use
canonical PUBLIC student-spa, exact callback, S256 and openid profile email with
random state/nonce/verifier. Real HTTP registration -> authorize 401 -> login/IdP
cookie -> identical authorize 302/exact state -> token exchange (no Basic/secret)
-> exact five-field response -> replay invalid_grant. Validate BOTH signatures
through LIVE Discovery-advertised public JWKS, never direct PEM reads. JOSE
enforces RS256, expected issuer and each token's distinct audience; validate exact
header/claim allowlists, subject and per-token TTL. Explicitly compare ID-token
nonce to the original opaque request nonce, and prove the SAME token is rejected
for a wrong expected nonce and the resource-API audience.

Call live advertised UserInfo with the ACCESS token, requiring exactly
sub/preferred_username/email for the registered identity. Before accepting profile
claims, explicitly require UserInfo.sub === validated ID Token.sub. Preserve the
existing standalone UserInfo check and ID-token-as-Bearer rejection tests.
Use M6.8's unique ownership proof, finally logout/runtime/code/FK-ordered row
cleanup, eight database fingerprints and unrelated Redis value/absolute-expiry
snapshots. Compare published JWKS before/after; no key writes, canonical registry
changes, seed, flush or sensitive output. This completes M7 only; M8 remains absent.

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

M3.7 adds only the injectable internal AdminSessionRevocationService, exported
through AuthModule for trusted internal consumers. Its API is
`revokeUserSessions(targetUserId: string): Promise<void>`. The caller must FIRST
authorize this action through a future trusted management/RBAC layer; the target
UUID is not proof of privilege. This service performs no administrator
authentication/authorization, accepts no actor/role/privilege flag or secret,
and has no HTTP route or cookie semantics. No temporary privilege mechanism,
Role/Permission model, OAuth token behavior or persistent audit infrastructure
is introduced; M3.6 ownership enforcement remains unchanged.

Validate the target with the existing canonical UUID domain before touching
stores, without trimming/normalization. Discover only PostgreSQL Session IDs with
`where: {userId: targetUserId, status: 'ACTIVE'}`, `select: {id: true}` and
`orderBy: {id: 'asc'}`. PostgreSQL is the persistent session registry; Redis is
never scanned or pre-read for discovery. Unknown users and zero ACTIVE sessions
are the same idempotent success, without a separate User lookup. REVOKED history
is not enumerated or deleted. ACTIVE records with missing/expired runtime are
still passed directly to the existing logout primitive.

Sequentially await IdpLogoutService.logout for each discovered ID, preserving
Redis-first invalidation, conditional persistent REVOKED, DEL=0/update count=0
idempotency and unchanged timestamps/metadata. Revocation covers only this
discovery snapshot; it does not disable/lock an account, change its Credential or
prevent new login sessions after discovery. There is no cross-store/multi-session
transaction or distributed compensation. On the first failure, stop subsequent
work and reject only `Admin session revocation failed.` without identifiers,
URLs, driver causes or sensitive logs. Earlier completed revokes remain complete;
partially deleted runtime is never restored. Retry performs a fresh ACTIVE
discovery: fully REVOKED rows disappear, Redis-deleted/DB-ACTIVE rows and untouched
rows are retried safely through M3.5 idempotency. Concurrent user logout or
privileged invocations do not recreate runtime state or persistent rows.

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

M4.3 persistence baseline: `Scope` maps to `scopes`, containing only a
Prisma-generated UUID `id` and globally unique exact text `name`, without
trimming, casefolding, Unicode normalization or new scope-name CHECK policies.
Explicit `ClientScope` maps to `client_scopes`: required UUID `client_id` and
`scope_id` reference internal `Client.id` and `Scope.id`, not protocol strings.
The pair `(client_id, scope_id)` is the composite primary key; no surrogate ID
or extra metadata is added. Both FKs use Prisma's default ON DELETE RESTRICT /
ON UPDATE CASCADE behavior.

`Client.allowedScopes` and `Scope.clientScopes` expose the explicit assignments:
one Client may allow zero/one/many scopes, and one Scope may belong to
zero/one/many Clients. M4.3 seeds no canonical scopes or demo assignments and
adds no runtime scope parser, policy or endpoint. M4.5 owns seed data, M4.6 owns
lookup, and M5.3 owns requested/allowed intersection and `invalid_scope` behavior.

Client registration defines `allowed_scopes`.

Authorization request defines `requested_scopes`.

Granted scope:

```text
granted_scopes =
requested_scopes ∩ client_allowed_scopes
```

If request includes an unknown or forbidden scope, return `invalid_scope`.

M5.3 runtime order is parse -> response_type -> enabled client -> exact redirect
-> PKCE -> ScopeLookupService.getAllowedScopeNames(client.id) -> granted-scope
policy. The lookup receives internal Client.id, never OAuth client_id; its exact
names come only from existing ClientScope -> Scope assignments. No lookup occurs
when an earlier validation fails. No duplicate repository, cache, defaults,
scope aliases, normalization or permission mapping is introduced.

Every requested token must be in the allowed set. Reject the entire request on
any miss; never silently drop forbidden scopes. The pure policy returns the exact
intersection with first-request occurrence order and duplicate grant names removed,
without mutating either input. request.scope retains all parsed requested tokens;
the successful internal result exposes a separate grantedScopes array. It is
transient in M5.3, never returned through HTTP. M5.5 persists that exact result in
authorization-code state after session authentication; no session or token state
is added by the scope policy. HTTP success uses the M5.6 callback only after session
authentication and successful M5.5 code persistence.

Policy rejection returns direct HTTP 400
`{error: "invalid_scope", error_description: "Invalid authorization request."}`.
Lookup operational failure is not invalid_scope: return the existing safe HTTP
500 server_error with description `Authorization request failed.`. No offending scope,
allowed list, UUID, query or private driver cause is echoed/logged. All responses
retain no-store and no Location/Set-Cookie on these errors. Exact requested openid still requires
nonce at the unchanged parser boundary; OpenID is a distinct scope, not an alias.

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
`COOKIE_SECURE=false` and a non-HTTPS issuer. JWT key-file format/existence/pair/strength
are validated lazily at the M6.5 signing-key boundary, not by startup env validation.
TOTP key encoding/strength remains deferred to its encryption task.

Never commit production secrets.

---

## 26. Test Boundaries

M6.8 adds explicit `authorization-code-e2e:check` against the running real local
Identity Server, PostgreSQL and Redis. It uses canonical PUBLIC student-spa,
exact http://localhost:3200/callback and only the registered opaque OAuth scope
profile, not an OpenID Connect compliance flow. No controllers/stores/hashing/
session/code/PKCE/signing are mocked. No canonical client or secret is modified.

Register a uniquely owned identity through HTTP; valid authorize without a cookie
returns the existing 401/no callback or code. HTTP login establishes the central
session; repeat the identical authorize request with that cookie, without following
the callback. Verify exact callback/state, real hash-keyed code/session binding,
S256 exchange, and signed access-token response using the configured public key
and JOSE RS256 verification. Replay the same exchange must return invalid_grant
without recreating code state. No ID/refresh token; M7.1 adds Discovery metadata
and M7.2 makes JWKS live; M7.4 UserInfo requires Bearer credentials. Only obsolete metadata
route-status assertions are updated in this M6.8 regression; its
OAuth/session/code/token flow is unchanged.

The check requires existing provisioned keys and never generates/rotates them.
Missing/invalid public verification key yields a fixed prerequisite message without
paths/PEMs. Password/cookie/code/verifier/JWT remain transient and never printed,
including assertion failures. Finally log out only the proven owned session and
remove only owned runtime keys and Session/Credential/User rows in FK order,
recovering owned state after lost replies where possible. Compare eight full-row
database fingerprints and bounded unrelated Redis value/absolute-expiry snapshots
after cleanup. Run on a quiet local development stack; fail safely if unrelated
keys are about to expire, rather than modifying/restoring unrelated data.

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
