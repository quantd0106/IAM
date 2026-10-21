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
M6.4-M6.6 preserve the temporary 204; M6.7 token issuance will replace it. GET /oauth/token remains absent.

M6.4 adds a read-only ClientAuthenticationService exported by ClientRegistryModule.
The mandatory token endpoint order is M6.1 shape/grant validation -> M6.4 client
resolution/authentication -> M6.2 code hashing/GETDEL/binding -> M6.3 PKCE -> empty 204.
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
The stored hash stays private to this capability; return only id/clientId/clientType.
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
credentials, hashes, challenges or authorization codes. No token issuance or secret
delivery channel is added. Canonical demo seed hashes remain unchanged; local probes
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
Success returns only validated consumed state internally and temporarily HTTP 204
with empty body, Cache-Control: no-store, no Location and no Set-Cookie. Concurrent
requests have exactly one winner. Successful consumption now continues into M6.3
below before returning the staged 204. The consume capability itself remains
verifier-agnostic and performs no client authentication/secret access itself. No token issuance.

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
with description Token request failed., without causes or sensitive logs. Success
still returns empty 204/no-store/no Location/no Set-Cookie. M6.4 authenticates the client
before consumption; later token issuance remains unimplemented. No storage-format or M5.2 policy change.

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
OAuthModule/token processing does not request signing keys yet: M6.1 -> M6.4 ->
M6.2 -> M6.3 still ends in empty HTTP 204, not a signed token. M6.5 adds no claims
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
boundary. The public material is ready for later M7.2 but not exposed over HTTP.

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
origin or issuer; no Client audience column or client/resource mapping is introduced.

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
the token response. Current /oauth/token still ends in empty HTTP 204, no-store,
no Location/Set-Cookie; M6.5 stays lazy/unchanged and JWKS/Discovery remain absent.

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
