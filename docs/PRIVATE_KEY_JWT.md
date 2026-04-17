# Private Key JWT Client Authentication (RFC 7523)

AuthGate supports **`private_key_jwt`** at the token endpoint — clients authenticate by signing a short-lived JWT assertion with their private key instead of presenting a long-lived `client_secret`. This is the authentication method [recommended by the MCP OAuth Client Credentials extension](https://modelcontextprotocol.io/extensions/auth/oauth-client-credentials) for machine-to-machine flows.

- **RFC 7521** — Assertion Framework for OAuth 2.0 Client Authentication
- **RFC 7523** — JWT Profile for OAuth 2.0 Client Authentication
- **RFC 7591 §2.1** — Dynamic client registration of `jwks`/`jwks_uri`

## Why use it

| Aspect                    | `client_secret_basic`/`_post`                                         | `private_key_jwt`                                        |
| ------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------- |
| Credential lifetime       | Long-lived, stored on server                                          | Short-lived (minutes), regenerated per call              |
| Transmitted over the wire | Raw secret (even under TLS, exposed to intermediaries)                | JWT signed with private key; private key stays on client |
| Server storage            | bcrypt hash of secret (attacker who exfiltrates DB can offline-crack) | Public key only (no useful secret to steal)              |
| Rotation                  | Requires re-issuing secret                                            | Rotate JWKS; no downtime                                 |
| Replay protection         | None at protocol level                                                | Built-in via `jti` + short `exp`                         |

See [RFC 7523 §1](https://datatracker.ietf.org/doc/html/rfc7523#section-1) for more background.

## Enabling the feature

`private_key_jwt` is enabled by default. Set the following environment variables to configure it:

```bash
PRIVATE_KEY_JWT_ENABLED=true            # Feature flag (default: true)
JWKS_FETCH_TIMEOUT=10s                  # HTTP timeout when fetching jwks_uri (default: 10s)
JWKS_CACHE_TTL=1h                       # JWKS cache lifetime (default: 1h)
CLIENT_ASSERTION_MAX_LIFETIME=5m        # Reject assertions whose exp-iat exceeds this (default: 5m)
CLIENT_ASSERTION_CLOCK_SKEW=30s         # Tolerance for exp/nbf/iat skew (default: 30s)
```

When enabled, the OIDC discovery document lists the new method:

```bash
curl https://authgate.example.com/.well-known/openid-configuration | jq .token_endpoint_auth_methods_supported
# ["client_secret_basic","client_secret_post","none","private_key_jwt"]

curl https://authgate.example.com/.well-known/openid-configuration | jq .token_endpoint_auth_signing_alg_values_supported
# ["RS256","ES256"]
```

## Supported algorithms

- **RS256** — 2048-bit (or larger) RSA with SHA-256
- **ES256** — ECDSA P-256 with SHA-256

`HS256` and other symmetric algorithms are rejected by design (they provide no advantage over `client_secret_*`). `EdDSA` is not currently supported; file an issue if you need it.

## Registering a client

### Option 1 — Dynamic Client Registration (RFC 7591)

Enable DCR (`ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`), then POST a client metadata document:

```bash
curl -X POST https://authgate.example.com/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-service",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "RS256",
    "scope": "email profile",
    "jwks": {
      "keys": [
        {
          "kty": "RSA",
          "use": "sig",
          "kid": "2026-04-12",
          "alg": "RS256",
          "n": "0vx7agoebGcQ...",
          "e": "AQAB"
        }
      ]
    }
  }'
```

Alternative: provide `jwks_uri` instead of an inline `jwks`:

```json
{
  "client_name": "my-service",
  "grant_types": ["client_credentials"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks_uri": "https://my-service.example.com/.well-known/jwks.json"
}
```

`jwks_uri` and `jwks` are **mutually exclusive**; exactly one must be present.

Registered clients start in `pending` status and require admin approval (standard DCR behaviour). The response does **not** include a `client_secret` — `private_key_jwt` clients have no shared secret.

### Option 2 — Service-layer API

Callers with direct access to the service layer can use `services.CreateClientRequest` with the new fields:

```go
req := services.CreateClientRequest{
    ClientName:                  "my-service",
    ClientType:                  core.ClientTypeConfidential,
    EnableClientCredentialsFlow: true,
    TokenEndpointAuthMethod:     models.TokenEndpointAuthPrivateKeyJWT,
    TokenEndpointAuthSigningAlg: "RS256",
    JWKS:                        jwkSetJSON,   // or JWKSURI: "https://..."
    IsAdminCreated:              true,         // active immediately
}
resp, err := clientService.CreateClient(ctx, req)
```

### Admin UI

The admin web form does not yet expose the new fields. Admins can register `private_key_jwt` clients via the DCR endpoint above or via a small helper script that calls the service layer directly. This will be added in a follow-up.

## Requesting a token

The client signs a JWT and presents it as `client_assertion` at `/oauth/token`:

```http
POST /oauth/token HTTP/1.1
Host: authgate.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=read write
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<SIGNED_JWT>
```

### Required JWT claims

| Claim | Value                                                                         |
| ----- | ----------------------------------------------------------------------------- |
| `iss` | Your client_id                                                                |
| `sub` | Your client_id (must match `iss`)                                             |
| `aud` | AuthGate's token endpoint URL, or the issuer URL                              |
| `iat` | Issued-at timestamp (now)                                                     |
| `exp` | Expiration (max `iat + CLIENT_ASSERTION_MAX_LIFETIME`; recommend 1–5 minutes) |
| `jti` | Unique per-assertion identifier (required — replay protection)                |

### JWT header

`alg` must match `token_endpoint_auth_signing_alg` that was registered for the client. Include `kid` so AuthGate can pick the right key from your JWK Set:

```json
{
  "alg": "RS256",
  "kid": "2026-04-12",
  "typ": "JWT"
}
```

## Client examples

### Python (official MCP SDK)

```python
from mcp.client.auth.extensions.client_credentials import (
    PrivateKeyJWTOAuthProvider,
    SignedJWTParameters,
)
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

jwt_params = SignedJWTParameters(
    issuer="my-service",              # client_id
    subject="my-service",              # must match issuer
    signing_key=open("private_key.pem").read(),
    signing_algorithm="RS256",
    lifetime_seconds=300,
)

provider = PrivateKeyJWTOAuthProvider(
    server_url="https://authgate.example.com/mcp",
    client_id="my-service",
    assertion_provider=jwt_params.create_assertion_provider(),
    scopes="read write",
)
```

The SDK obtains the token endpoint URL from AuthGate's `/.well-known/openid-configuration` and handles assertion signing + token refresh automatically.

### curl (debugging)

Generate a key pair and sign a JWT manually (using `python -c` or `jose-util`), then:

```bash
ASSERTION=$(python3 - <<'PY'
import jwt, time, uuid
priv = open('private_key.pem').read()
claims = {
    'iss': 'my-service',
    'sub': 'my-service',
    'aud': 'https://authgate.example.com/oauth/token',
    'iat': int(time.time()),
    'exp': int(time.time()) + 300,
    'jti': str(uuid.uuid4()),
}
print(jwt.encode(claims, priv, algorithm='RS256', headers={'kid': '2026-04-12'}))
PY
)

curl -X POST https://authgate.example.com/oauth/token \
  -d grant_type=client_credentials \
  -d scope="read write" \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion="$ASSERTION"
```

## Key rotation

- **`jwks_uri`**: publish both old and new keys during overlap; AuthGate re-fetches when it encounters a `kid` it doesn't know (bypassing `JWKS_CACHE_TTL`). This supports zero-downtime rotation.
- **Inline `jwks`**: update the client via DCR or admin API with the new JWK Set. Old clients already issued assertions against the old key continue to verify until reassertions start arriving with the new `kid`.

Best practice: keep both keys published for at least twice the longest `exp` you expect (e.g. 10 minutes for 5-minute assertions) before retiring the old one.

## Which endpoints accept `private_key_jwt`

Currently supported:

- `POST /oauth/token` for **`grant_type=client_credentials`** — primary use case (MCP M2M).
- `POST /oauth/introspect` — so Resource Servers can authenticate via the same JWT.

The other grants (`authorization_code`, `refresh_token`, `device_code`) continue to use `client_secret_*` or public-client (no auth) modes. Extending them is tracked as a follow-up — the shared authenticator (`internal/handlers/client_auth.go`) is already in place, only the per-grant wiring is pending.

## Troubleshooting

| Symptom                                           | Likely cause                                                                                                         |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `invalid_client` immediately                      | `iss` / `sub` / `aud` mismatch, or `exp` missing/past                                                                |
| `invalid_client` after a few seconds              | Clock skew — check `CLIENT_ASSERTION_CLOCK_SKEW`                                                                     |
| `invalid_client` on re-use                        | `jti` replay — each assertion must be unique                                                                         |
| `invalid_client` with correct claims              | `kid` missing or not in registered JWKS; check server logs for `no matching JWK for kid`                             |
| `invalid_client` after key rotation               | `JWKS_CACHE_TTL` not yet expired and `kid` mismatch didn't trigger refresh — verify new key ships with a fresh `kid` |
| `unauthorized_client` instead of `invalid_client` | Client registered but `client_credentials` flow not enabled                                                          |

Check `/admin/audit` with filter `event_type=CLIENT_ASSERTION_FAILED` for the exact reason logged server-side.

## Security notes

- **Private keys must never leave the client.** Use a secrets manager (AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault) or a KMS-backed sign API (AWS KMS, GCP Cloud KMS).
- Keep assertion lifetime short (≤ 5 minutes) — `CLIENT_ASSERTION_MAX_LIFETIME` caps it server-side.
- Use a cryptographically-random `jti` per assertion (a UUIDv4 is fine).
- `PRIVATE_KEY_JWT_ENABLED=false` immediately rejects all assertion-based authentication and hides the method from discovery — a useful kill-switch if key material is suspected to be compromised and you need time to investigate.
- `jti` replay protection currently uses an in-memory cache per instance. For multi-instance deployments where a client might hit different replicas within the same assertion lifetime, promote the jti cache to Redis (tracked as a follow-up).
