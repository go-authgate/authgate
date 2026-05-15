# MCP Integration Guide

AuthGate implements the OAuth 2.1 surface required by the
[Model Context Protocol (MCP) authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization),
so it can act as a drop-in authorization server for any MCP deployment.

This guide covers what an MCP server (the resource server) advertises to
clients, what AuthGate provides on each side of the trust boundary, and how
to wire the two together.

## Trust boundary

| Component            | Owner                | Responsibility                                                       |
| -------------------- | -------------------- | -------------------------------------------------------------------- |
| MCP client           | The application      | Discovers the AS, performs PKCE, sends `resource=<MCP-URL>`          |
| MCP server (RS)      | Your deployment      | Publishes [RFC 9728 Protected Resource Metadata][rfc9728] pointing at AuthGate; verifies token signature, `iss`, `aud` |
| AuthGate (AS)        | This service         | Issues access/refresh tokens with audience bound to the MCP resource |

AuthGate does **not** publish RFC 9728 Protected Resource Metadata; that
belongs to each MCP server. The PRM document is what tells clients which
AuthGate URL to use.

[rfc9728]: https://datatracker.ietf.org/doc/html/rfc9728

## What to advertise on your MCP server

The MCP server's PRM document (`/.well-known/oauth-protected-resource`) must
advertise the AuthGate base URL as its authorization server. Example:

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["read", "write"]
}
```

When an MCP client receives a 401 with `WWW-Authenticate: Bearer
resource_metadata="..."`, it fetches the PRM, follows
`authorization_servers[0]`, and asks AuthGate for metadata.

## AuthGate AS metadata

MCP clients try `/.well-known/oauth-authorization-server` (RFC 8414) first,
then fall back to OIDC discovery. AuthGate publishes both:

| URL                                                  | Use                                                   |
| ---------------------------------------------------- | ----------------------------------------------------- |
| `/.well-known/oauth-authorization-server`            | OAuth 2.0 AS metadata — curated, no OIDC-only fields  |
| `/.well-known/openid-configuration`                  | OIDC Provider metadata — unchanged                    |
| `/.well-known/jwks.json`                             | Public keys for `RS256`/`ES256` verification          |

The OAuth metadata response includes:

- `issuer`, `authorization_endpoint`, `token_endpoint`
- `introspection_endpoint`, `revocation_endpoint`
- `registration_endpoint` — only when `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`
- `grant_types_supported` — `authorization_code`, `device_code`,
  `refresh_token`, `client_credentials`
- `code_challenge_methods_supported` — `["S256"]` (PKCE `plain` is rejected)
- `token_endpoint_auth_methods_supported`,
  `introspection_endpoint_auth_methods_supported`,
  `revocation_endpoint_auth_methods_supported`

Browser-based MCP clients need cross-origin access to these endpoints. The
`/.well-known/*` group respects `CORS_ENABLED` / `CORS_ALLOWED_ORIGINS`
exactly like `/oauth/*`.

## PKCE requirement

MCP requires `code_challenge_method=S256`. AuthGate's behaviour aligns:

- Public clients (no client secret) **must** present an `S256` code challenge.
- `plain` is rejected (returns `invalid_request`).
- Confidential clients may also opt into PKCE; set `PKCE_REQUIRED=true` to
  force it across all clients.

## Dynamic Client Registration (RFC 7591)

MCP recommends DCR so clients can self-register without admin intervention.
AuthGate exposes `POST /oauth/register` when
`ENABLE_DYNAMIC_CLIENT_REGISTRATION=true`. An MCP client posts:

```http
POST /oauth/register HTTP/1.1
Content-Type: application/json

{
  "client_name": "Acme MCP CLI",
  "redirect_uris": ["http://127.0.0.1:1729/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_method": "none"
}
```

The response contains `client_id` and (for confidential clients) a one-time
`client_secret`. Restrict DCR with `DYNAMIC_CLIENT_REGISTRATION_TOKEN` to
require a pre-shared bearer token for registration.

## Audience binding via Resource Indicators (RFC 8707)

MCP clients send `resource=<MCP-URL>` on both `/authorize` and `/token`. The
issued JWT's `aud` claim is **bound to the requested resource**. AuthGate:

- Validates each `resource` value against RFC 8707 §2.1 (absolute URI, no
  fragment) and rejects malformed values with `error=invalid_target`.
- Replaces the static `JWT_AUDIENCE` config for that token. When the caller
  does not send `resource`, the existing `JWT_AUDIENCE` is used as before.
- Persists the bound resource on the authorization code and on access/refresh
  token rows.
- Enforces RFC 8707 §2.2 on refresh: the caller may narrow the audience but
  never widen it. Widening returns 400 `invalid_target`.
- On `authorization_code` token exchange, validates that any token-time
  `resource` is a subset of what was bound at `/authorize`.

**Trust model:** the `aud` claim is server-attested. The MCP server must
verify that `aud` matches its own resource identifier before accepting the
token — token replay against a different MCP server with the same
`iss`/signature must fail. Standard verification still applies:

- Check the JWT signature against JWKS.
- `iss` matches AuthGate's configured `BASE_URL`.
- `exp` is in the future.
- **`type` claim equals `"access"`.** AuthGate also issues refresh tokens
  signed with the same key, but they carry `type: "refresh"` and never the
  per-request RFC 8707 resource as `aud` (refresh JWTs are signed with nil
  audience override and fall back to the static `JWT_AUDIENCE` config). A
  resource server that checks only signature/`iss`/`exp`/`aud` would silently
  accept a refresh token as a valid access token whenever `JWT_AUDIENCE` is
  configured to its own resource identifier. Reject any JWT whose `type` is
  not `"access"`, and configure `JWT_AUDIENCE` either unset or to an AS-only
  value (never a resource-server identifier).
- For tokens obtained via `client_credentials`, `sub` starts with `client:`
  (machine identity) — treat these distinctly from user-delegated tokens
  if your policy differs for them.

## curl walkthrough

```bash
# 1. Fetch AS metadata (the MCP-required endpoint).
curl -s http://localhost:8080/.well-known/oauth-authorization-server | jq '
  {issuer, authorization_endpoint, token_endpoint,
   introspection_endpoint, registration_endpoint,
   code_challenge_methods_supported}'
# Expect: code_challenge_methods_supported = ["S256"];
# registration_endpoint present when ENABLE_DYNAMIC_CLIENT_REGISTRATION=true.

# 2. Confirm CORS preflight on the metadata endpoint. A real browser preflight
#    is an OPTIONS request carrying Access-Control-Request-Method.
curl -i -X OPTIONS \
  -H "Origin: https://allowed.example.com" \
  -H "Access-Control-Request-Method: GET" \
  http://localhost:8080/.well-known/oauth-authorization-server \
  | grep -i access-control-allow-origin
# Expect: Access-Control-Allow-Origin: https://allowed.example.com

# 3. Run the authorization-code flow with a resource indicator.
#    (Perform interactive consent in a browser, then exchange the code.)
curl -s -X POST http://localhost:8080/oauth/token \
  -d grant_type=authorization_code -d "code=$CODE" -d "redirect_uri=$RURI" \
  -d "client_id=$CID" -d "code_verifier=$CV" \
  -d "resource=https://mcp.example.com"
# Decode the access_token's payload; "aud" must equal "https://mcp.example.com".

# 4. Refresh requesting a resource outside the original grant — must fail.
curl -X POST http://localhost:8080/oauth/token \
  -d grant_type=refresh_token -d "refresh_token=$RT" -d "client_id=$CID" \
  -d "resource=https://forbidden.example.com"
# Expect: 400 {"error":"invalid_target",...}
```

## Configuration checklist

For an MCP-ready deployment:

- `BASE_URL=https://auth.example.com` (your AuthGate's public URL)
- `JWT_SIGNING_ALGORITHM=RS256` or `ES256` (asymmetric keys exposed via JWKS)
- `CORS_ENABLED=true` and `CORS_ALLOWED_ORIGINS=<browser MCP client origins>`
- `ENABLE_DYNAMIC_CLIENT_REGISTRATION=true` if you want self-service MCP clients
- `ENABLE_REFRESH_TOKENS=true` (long-running MCP sessions)
- `PKCE_REQUIRED=true` recommended; AuthGate already requires `S256` for public
  clients and rejects `plain`.

No new configuration keys are required to support MCP — Resource Indicators
are always-on and backward-compatible: callers that don't send `resource`
keep getting `aud` from `JWT_AUDIENCE`.
