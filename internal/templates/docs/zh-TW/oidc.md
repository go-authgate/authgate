# OpenID Connect（ID Token 與 UserInfo）

AuthGate 在 Authorization Code Flow 上支援 **OpenID Connect 1.0**。當您在 `scope` 中包含 `openid`，AuthGate 會在發出 access token 的同時簽發一張 **ID token**，並開放 `/oauth/userinfo` 端點。

> **目前 Device Flow 不簽發 ID token**。要做 OIDC 請用 [Authorization Code Flow](./auth-code-flow)。

## ID Token vs. Access Token

| 問題                                  | ID Token                                         | Access Token                                   |
| ------------------------------------- | ------------------------------------------------ | ---------------------------------------------- |
| 它在描述 *誰*？                       | 終端使用者（身分）                               | 呼叫 API 的授權                                |
| 它 *給誰用*？                         | **您的客戶端應用**（`aud=client_id`）            | Resource server（不設 `aud`）                  |
| 能當 `Authorization: Bearer` 送 API？ | **不行** — 永遠不行                              | 可以                                           |
| 需要驗 `aud`？                        | **要** — 必須等於您的 `client_id`                | 不需要 — AuthGate 這邊不設 `aud`               |
| 需要驗 `nonce`？                      | 要 — 必須與您送出的一致                          | 不適用                                         |
| 包含個資？                            | 有（email、name、picture，視 scope 而定）        | 無                                             |

**原則**：只有您自己的客戶端應用才應該去解析 ID token。把它傳給另一個服務，等於把使用者身分洩露給非預期對象。

## 索取 ID token

在 Authorization Code Flow 的授權請求中把 `openid` 放進 `scope`，並帶上 `nonce`：

```
GET /oauth/authorize
  ?client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yourapp.example/callback
  &response_type=code
  &scope=openid profile email
  &state=RANDOM_STATE
  &nonce=RANDOM_NONCE
  &code_challenge=CODE_CHALLENGE
  &code_challenge_method=S256
```

在 `/oauth/token` 換取 token 的回應中會附上 `id_token`：

```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "def502...",
  "id_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

## ID Token 的 claims

**Header：**

```json
{
  "alg": "RS256",
  "kid": "abc123...",
  "typ": "JWT"
}
```

**Payload**（依授予的 scope 而定）：

| Claim                | 必出現 | 出現時機                                          | 意義                                                                |
| -------------------- | ------ | ------------------------------------------------- | ------------------------------------------------------------------- |
| `iss`                | ✓      |                                                   | Issuer URL — 必須等於您的 AuthGate `BASE_URL`                       |
| `sub`                | ✓      |                                                   | 穩定的使用者識別（UUID）                                            |
| `aud`                | ✓      |                                                   | 您的 `client_id` — **必須相符** 才算有效                            |
| `exp`                | ✓      |                                                   | 過期時間（Unix 秒）                                                 |
| `iat`                | ✓      |                                                   | 簽發時間（Unix 秒）                                                 |
| `auth_time`          | ✓      |                                                   | 使用者認證時間（Unix 秒）                                           |
| `jti`                | ✓      |                                                   | 唯一 token id                                                       |
| `nonce`              | —      | 您在授權請求有帶 `nonce` 時                       | 必須與您送出的值一致 — 防重送                                       |
| `at_hash`            | —      | 同時簽發 access token 時                          | 對 access token 做 SHA-256 的前半段，base64url 編碼                 |
| `name`               | —      | `scope` 含 `profile`                              | 顯示用全名                                                          |
| `preferred_username` | —      | `scope` 含 `profile`                              | 顯示用帳號（例如 `alice`）                                          |
| `picture`            | —      | `scope` 含 `profile` 且使用者有大頭貼             | 頭像 URL                                                            |
| `updated_at`         | —      | `scope` 含 `profile`                              | profile 最近更新時間（Unix 秒）                                     |
| `email`              | —      | `scope` 含 `email`                                | 主要 email                                                          |
| `email_verified`     | —      | `scope` 含 `email`                                | `true` 表示 email 已被驗證（例如透過 OAuth provider）                |

## 驗證 ID token

與 access token 同樣使用 JWKS（見 [JWT 驗證](./jwt-verification)），但驗證規則 **更嚴格**：

1. **簽章** — 以 JWKS 中 `kid` 對應的金鑰驗證。
2. **`iss`** — 必須等於您的 AuthGate `BASE_URL`。
3. **`aud`** — 必須等於您的 `client_id`。若 `aud` 是陣列，必須包含您的 `client_id` 且不得包含可疑值。
4. **`exp`** — 必須在未來（可容許少量時鐘偏移，例如 30 秒）。
5. **`iat`** — 應該是近期時間。
6. **`nonce`** — 必須等於您在授權請求送出的 `nonce`。
7. **`auth_time`** — 若您帶了 `max_age`，需強制檢查。
8. **`at_hash`** *（選用、建議）* — 驗證與同時拿到的 access token 相符。

### Go（golang-jwt + keyfunc）

```go
import (
    "strings"
    "github.com/MicahParks/keyfunc/v3"
    "github.com/golang-jwt/jwt/v5"
)

jwksURL := "https://your-authgate/.well-known/jwks.json"
k, _ := keyfunc.NewDefault([]string{jwksURL})

token, err := jwt.Parse(idTokenString, k.Keyfunc,
    jwt.WithIssuer("https://your-authgate"),
    jwt.WithAudience(clientID),               // 強制驗 aud
    jwt.WithExpirationRequired(),
    jwt.WithValidMethods([]string{"RS256", "ES256"}),
)
if err != nil {
    return fmt.Errorf("invalid id_token: %w", err)
}

claims := token.Claims.(jwt.MapClaims)
nonce, ok := claims["nonce"].(string)
if !ok || nonce != expectedNonce {
    return fmt.Errorf("nonce mismatch")
}
```

### Python（PyJWT）

```python
import jwt
from jwt import PyJWKClient

jwks_client = PyJWKClient(f"{AUTHGATE_URL}/.well-known/jwks.json")
signing_key = jwks_client.get_signing_key_from_jwt(id_token)

claims = jwt.decode(
    id_token,
    signing_key.key,
    algorithms=["RS256", "ES256"],
    issuer=AUTHGATE_URL,
    audience=CLIENT_ID,              # 強制驗 aud
    options={"require": ["exp", "iss", "sub", "aud"]},
)

if claims.get("nonce") != expected_nonce:
    raise ValueError("nonce mismatch")
```

### Node.js（jose）

```javascript
import { createRemoteJWKSet, jwtVerify } from "jose";

const JWKS = createRemoteJWKSet(new URL(`${AUTHGATE_URL}/.well-known/jwks.json`));

const { payload } = await jwtVerify(idToken, JWKS, {
  issuer: AUTHGATE_URL,
  audience: CLIENT_ID,               // 強制驗 aud
  algorithms: ["RS256", "ES256"],
});

if (payload.nonce !== expectedNonce) throw new Error("nonce mismatch");
```

## UserInfo 端點

要取得 scope 授權的即時使用者資料，請用 **access token**（不是 ID token）呼叫 `/oauth/userinfo`：

```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" https://your-authgate/oauth/userinfo
```

**回應**（欄位取決於授予的 scope）：

```json
{
  "sub": "user-uuid",
  "iss": "https://your-authgate",
  "name": "Alice Example",
  "preferred_username": "alice",
  "picture": "https://...",
  "updated_at": 1700000000,
  "email": "alice@example.com",
  "email_verified": true
}
```

- 一定包含 `sub` 與 `iss`
- `profile` scope 控制 `name`、`preferred_username`、`picture`、`updated_at`
- `email` scope 控制 `email`、`email_verified`

若 token 無效或過期，UserInfo 回應 `401 Unauthorized` 並帶 `WWW-Authenticate: Bearer error="invalid_token"`。

**ID token 的 claim vs. UserInfo，該選哪個？** ID token 是登入當下一次性的身分證明。若需要即時 profile 資料（例如使用者剛換頭像），用當下的 access token 打 UserInfo。

## Discovery

OIDC 函式庫應該自動從這裡取得設定：

```
https://your-authgate/.well-known/openid-configuration
```

完整文件格式見 [開始使用](./getting-started)。

## 常見陷阱

- **把 ID token 當 Bearer 送去打 API**。不要。用 access token。
- **不驗 `aud`**。缺這一步，別人家客戶端的 ID token 可能被您誤接受。
- **不驗 `nonce`**。一律送並驗 `nonce`。規範雖然在 Auth Code Flow 標為 OPTIONAL，但省略就等於放棄防重送保護，強烈不建議。
- **沒驗簽就解析 ID token**。千萬別這樣做 — 沒驗簽前的 JWT 是 *未認證* 的。
- **對 access token 要求 `aud`**。access token 沒有 `aud`，只有 ID token 才有。

## 相關文件

- [開始使用](./getting-started)
- [Authorization Code Flow](./auth-code-flow)
- [JWT 驗證](./jwt-verification)
- [Token 與撤銷](./tokens)
- [錯誤處理](./errors)
