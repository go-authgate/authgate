# 開始使用 AuthGate

這份指南是寫給**串接方**開發者的：您要將既有的應用程式接上已經部署好的 AuthGate。若您要找伺服器營運與部署文件（啟動伺服器、環境變數、金鑰產生等），請參考專案 README。

AuthGate 是一個 OAuth 2.0 + OpenID Connect 授權伺服器，會簽發權杖（token）給您的應用程式，用於認證使用者與呼叫受保護的 API。

## 選擇流程

| 您的應用程式型態                                  | 建議流程                                         |
| ------------------------------------------------- | ------------------------------------------------ |
| 伺服器端網頁應用（有後端）                        | Authorization Code + PKCE（機密客戶端）          |
| 單頁應用（React / Vue / Svelte 等）               | Authorization Code + PKCE（公開客戶端）          |
| 行動或桌面應用                                    | Authorization Code + PKCE（公開客戶端）          |
| CLI 工具、IoT 裝置、無頭環境（SSH、容器）         | Device Authorization Grant                       |
| 後端服務呼叫另一個服務（無使用者）                | Client Credentials                               |

還沒頭緒？任何「有使用者」的情境請用 **Authorization Code + PKCE**，「服務對服務」請用 **Client Credentials**。

## 串接之前

向 AuthGate 管理員索取：

1. **Base URL** — 例如 `https://your-authgate`。其他資訊都可以從 `BASE_URL/.well-known/openid-configuration` 發現（見下節）。
2. **`client_id`** — 識別您的應用程式。
3. **`client_secret`** — 只有 *機密* 客戶端才會拿到（伺服器端網頁應用、Client Credentials 服務）。公開客戶端（SPA、行動、CLI）沒有 secret。
4. **允許的 redirect URI** — Authorization Code Flow 會用到。AuthGate 做 **完全字串比對**：`https://yourapp.example/cb` 與 `https://yourapp.example/cb/` 是不同的。
5. **允許的 scope** — 此客戶端可要求的 scope 子集（例如 `openid`、`profile`、`email`、`offline_access`）。管理員也可能註冊了自訂的 API scope，請向管理員詢問。
6. **啟用的 grant type** — 此客戶端開啟了 Device Flow / Auth Code Flow / Client Credentials 中的哪幾種。

## 從這裡開始：OIDC Discovery

不要把端點 URL 寫死，改成抓取 OIDC Discovery 文件：

```bash
curl https://your-authgate/.well-known/openid-configuration
```

```json
{
  "issuer": "https://your-authgate",
  "authorization_endpoint": "https://your-authgate/oauth/authorize",
  "token_endpoint": "https://your-authgate/oauth/token",
  "userinfo_endpoint": "https://your-authgate/oauth/userinfo",
  "revocation_endpoint": "https://your-authgate/oauth/revoke",
  "jwks_uri": "https://your-authgate/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "read", "write"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "grant_types_supported": [
    "authorization_code",
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
    "client_credentials"
  ],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "name", "preferred_username", "email", "email_verified", "picture", "updated_at"],
  "code_challenge_methods_supported": ["S256"]
}
```

多數成熟的 OAuth / OIDC 函式庫可以直接吃這份文件並自動把流程接起來。

**幾個需要注意的眉角：**

- `jwks_uri` 與 `id_token_signing_alg_values_supported` **只在 AuthGate 設定為 RS256/ES256（非對稱簽章）時才會出現**。HS256 部署會省略這兩個欄位。
- `/oauth/introspect` 與 `/oauth/device/code` 有支援，但 **未在 Discovery 宣告**，請直接使用本指南列出的路徑。
- `offline_access` 即使沒列在 `scopes_supported`，被要求時仍會被接受。

## 支援的 scope

| Scope            | 用途                                                                            |
| ---------------- | ------------------------------------------------------------------------------- |
| `openid`         | 要拿到 **ID token** 與使用 `/oauth/userinfo` 的必要條件                         |
| `profile`        | 在 UserInfo / ID token 中解鎖 `name`、`preferred_username`、`picture`、`updated_at` |
| `email`          | 在 UserInfo / ID token 中解鎖 `email`、`email_verified`                         |
| `offline_access` | 表示您想拿到 refresh token（OIDC Core §11）                                     |

注意事項：

- `openid` 與 `offline_access` 在 Client Credentials 流程中 **不合法**，會被拒絕。
- 客戶端只能索取管理員為其註冊過的 scope。
- scope 以**空白分隔字串**傳送（`scope=openid profile email`）。

## 權杖速覽

流程成功後，AuthGate 會簽發：

- **Access token** — JWT；短效；帶在 API 呼叫的 `Authorization: Bearer <token>` 中。
- **Refresh token** — 不透明；較長效；拿到 `/oauth/token` 換取新的 access token。
- **ID token** — 關於使用者的 JWT（只有 `scope` 包含 `openid` 時才會有）。詳見 [OpenID Connect](./oidc)。

Access token 的生命週期會依每個客戶端的設定而異（`short` ≈ 15 分鐘、`standard` ≈ 10 小時、`long` ≈ 24 小時）。**請一律看 token response 的 `expires_in` 欄位**，絕對不要寫死時間。

速率限制、撤銷、反查、refresh rotation：請見 [Token 與撤銷](./tokens)。

## 最小串接檢查清單

- [ ] 與管理員確認 `BASE_URL`、`client_id`、（必要時）`client_secret`、redirect URI、scope。
- [ ] 啟動時抓一次 `/.well-known/openid-configuration` 並快取。
- [ ] 選一個流程並實作（見下方各流程文件）。
- [ ] 在 resource server 以 JWKS 驗證 token（[JWT 驗證](./jwt-verification)）。
- [ ] 處理常見的 OAuth 錯誤（[錯誤處理](./errors)）。
- [ ] 實作登出：以 refresh token 呼叫 `/oauth/revoke`（[Token 與撤銷](./tokens)）。
- [ ] 如果是公開且長效的客戶端，使用 PKCE（AuthGate 只接受 `S256`）。

## 下一步

- [Authorization Code Flow + PKCE](./auth-code-flow) — 網頁、SPA、行動應用
- [Device Authorization Flow](./device-flow) — CLI 與無頭客戶端
- [Client Credentials Flow](./client-credentials) — 服務對服務
- [OpenID Connect](./oidc) — ID token 與 UserInfo
- [JWT 驗證](./jwt-verification) — 在 resource server 驗證 access token
- [Token 與撤銷](./tokens) — 刷新、撤銷、反查
- [錯誤處理](./errors) — OAuth 錯誤碼與對應做法
