# Token 與撤銷

流程跑完之後，串接方需要知道的 AuthGate token 事項：生命週期、刷新、撤銷、即時驗證。

## Token 生命週期

流程成功後您會拿到其中一或多種：

| Token           | 格式                 | 生命週期（依客戶端 profile 而定）                  | 用途                                                |
| --------------- | -------------------- | -------------------------------------------------- | --------------------------------------------------- |
| Access token    | JWT                  | `short` 15m · `standard` 10h · `long` 24h（近似值）| `Authorization: Bearer` 打 API                      |
| Refresh token   | JWT（請當不透明處理）| `short` 1d · `standard` 30d · `long` 90d（近似值） | 到 `/oauth/token` 換新 access token                 |
| ID token        | JWT                  | 與 access token 相同                               | 客戶端身分資訊 — [見 OIDC](./oidc)                  |

> Refresh token 內部是 JWT，但您應該 **把它當成不透明** — 在客戶端不要去解析其 claim，收穫為零還會耦合到內部實作。

實際數值取決於管理員為此客戶端選擇的 **token profile**。**請一律相信 token response 的 `expires_in`**，永遠不要寫死。

## 刷新 token

在 refresh token 本身過期之前，任何時刻都可以：

```bash
curl -X POST https://your-authgate/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN" \
  -d "client_id=YOUR_CLIENT_ID"
# 機密客戶端：改用 -u "$CLIENT_ID:$CLIENT_SECRET"，body 不要帶 client_id
```

**回應** 與初次 token 交換相同格式。

**何時刷新**：提前刷，例如過期前 30–60 秒，不要等到收到 401 才做。這樣可以避免請求失敗的中途錯誤與重試的噪音。

> 若您的部署啟用 rotation 模式（下節），還必須 **將同一 session 的並發刷新序列化** — 兩個分頁同時刷新會直接毀掉 session。

### 輪轉模式：重用偵測的陷阱

某些 AuthGate 部署會啟用 **rotation 模式**（`ENABLE_TOKEN_ROTATION=true`）。在這個模式：

- 每次刷新會簽發 **新的** refresh token 並 **作廢** 舊的。
- 若舊 refresh token 被再次使用（兩個分頁搶刷、網路抖動後重試、token 被偷去用），AuthGate 會偵測到重用，然後 **把整個 token family 撤銷**。
- 後續請求會回 `{"error": "invalid_grant"}`。

**對串接方的實務意義：**

- **序列化每個使用者 / session 的刷新**（mutex、single-flight）。兩個分頁同時刷新，兩邊都拿著同一份舊 refresh token，一個會贏，另一個會用 *剛被作廢* 的舊 token 觸發重用偵測，整個 session 就死了。
- **立刻持久化新 refresh token**。儲存更新前，不要先用舊的再發一輪請求。
- **刷新時收到 `invalid_grant` 是終態** — 請顯示登入頁面，不要重試。

從 token response 本身無法判斷 rotation 是否開啟。若您的串接必須同時支援兩種模式，一律把回傳的 `refresh_token` 存下來（即使看起來一樣 — rotation 模式下它會不同）。

## 登出 — `/oauth/revoke`（RFC 7009）

登出時撤銷 **refresh token**（access token 可選），讓被偷走的也變成啞彈：

```bash
curl -X POST https://your-authgate/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=REFRESH_TOKEN" \
  -d "token_type_hint=refresh_token" \
  -d "client_id=YOUR_CLIENT_ID"
# 機密客戶端：帶 client_secret 或使用 HTTP Basic
```

| 參數              | 必填 | 值                                        |
| ----------------- | ---- | ----------------------------------------- |
| `token`           | 是   | 要撤銷的 token                            |
| `token_type_hint` | 否   | `access_token` 或 `refresh_token`         |
| `client_id`       | 是   | 機密客戶端還需要 `client_secret`          |

依 RFC 7009，不論 token 原本存不存在，端點一律回 **`200 OK`**。不要依賴回應判斷狀態 — 直接當作 token 已經消失。

> 撤銷一張 refresh token 也會（在 rotation 模式下）作廢整個 token family。撤銷 access token **不會** 順便作廢對應的 refresh token — 要嘛兩者都撤，要嘛登出時撤 refresh token，短效的 access token 自然過期即可。

## 即時驗證

resource server 的本地 JWT 驗證見 [JWT 驗證](./jwt-verification)。那條路速度快、可水平擴展，但 **無法** 察覺被撤銷 / 停用的 token — 一張被撤銷的 JWT 在密碼學上仍然有效，直到 `exp`。

需要即時察覺撤銷時，用以下端點之一：

### `/oauth/introspect`（RFC 7662）— 首選

需要客戶端認證（呼叫端本身必須是已註冊的 AuthGate 客戶端）：

```bash
curl -X POST https://your-authgate/oauth/introspect \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=TOKEN_TO_CHECK" \
  -d "token_type_hint=access_token"
```

**回應：**

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client-uuid",
  "username": "alice",
  "token_type": "Bearer",
  "exp": 1700000000,
  "iat": 1699996400,
  "sub": "user-uuid",
  "iss": "https://your-authgate",
  "jti": "unique-token-id"
}
```

若 token 無效、過期、被撤銷或停用，回應是：

```json
{ "active": false }
```

**政策強制** 要有即時性時用這個 — 管理儀表板、高價值操作，任何無法容忍 ≤ 1 小時「陳舊有效」窗口的場景。

### `/oauth/tokeninfo` — 輕量替代

以 Bearer header 帶 token，回傳較少的欄位。不用客戶端憑證（token 本身即認證）：

```bash
curl -H "Authorization: Bearer TOKEN_TO_CHECK" https://your-authgate/oauth/tokeninfo
```

```json
{
  "active": true,
  "user_id": "user-uuid",
  "client_id": "client-uuid",
  "scope": "openid profile email",
  "exp": 1700000000,
  "iss": "https://your-authgate",
  "subject_type": "user"
}
```

Client Credentials 發出的 token，`subject_type` 會是 `"client"`。無效 token 回 `401` 並帶 OAuth `invalid_token` 錯誤。

### 該選哪個？

| 需求                                                         | 方式                                        |
| ------------------------------------------------------------ | ------------------------------------------- |
| resource server 大量驗證，可容忍短暫陳舊                     | **本地 JWKS 驗證**（不打 AuthGate）         |
| 需要即時撤銷狀態，呼叫端能做客戶端認證                       | **`/oauth/introspect`**                     |
| 使用者 session 內的輕量檢查，手邊沒有客戶端憑證              | **`/oauth/tokeninfo`**                      |
| 呼叫端本身就是此 token 的持有者                              | **`/oauth/tokeninfo`**                      |

## 速率限制

AuthGate 對 token 路徑端點做每 IP 速率限制。預設值（營運者可調整）：

| 端點                        | 預設限制           |
| --------------------------- | ------------------ |
| `POST /oauth/token`         | 20 req/min         |
| `POST /oauth/device/code`   | 10 req/min         |
| `POST /device/verify`       | 10 req/min         |
| `POST /oauth/introspect`    | 20 req/min         |
| `POST /login`               | 5 req/min          |

超過限制回 `429 Too Many Requests`。若有 `Retry-After` header 請遵守；沒有的話指數退避。能批次就批次 — 可以本地 JWKS 驗證時不要用 `/oauth/tokeninfo` 逐筆打。

## 相關文件

- [開始使用](./getting-started)
- [Authorization Code Flow](./auth-code-flow)
- [Device Authorization Flow](./device-flow)
- [Client Credentials Flow](./client-credentials)
- [JWT 驗證](./jwt-verification)
- [OpenID Connect](./oidc)
- [錯誤處理](./errors)
