# 錯誤處理

AuthGate 回傳的 OAuth 錯誤碼，以及串接方該怎麼處理。所有錯誤都遵循 RFC 6749 §5.2：

```json
{
  "error": "invalid_grant",
  "error_description": "Human-readable description of what went wrong"
}
```

`error_description` 是給您看的（記 log、除錯）— **不要** 顯示給終端使用者。

## 依情境分類的錯誤

### 授權端點的導回錯誤

當 `/oauth/authorize` 在使用者已被導回 `redirect_uri` 後失敗，錯誤會透過 query string 傳回：

```
https://yourapp.example/callback?error=access_denied&error_description=...&state=RANDOM_STATE
```

| `error`                     | 原因                                                                           | 您該怎麼做                                                    |
| --------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| `access_denied`             | 使用者拒絕授權，或管理員撤銷了使用者的存取權                                   | 顯示「登入已取消」；讓使用者重試                              |
| `invalid_request`           | 缺少 / 畸形的參數，**或** 此客戶端要求 PKCE 但沒帶 `code_challenge`            | 修正請求 — 這是客戶端的 bug                                   |
| `invalid_scope`             | 要求的 scope 不在此客戶端允許範圍                                              | 拿掉該 scope；與管理員確認                                    |
| `unauthorized_client`       | 此客戶端沒開 Authorization Code Flow                                           | 請管理員為此客戶端開啟 Auth Code Flow                         |
| `unsupported_response_type` | `response_type` 不是 `code`                                                    | 改用 `response_type=code`                                     |
| `server_error`              | AuthGate 暫時性錯誤                                                            | 退避重試                                                      |

### Token 端點錯誤（`/oauth/token`）

回傳 HTTP 400 JSON（除了 `invalid_client` 是 401）：

| `error`                  | HTTP | 常見原因                                                              | 您該怎麼做                                            |
| ------------------------ | ---- | --------------------------------------------------------------------- | ----------------------------------------------------- |
| `invalid_request`        | 400  | 缺必填 form 欄位                                                      | 修正請求                                              |
| `invalid_client`         | 401  | `client_id` / `client_secret` 錯，或沒提供客戶端認證                  | 核對憑證；HTTP Basic vs. body 要一致                  |
| `invalid_grant`          | 400  | code / refresh token / device code 無效、過期、已用過、或被撤銷（含 rotation 重用偵測）；或 PKCE `code_verifier` 與原 `code_challenge` 不符 | 停止重試。重啟流程 / 要求使用者重新登入               |
| `invalid_scope`          | 400  | Scope 超過客戶端或原授權的範圍                                        | 去掉或縮小 scope                                      |
| `unauthorized_client`    | 400  | 此 grant type 在此客戶端未啟用                                        | 請管理員開啟                                          |
| `unsupported_grant_type` | 400  | 不認識的 `grant_type`                                                 | 用 `authorization_code`、`refresh_token`、`urn:ietf:params:oauth:grant-type:device_code` 或 `client_credentials` 之一 |
| `server_error`           | 500  | AuthGate 內部錯誤                                                     | 退避重試；持續異常請上報                              |

### Device Flow 輪詢錯誤

對 `/oauth/token` 做 `grant_type=urn:ietf:params:oauth:grant-type:device_code` 輪詢時：

| `error`                 | 意義                                         | 您該怎麼做                                      |
| ----------------------- | -------------------------------------------- | ----------------------------------------------- |
| `authorization_pending` | 使用者還沒同意                               | 維持 `interval` 繼續輪詢                        |
| `slow_down`             | 輪詢太快                                     | **將 `interval` 增加 ≥ 5 秒**                   |
| `access_denied`         | 使用者拒絕                                   | 停止；告訴使用者                                |
| `expired_token`         | `device_code` 超過 `expires_in`              | 從 `POST /oauth/device/code` 重跑                |
| `invalid_grant`         | `device_code` 不存在或已被用過               | 重跑流程                                        |

細節見 [Device Flow](./device-flow)。

### Token Introspection 與驗證

| 端點                          | 失敗情境                                    | 回應                                                              |
| ----------------------------- | ------------------------------------------- | ----------------------------------------------------------------- |
| `GET /oauth/tokeninfo`        | 缺 Bearer header                            | `401` `{"error": "missing_token"}`                                |
| `GET /oauth/tokeninfo`        | Token 無效或過期                            | `401` `{"error": "invalid_token", ...}`                           |
| `GET /oauth/userinfo`         | 缺 / 無效 Bearer                            | `401` + `WWW-Authenticate: Bearer error="invalid_token"`          |
| `POST /oauth/introspect`      | 缺 / 無效的客戶端認證                       | `401` + `WWW-Authenticate: Basic realm="authgate"`                |
| `POST /oauth/introspect`      | Token 無效 / 過期 / 被撤銷                  | `200` `{"active": false}`（依 RFC 7662 — 永遠不是 4xx）           |
| `POST /oauth/revoke`          | 任何情況                                    | `200`（依 RFC 7009 — 不帶錯誤訊號）                               |

## 速率限制錯誤 — HTTP 429

超過每 IP 速率限制會拿到 `429 Too Many Requests`：

```
HTTP/1.1 429 Too Many Requests
Retry-After: 30
Content-Type: application/json

{"error": "rate_limit_exceeded", "error_description": "..."}
```

**處理方式：**

- **一律遵守 `Retry-After`**（若有）。
- 連續 429 就指數退避 + jitter。
- 做 Device Flow 輪詢的話，`interval` 本該讓您遠低於限制。看到 429 代表您輪詢節奏不對 — 修客戶端，不是加快重試。
- 多服務共用同一出口 IP 時，可以請管理員把 IP 放白名單或調高限制。

預設值見 [Token 與撤銷](./tokens)。

## 特例：Refresh Token 重用 → Family 撤銷

rotation 模式下，使用已被輪轉掉的舊 refresh token 會回 `invalid_grant`，同時 **整個 token family 在伺服器端被撤銷**。這是 **終態**，不要重試。

```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token is invalid or expired"
}
```

原因可能是：

- 兩個分頁 / 行程用同一份儲存的 token 並發刷新
- 部分失敗後重試，但沒持久化新 token
- 被偷走的 token 被別人先用了

**回應**：強制使用者重新登入。預防方式見 [Token 與撤銷](./tokens)。

## 錯誤處理檢查清單

- [ ] 刷新時遇到 `invalid_grant` 視為終態 — 觸發重新登入，不要重試
- [ ] `access_denied` 是使用者主動 — 客氣地提示，不要自動重試
- [ ] `server_error` 與網路錯誤指數退避重試
- [ ] 遇 429 尊重 `Retry-After`
- [ ] 伺服器端記 `error_description`；**絕對不要** 顯示給終端使用者
- [ ] `invalid_request` / `invalid_scope` / `unsupported_grant_type` / `unsupported_response_type` 是客戶端 bug — 修，不要重試
- [ ] 關注 `invalid_client` 飆高 — 可能有人在探測憑證，或發生了輪替 / 外洩

## 相關文件

- [開始使用](./getting-started)
- [Authorization Code Flow](./auth-code-flow)
- [Device Authorization Flow](./device-flow)
- [Client Credentials Flow](./client-credentials)
- [Token 與撤銷](./tokens)
- [JWT 驗證](./jwt-verification)
- [OpenID Connect](./oidc)
