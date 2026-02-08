# Use Cases and Examples

This guide provides real-world examples of how to use AuthGate for different scenarios.

## Table of Contents

- [Use Cases and Examples](#use-cases-and-examples)
  - [Table of Contents](#table-of-contents)
  - [CLI Tool Authentication](#cli-tool-authentication)
    - [Scenario](#scenario)
    - [Requirements](#requirements)
    - [Implementation](#implementation)
  - [IoT Device Authentication](#iot-device-authentication)
    - [Scenario](#scenario-1)
    - [Requirements](#requirements-1)
    - [Implementation](#implementation-1)
  - [CI/CD Pipeline Authentication](#cicd-pipeline-authentication)
    - [Scenario](#scenario-2)
    - [Requirements](#requirements-2)
    - [Implementation](#implementation-2)
  - [Smart TV Authentication](#smart-tv-authentication)
    - [Scenario](#scenario-3)
    - [Requirements](#requirements-3)
    - [Implementation](#implementation-3)
  - [Security Incident Response](#security-incident-response)
    - [Scenario](#scenario-4)
    - [User Actions](#user-actions)
    - [Admin Response](#admin-response)
  - [Multi-Device User Management](#multi-device-user-management)
    - [Scenario](#scenario-5)
    - [Features](#features)

---

## CLI Tool Authentication

### Scenario

You're building a CLI tool (like `gh` or `aws-cli`) that needs to access user resources on your platform.

### Requirements

- Users should authenticate via browser (not enter password in CLI)
- CLI should receive an access token after authorization
- Token should be stored securely for future use
- Automatic token refresh when expired

### Implementation

**1. Server Setup:**

Deploy AuthGate with your OAuth client:

```bash
# .env
BASE_URL=https://auth.yourplatform.com
JWT_SECRET=your-strong-secret
SESSION_SECRET=your-session-secret
```

**2. CLI Implementation:**

```go
package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "time"
)

type TokenStorage struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    ExpiresAt    time.Time `json:"expires_at"`
}

const (
    clientID     = "your-client-id"
    tokenFile    = ".myapp-tokens.json"
    authServer   = "https://auth.yourplatform.com"
)

func main() {
    // Try to load existing tokens
    tokens, err := loadTokens()
    if err != nil || tokens.AccessToken == "" {
        // First time: perform device flow
        tokens, err = performDeviceFlow()
        if err != nil {
            fmt.Println("Authentication failed:", err)
            os.Exit(1)
        }
        saveTokens(tokens)
    }

    // Check if token is expired
    if time.Now().After(tokens.ExpiresAt) {
        fmt.Println("Token expired, refreshing...")
        tokens, err = refreshToken(tokens.RefreshToken)
        if err != nil {
            fmt.Println("Token refresh failed, re-authenticating...")
            tokens, err = performDeviceFlow()
            if err != nil {
                fmt.Println("Authentication failed:", err)
                os.Exit(1)
            }
        }
        saveTokens(tokens)
    }

    // Use the access token
    makeAPICall(tokens.AccessToken)
}

func performDeviceFlow() (*TokenStorage, error) {
    // Step 1: Request device code
    resp, err := http.PostForm(authServer+"/oauth/device/code",
        url.Values{"client_id": {clientID}})
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var deviceCodeResp struct {
        DeviceCode      string `json:"device_code"`
        UserCode        string `json:"user_code"`
        VerificationURI string `json:"verification_uri"`
        Interval        int    `json:"interval"`
        ExpiresIn       int    `json:"expires_in"`
    }
    json.NewDecoder(resp.Body).Decode(&deviceCodeResp)

    // Step 2: Display instructions to user
    fmt.Printf("\n🔐 Authentication Required\n\n")
    fmt.Printf("Visit: %s\n", deviceCodeResp.VerificationURI)
    fmt.Printf("Enter code: %s\n\n", deviceCodeResp.UserCode)
    fmt.Println("Waiting for authorization...")

    // Step 3: Poll for token
    ticker := time.NewTicker(time.Duration(deviceCodeResp.Interval) * time.Second)
    defer ticker.Stop()

    timeout := time.After(time.Duration(deviceCodeResp.ExpiresIn) * time.Second)

    for {
        select {
        case <-ticker.C:
            resp, err := http.PostForm(authServer+"/oauth/token", url.Values{
                "grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
                "device_code": {deviceCodeResp.DeviceCode},
                "client_id":   {clientID},
            })
            if err != nil {
                continue
            }
            defer resp.Body.Close()

            body, _ := ioutil.ReadAll(resp.Body)

            var tokenResp struct {
                AccessToken  string `json:"access_token"`
                RefreshToken string `json:"refresh_token"`
                ExpiresIn    int    `json:"expires_in"`
                Error        string `json:"error"`
            }
            json.Unmarshal(body, &tokenResp)

            if tokenResp.Error == "authorization_pending" {
                continue
            }

            if tokenResp.AccessToken != "" {
                fmt.Println("✅ Authentication successful!")
                return &TokenStorage{
                    AccessToken:  tokenResp.AccessToken,
                    RefreshToken: tokenResp.RefreshToken,
                    ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
                }, nil
            }

            return nil, fmt.Errorf("authentication failed: %s", tokenResp.Error)

        case <-timeout:
            return nil, fmt.Errorf("authentication timeout")
        }
    }
}

func refreshToken(refreshToken string) (*TokenStorage, error) {
    resp, err := http.PostForm(authServer+"/oauth/token", url.Values{
        "grant_type":    {"refresh_token"},
        "refresh_token": {refreshToken},
        "client_id":     {clientID},
    })
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var tokenResp struct {
        AccessToken  string `json:"access_token"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
    }
    json.NewDecoder(resp.Body).Decode(&tokenResp)

    return &TokenStorage{
        AccessToken:  tokenResp.AccessToken,
        RefreshToken: tokenResp.RefreshToken,
        ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
    }, nil
}

func loadTokens() (*TokenStorage, error) {
    data, err := ioutil.ReadFile(tokenFile)
    if err != nil {
        return nil, err
    }
    var tokens TokenStorage
    err = json.Unmarshal(data, &tokens)
    return &tokens, err
}

func saveTokens(tokens *TokenStorage) error {
    data, err := json.Marshal(tokens)
    if err != nil {
        return err
    }
    return ioutil.WriteFile(tokenFile, data, 0600) // Secure permissions
}

func makeAPICall(accessToken string) {
    req, _ := http.NewRequest("GET", "https://api.yourplatform.com/user/profile", nil)
    req.Header.Set("Authorization", "Bearer "+accessToken)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        fmt.Println("API call failed:", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusUnauthorized {
        fmt.Println("Token invalid, need to re-authenticate")
        os.Remove(tokenFile)
        os.Exit(1)
    }

    // Process response...
    fmt.Println("API call successful!")
}
```

**3. User Experience:**

```bash
$ myapp-cli deploy

🔐 Authentication Required

Visit: https://auth.yourplatform.com/device
Enter code: ABCD-1234

Waiting for authorization...
✅ Authentication successful!

Deploying application...
```

---

## IoT Device Authentication

### Scenario

You're building a smart home device (security camera, thermostat) that needs user authorization to access cloud services.

### Requirements

- Device has no keyboard or browser
- Device displays code on screen/LCD
- User authorizes via mobile app or browser
- Token stored in device memory
- Automatic token refresh

### Implementation

**1. Device Code (Python):**

```python
import requests
import time
import json
from pathlib import Path

CLIENT_ID = "iot-device-client-id"
AUTH_SERVER = "https://auth.yourplatform.com"
TOKEN_FILE = "/etc/mydevice/token.json"

def device_login():
    # Request device code
    response = requests.post(f"{AUTH_SERVER}/oauth/device/code", data={
        "client_id": CLIENT_ID
    })
    data = response.json()

    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]
    interval = data["interval"]
    expires_in = data["expires_in"]

    # Display on device screen
    print(f"Go to: {verification_uri}")
    print(f"Code: {user_code}")

    # Or show QR code
    qr_url = f"{verification_uri}?user_code={user_code}"
    display_qr_code(qr_url)

    # Poll for token
    start_time = time.time()
    while time.time() - start_time < expires_in:
        time.sleep(interval)

        response = requests.post(f"{AUTH_SERVER}/oauth/token", data={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": CLIENT_ID
        })

        token_data = response.json()

        if "error" in token_data:
            if token_data["error"] == "authorization_pending":
                continue
            else:
                raise Exception(f"Authorization failed: {token_data['error']}")

        # Save tokens securely
        save_tokens(token_data)
        return token_data

    raise Exception("Authorization timeout")

def save_tokens(token_data):
    with open(TOKEN_FILE, 'w') as f:
        json.dump(token_data, f)
    # Set secure permissions
    Path(TOKEN_FILE).chmod(0o600)

def load_tokens():
    try:
        with open(TOKEN_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def refresh_token(refresh_token):
    response = requests.post(f"{AUTH_SERVER}/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID
    })
    return response.json()

def display_qr_code(url):
    # Generate and display QR code on device screen
    import qrcode
    qr = qrcode.QRCode()
    qr.add_data(url)
    qr.make()
    # Display on device LCD/OLED
    # ...

def main():
    tokens = load_tokens()

    if tokens is None:
        print("First time setup, authenticating...")
        tokens = device_login()

    # Check if token expired
    if is_token_expired(tokens):
        print("Refreshing token...")
        tokens = refresh_token(tokens["refresh_token"])
        save_tokens(tokens)

    # Use access token to access cloud services
    access_token = tokens["access_token"]
    # ... device operations

if __name__ == "__main__":
    main()
```

**2. User Experience:**

Device LCD shows:

```
╔═══════════════════╗
║ Setup Required    ║
║                   ║
║ Visit:            ║
║ auth.app.com      ║
║                   ║
║ Code: WXYZ-5678   ║
║                   ║
║ [QR Code]         ║
╚═══════════════════╝
```

User scans QR code or visits URL on phone, enters code, device activates.

---

## CI/CD Pipeline Authentication

### Scenario

Your CI/CD pipeline needs to deploy applications to your platform on behalf of developers.

### Requirements

- Pipeline runs in headless environment
- Authenticate on behalf of repository owner
- Use long-lived refresh tokens
- Revoke access when developer leaves team

### Implementation

**1. One-Time Setup (Developer's Machine):**

```bash
#!/bin/bash
# setup-ci-token.sh

CLIENT_ID="cicd-client-id"
AUTH_SERVER="https://auth.yourplatform.com"

# Perform device flow
response=$(curl -s -X POST "$AUTH_SERVER/oauth/device/code" \
  -d "client_id=$CLIENT_ID")

device_code=$(echo $response | jq -r '.device_code')
user_code=$(echo $response | jq -r '.user_code')
verification_uri=$(echo $response | jq -r '.verification_uri')
interval=$(echo $response | jq -r '.interval')

echo "Visit: $verification_uri"
echo "Enter code: $user_code"
echo ""
echo "Waiting for authorization..."

# Poll for token
while true; do
  sleep $interval

  token_response=$(curl -s -X POST "$AUTH_SERVER/oauth/token" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "device_code=$device_code" \
    -d "client_id=$CLIENT_ID")

  error=$(echo $token_response | jq -r '.error // empty')

  if [ "$error" = "authorization_pending" ]; then
    continue
  elif [ -z "$error" ]; then
    # Success
    refresh_token=$(echo $token_response | jq -r '.refresh_token')
    echo ""
    echo "✅ Authentication successful!"
    echo ""
    echo "Add this secret to your CI/CD environment:"
    echo "PLATFORM_REFRESH_TOKEN=$refresh_token"
    break
  else
    echo "Error: $error"
    exit 1
  fi
done
```

**2. CI/CD Pipeline (.github/workflows/deploy.yml):**

```yaml
name: Deploy to Platform

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Get Access Token
        id: auth
        run: |
          response=$(curl -s -X POST https://auth.yourplatform.com/oauth/token \
            -d "grant_type=refresh_token" \
            -d "refresh_token=${{ secrets.PLATFORM_REFRESH_TOKEN }}" \
            -d "client_id=cicd-client-id")

          access_token=$(echo $response | jq -r '.access_token')
          echo "::add-mask::$access_token"
          echo "access_token=$access_token" >> $GITHUB_OUTPUT

      - name: Deploy Application
        run: |
          curl -X POST https://api.yourplatform.com/deploy \
            -H "Authorization: Bearer ${{ steps.auth.outputs.access_token }}" \
            -H "Content-Type: application/json" \
            -d '{"repository":"${{ github.repository }}"}'
```

**3. Token Management:**

When developer leaves team, revoke their CI/CD token via web UI:

```bash
# Admin logs in and revokes token
curl -X POST https://auth.yourplatform.com/account/sessions/revoke-all \
  -H "Cookie: admin-session=..."
```

---

## Smart TV Authentication

### Scenario

Building a streaming app for Smart TVs where users need to login to access their account.

### Requirements

- Display code on TV screen
- User enters code on mobile/web
- Seamless experience across devices
- Remember device for 30 days

### Implementation

**TV App (React Native for TV):**

```javascript
import React, { useState, useEffect } from "react";

const AUTH_SERVER = "https://auth.streamingapp.com";
const CLIENT_ID = "smart-tv-client";

function LoginScreen() {
  const [userCode, setUserCode] = useState("");
  const [verificationUri, setVerificationUri] = useState("");
  const [status, setStatus] = useState("loading");

  useEffect(() => {
    initiateDeviceFlow();
  }, []);

  async function initiateDeviceFlow() {
    // Request device code
    const response = await fetch(`${AUTH_SERVER}/oauth/device/code`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_id: CLIENT_ID }),
    });

    const data = await response.json();
    setUserCode(data.user_code);
    setVerificationUri(data.verification_uri);
    setStatus("waiting");

    // Start polling
    pollForToken(data.device_code, data.interval);
  }

  async function pollForToken(deviceCode, interval) {
    const pollInterval = setInterval(async () => {
      const response = await fetch(`${AUTH_SERVER}/oauth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
          client_id: CLIENT_ID,
        }),
      });

      const data = await response.json();

      if (data.error === "authorization_pending") {
        return; // Keep polling
      }

      clearInterval(pollInterval);

      if (data.access_token) {
        // Save tokens securely
        await saveTokens(data);
        setStatus("success");
        // Navigate to home screen
      } else {
        setStatus("error");
      }
    }, interval * 1000);
  }

  return (
    <View style={styles.container}>
      {status === "waiting" && (
        <>
          <Text style={styles.title}>Sign In</Text>
          <Text style={styles.instructions}>
            On your phone or computer, visit:
          </Text>
          <Text style={styles.url}>{verificationUri}</Text>
          <Text style={styles.instructions}>And enter this code:</Text>
          <Text style={styles.code}>{userCode}</Text>
          <QRCode value={`${verificationUri}?code=${userCode}`} />
          <ActivityIndicator />
        </>
      )}
      {status === "success" && (
        <Text style={styles.success}>✅ Sign in successful!</Text>
      )}
    </View>
  );
}
```

---

## Security Incident Response

### Scenario

A user suspects unauthorized access to their account and wants to revoke all device access.

### User Actions

**1. User logs into web UI:**

```
https://auth.yourplatform.com/login
```

**2. Navigate to Sessions:**

```
https://auth.yourplatform.com/account/sessions
```

**3. Review Active Devices:**

User sees list of authorized devices:

- iPhone (iOS App) - Authorized 2 days ago
- Chrome on Windows - Authorized 5 hours ago ⚠️ Suspicious
- CLI Tool - Authorized 1 month ago

**4. Revoke Specific Device:**

Click "Revoke" next to suspicious device.

**5. Or Revoke All Devices:**

Click "Revoke All" button to sign out all devices immediately.

**6. Re-authorize Legitimate Devices:**

Legitimate devices will prompt for re-authentication on next use.

### Admin Response

```bash
# Admin can also revoke all tokens for a user
sqlite3 oauth.db "UPDATE access_tokens SET status='revoked' WHERE user_id='user-uuid';"

# Check audit logs for suspicious activity
curl "https://auth.yourplatform.com/admin/audit/api?user_id=user-uuid&since=7d" \
  -H "Cookie: admin-session=..."
```

---

## Multi-Device User Management

### Scenario

A user has multiple devices (phone, laptop, tablet, TV) and wants to manage access from a central location.

### Features

**1. View All Active Sessions:**

Web UI at `/account/sessions` shows:

| Device      | Client          | Authorized  | Last Used  | Status | Actions |
| ----------- | --------------- | ----------- | ---------- | ------ | ------- |
| iPhone 12   | iOS App         | 2 days ago  | 2 min ago  | Active | Revoke  |
| MacBook Pro | Desktop App     | 1 week ago  | 1 hour ago | Active | Revoke  |
| iPad        | iOS App         | 3 days ago  | Never      | Active | Revoke  |
| Smart TV    | TV App          | 1 month ago | 2 days ago | Active | Revoke  |
| CLI Tool    | Developer Tools | 2 weeks ago | 5 min ago  | Active | Revoke  |

**2. Selective Revocation:**

User can revoke specific device without affecting others (thanks to fixed refresh token mode).

**3. Bulk Actions:**

- "Revoke All" - Sign out all devices (security incident)
- "Revoke Inactive" - Remove devices not used in 30+ days

**4. Device Identification:**

Show helpful information:

- Client name ("iOS App", "Desktop App")
- Authorization timestamp
- Last used timestamp
- IP address (privacy-sensitive)
- User-agent (if available)

---

**Next Steps:**

- [Development Guide](DEVELOPMENT.md) - Build your own integration
- [API Reference (README)](../README.md#key-endpoints) - Endpoint documentation
- [Example CLI](../_example/authgate-cli/) - Working reference implementation
