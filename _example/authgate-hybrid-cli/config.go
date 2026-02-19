package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	retry "github.com/appleboy/go-httpretry"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

var (
	serverURL         string
	clientID          string
	clientSecret      string
	redirectURI       string
	callbackPort      int
	scope             string
	tokenFile         string
	forceDevice       bool
	configInitialized bool
	retryClient       *retry.Client

	flagServerURL    *string
	flagClientID     *string
	flagClientSecret *string
	flagRedirectURI  *string
	flagCallbackPort *int
	flagScope        *string
	flagTokenFile    *string
	flagDevice       *bool
	flagNoBrowser    *bool
)

const (
	tokenExchangeTimeout     = 10 * time.Second
	tokenVerificationTimeout = 10 * time.Second
	refreshTokenTimeout      = 10 * time.Second
	deviceCodeRequestTimeout = 10 * time.Second
)

func init() {
	_ = godotenv.Load()

	flagServerURL = flag.String(
		"server-url",
		"",
		"OAuth server URL (default: http://localhost:8080 or SERVER_URL env)",
	)
	flagClientID = flag.String("client-id", "", "OAuth client ID (required, or set CLIENT_ID env)")
	flagClientSecret = flag.String(
		"client-secret",
		"",
		"OAuth client secret (confidential clients only; omit for public/PKCE clients)",
	)
	flagRedirectURI = flag.String(
		"redirect-uri",
		"",
		"Redirect URI registered with the OAuth server (default: http://localhost:PORT/callback)",
	)
	flagCallbackPort = flag.Int(
		"port",
		0,
		"Local callback port for browser flow (default: 8888 or CALLBACK_PORT env)",
	)
	flagScope = flag.String("scope", "", "Space-separated OAuth scopes (default: \"read write\")")
	flagTokenFile = flag.String(
		"token-file",
		"",
		"Token storage file (default: .authgate-tokens.json or TOKEN_FILE env)",
	)
	flagDevice = flag.Bool(
		"device",
		false,
		"Force Device Code Flow (skip browser detection)",
	)
	flagNoBrowser = flag.Bool(
		"no-browser",
		false,
		"Alias for --device: skip browser and use Device Code Flow",
	)
}

func initConfig() {
	if configInitialized {
		return
	}
	configInitialized = true

	flag.Parse()

	// --device or --no-browser forces Device Code Flow unconditionally.
	forceDevice = *flagDevice || *flagNoBrowser

	serverURL = getConfig(*flagServerURL, "SERVER_URL", "http://localhost:8080")
	clientID = getConfig(*flagClientID, "CLIENT_ID", "")
	clientSecret = getConfig(*flagClientSecret, "CLIENT_SECRET", "")
	scope = getConfig(*flagScope, "SCOPE", "read write")
	tokenFile = getConfig(*flagTokenFile, "TOKEN_FILE", ".authgate-tokens.json")

	// Resolve callback port (int flag needs special handling).
	portStr := ""
	if *flagCallbackPort != 0 {
		portStr = fmt.Sprintf("%d", *flagCallbackPort)
	}
	portStr = getConfig(portStr, "CALLBACK_PORT", "8888")
	if _, err := fmt.Sscanf(portStr, "%d", &callbackPort); err != nil || callbackPort <= 0 {
		callbackPort = 8888
	}

	// Resolve redirect URI (depends on port, so compute after port is known).
	defaultRedirectURI := fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	redirectURI = getConfig(*flagRedirectURI, "REDIRECT_URI", defaultRedirectURI)

	if err := validateServerURL(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid SERVER_URL: %v\n", err)
		os.Exit(1)
	}

	if strings.HasPrefix(strings.ToLower(serverURL), "http://") {
		fmt.Fprintln(
			os.Stderr,
			"WARNING: Using HTTP instead of HTTPS. Tokens will be transmitted in plaintext!",
		)
		fmt.Fprintln(
			os.Stderr,
			"WARNING: This is only safe for local development. Use HTTPS in production.",
		)
		fmt.Fprintln(os.Stderr)
	}

	if clientID == "" {
		fmt.Println("Error: CLIENT_ID not set. Please provide it via:")
		fmt.Println("  1. Command-line flag: -client-id=<your-client-id>")
		fmt.Println("  2. Environment variable: CLIENT_ID=<your-client-id>")
		fmt.Println("  3. .env file: CLIENT_ID=<your-client-id>")
		fmt.Println("\nYou can find the client_id in the server startup logs.")
		os.Exit(1)
	}

	if _, err := uuid.Parse(clientID); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"WARNING: CLIENT_ID doesn't appear to be a valid UUID: %s\n",
			clientID,
		)
		fmt.Fprintln(os.Stderr)
	}

	baseHTTPClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	var err error
	retryClient, err = retry.NewBackgroundClient(retry.WithHTTPClient(baseHTTPClient))
	if err != nil {
		panic(fmt.Sprintf("failed to create retry client: %v", err))
	}
}

func getConfig(flagValue, envKey, defaultValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return getEnv(envKey, defaultValue)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func validateServerURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("server URL cannot be empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https, got: %s", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}

// isPublicClient returns true when no client secret is configured —
// i.e., this is a public client that must use PKCE.
func isPublicClient() bool {
	return clientSecret == ""
}
