package bootstrap

import (
	"crypto"
	"log"

	"github.com/go-authgate/authgate/internal/auth"
	"github.com/go-authgate/authgate/internal/client"
	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/core"
	"github.com/go-authgate/authgate/internal/token"
)

// initializeHTTPAPIAuthProvider creates HTTP API auth provider when configured.
// Returns core.AuthProvider (not *auth.HTTPAPIAuthProvider) so that the nil
// default case is an untyped nil interface, keeping == nil checks in UserService safe.
func initializeHTTPAPIAuthProvider(cfg *config.Config) core.AuthProvider {
	switch cfg.AuthMode {
	case config.AuthModeHTTPAPI:
		authRetryClient, err := client.CreateRetryClient(client.RetryClientConfig{
			AuthMode:           cfg.HTTPAPIAuthMode,
			AuthSecret:         cfg.HTTPAPIAuthSecret,
			Timeout:            cfg.HTTPAPITimeout,
			InsecureSkipVerify: cfg.HTTPAPIInsecureSkipVerify,
			MaxRetries:         cfg.HTTPAPIMaxRetries,
			RetryDelay:         cfg.HTTPAPIRetryDelay,
			MaxRetryDelay:      cfg.HTTPAPIMaxRetryDelay,
			AuthHeader:         cfg.HTTPAPIAuthHeader,
		})
		if err != nil {
			log.Fatalf("Failed to create HTTP API auth client: %v", err)
		}
		log.Printf("HTTP API authentication enabled: %s", cfg.HTTPAPIURL)
		return auth.NewHTTPAPIAuthProvider(cfg, authRetryClient)
	default:
		return nil
	}
}

// initializeTokenProvider creates a LocalTokenProvider with key loading for asymmetric algorithms.
func initializeTokenProvider(cfg *config.Config) *token.LocalTokenProvider {
	switch cfg.JWTSigningAlgorithm {
	case config.AlgHS256, "":
		log.Printf("Token signing: HS256 (symmetric)")
		p, err := token.NewLocalTokenProvider(cfg)
		if err != nil {
			log.Fatalf("Failed to create token provider: %v", err)
		}
		return p
	case config.AlgRS256, config.AlgES256:
		// handled below
	default:
		log.Fatalf("Unsupported JWT_SIGNING_ALGORITHM: %q", cfg.JWTSigningAlgorithm)
	}

	// Prefer inline PEM over file path so containerized deployments (K8s Secrets,
	// GitHub Actions) can override an image-baked default without rewriting the file.
	var (
		privateKey crypto.Signer
		err        error
	)
	if cfg.JWTPrivateKeyPEM != "" {
		if cfg.JWTPrivateKeyPath != "" {
			log.Printf("Warning: both JWT_PRIVATE_KEY_PEM and JWT_PRIVATE_KEY_PATH are set; using PEM")
		}
		privateKey, err = token.ParseSigningKey([]byte(cfg.JWTPrivateKeyPEM))
		if err != nil {
			log.Fatalf("Failed to parse JWT_PRIVATE_KEY_PEM: %v", err)
		}
	} else {
		privateKey, err = token.LoadSigningKey(cfg.JWTPrivateKeyPath)
		if err != nil {
			log.Fatalf("Failed to load JWT private key from %s: %v", cfg.JWTPrivateKeyPath, err)
		}
	}

	// Derive kid if not explicitly set
	kid := cfg.JWTKeyID
	if kid == "" {
		var err error
		kid, err = token.DeriveKeyID(privateKey.Public())
		if err != nil {
			log.Fatalf("Failed to derive JWT key ID: %v", err)
		}
	}

	log.Printf("Token signing: %s (kid=%s)", cfg.JWTSigningAlgorithm, kid)
	p, err := token.NewLocalTokenProvider(cfg,
		token.WithSigningKey(privateKey, privateKey.Public()),
		token.WithKeyID(kid),
	)
	if err != nil {
		log.Fatalf("Failed to create token provider: %v", err)
	}
	return p
}
