package bootstrap

import (
	"context"
	"fmt"
	"time"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/store"
)

// initializeDatabase creates and initializes the database connection
func initializeDatabase(cfg *config.Config) (*store.Store, error) {
	// Use a context with timeout for database initialization
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseDriver, cfg.DatabaseDSN, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return db, nil
}
