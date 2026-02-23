package bootstrap

import (
	"context"
	"fmt"

	"github.com/go-authgate/authgate/internal/config"
	"github.com/go-authgate/authgate/internal/store"
)

// initializeDatabase creates and initializes the database connection
func initializeDatabase(ctx context.Context, cfg *config.Config) (*store.Store, error) {
	// Create timeout context for this specific operation
	ctx, cancel := context.WithTimeout(ctx, cfg.DBInitTimeout)
	defer cancel()

	db, err := store.New(ctx, cfg.DatabaseDriver, cfg.DatabaseDSN, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return db, nil
}
