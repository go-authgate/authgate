package bootstrap

import (
	"fmt"

	"github.com/appleboy/authgate/internal/config"
	"github.com/appleboy/authgate/internal/store"
)

// initializeDatabase creates and initializes the database connection
func initializeDatabase(cfg *config.Config) (*store.Store, error) {
	db, err := store.New(cfg.DatabaseDriver, cfg.DatabaseDSN, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return db, nil
}
