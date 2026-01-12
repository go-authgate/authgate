package store

import (
	"fmt"
	"sync"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DriverFactory is a function that creates a gorm.Dialector
type DriverFactory func(dsn string) gorm.Dialector

var (
	// driverFactories maps driver names to their factory functions
	driverFactories = map[string]DriverFactory{
		"sqlite":   sqlite.Open,
		"postgres": postgres.Open,
	}
	// driverMu protects concurrent access to driverFactories
	driverMu sync.RWMutex
)

// GetDialector returns a GORM dialector for the given driver name and DSN
func GetDialector(driver, dsn string) (gorm.Dialector, error) {
	driverMu.RLock()
	factory, exists := driverFactories[driver]
	driverMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
	return factory(dsn), nil
}

// RegisterDriver allows registering custom database drivers
func RegisterDriver(name string, factory DriverFactory) {
	driverMu.Lock()
	driverFactories[name] = factory
	driverMu.Unlock()
}
