package store

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DriverFactory is a function that creates a gorm.Dialector
type DriverFactory func(dsn string) gorm.Dialector

// driverFactories maps driver names to their factory functions
var driverFactories = map[string]DriverFactory{
	"sqlite":   sqlite.Open,
	"postgres": postgres.Open,
}

// GetDialector returns a GORM dialector for the given driver name and DSN
func GetDialector(driver, dsn string) (gorm.Dialector, error) {
	factory, exists := driverFactories[driver]
	if !exists {
		return nil, fmt.Errorf("unsupported database driver: %s", driver)
	}
	return factory(dsn), nil
}

// RegisterDriver allows registering custom database drivers
func RegisterDriver(name string, factory DriverFactory) {
	driverFactories[name] = factory
}
