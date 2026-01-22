package main

import (
	"fmt"
	"os"
	"time"
)

// fileLock represents a file lock
type fileLock struct {
	lockFile *os.File
	lockPath string
}

// acquireFileLock acquires an exclusive lock on the token file
// Uses a separate lock file to coordinate access across processes
func acquireFileLock(filePath string) (*fileLock, error) {
	lockPath := filePath + ".lock"
	maxRetries := 50
	retryDelay := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		// Try to create lock file exclusively (fails if already exists)
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			// Successfully acquired lock
			// Write PID to lock file for debugging
			fmt.Fprintf(lockFile, "%d", os.Getpid())
			return &fileLock{
				lockFile: lockFile,
				lockPath: lockPath,
			}, nil
		}

		// Lock already exists, check if it's stale
		if os.IsExist(err) {
			// Check if lock file is older than 30 seconds (stale lock)
			if info, statErr := os.Stat(lockPath); statErr == nil {
				age := time.Since(info.ModTime())
				if age > 30*time.Second {
					// Stale lock, try to remove it; handle races and real errors
					if remErr := os.Remove(lockPath); remErr != nil && !os.IsNotExist(remErr) {
						return nil, fmt.Errorf("failed to remove stale lock file %s: %w", lockPath, remErr)
					}
					continue
				}
			}

			// Lock is held by another process, wait and retry
			time.Sleep(retryDelay)
			continue
		}

		// Other error
		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return nil, fmt.Errorf("timeout waiting for file lock after %v", time.Duration(maxRetries)*retryDelay)
}

// release releases the file lock
func (fl *fileLock) release() error {
	if fl.lockFile != nil {
		fl.lockFile.Close()
	}
	return os.Remove(fl.lockPath)
}
