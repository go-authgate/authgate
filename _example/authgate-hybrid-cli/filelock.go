package main

import (
	"fmt"
	"os"
	"time"
)

// fileLock represents a file lock.
type fileLock struct {
	lockFile *os.File
	lockPath string
}

// acquireFileLock acquires an exclusive lock on the token file.
// Uses a separate lock file to coordinate access across processes.
func acquireFileLock(filePath string) (*fileLock, error) {
	lockPath := filePath + ".lock"
	maxRetries := 50
	retryDelay := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(lockFile, "%d", os.Getpid())
			return &fileLock{
				lockFile: lockFile,
				lockPath: lockPath,
			}, nil
		}

		if os.IsExist(err) {
			if info, statErr := os.Stat(lockPath); statErr == nil {
				if time.Since(info.ModTime()) > 30*time.Second {
					if remErr := os.Remove(lockPath); remErr != nil && !os.IsNotExist(remErr) {
						return nil, fmt.Errorf(
							"failed to remove stale lock file %s: %w",
							lockPath,
							remErr,
						)
					}
					continue
				}
			}
			time.Sleep(retryDelay)
			continue
		}

		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return nil, fmt.Errorf(
		"timeout waiting for file lock after %v",
		time.Duration(maxRetries)*retryDelay,
	)
}

// release releases the file lock.
func (fl *fileLock) release() error {
	if fl.lockFile != nil {
		fl.lockFile.Close()
	}
	return os.Remove(fl.lockPath)
}
