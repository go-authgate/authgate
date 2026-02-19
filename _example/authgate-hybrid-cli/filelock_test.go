package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")

	lock, err := acquireFileLock(target)
	if err != nil {
		t.Fatalf("acquireFileLock() error: %v", err)
	}

	lockPath := target + ".lock"
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file was not created")
	}

	if err := lock.release(); err != nil {
		t.Errorf("release() error: %v", err)
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Error("lock file was not removed after release")
	}
}

func TestConcurrentLocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")

	const goroutines = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrent := 0

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			lock, err := acquireFileLock(target)
			if err != nil {
				t.Errorf("goroutine %d: acquireFileLock() error: %v", idx, err)
				return
			}

			mu.Lock()
			concurrent++
			if concurrent > 1 {
				t.Errorf("goroutine %d: more than one lock holder at a time: %d", idx, concurrent)
			}
			mu.Unlock()

			mu.Lock()
			concurrent--
			mu.Unlock()

			lock.release()
		}(i)
	}

	wg.Wait()
}

func TestStaleLockRemoval(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")
	lockPath := target + ".lock"

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	staleTime := time.Now().Add(-60 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("os.Chtimes: %v", err)
	}

	lock, err := acquireFileLock(target)
	if err != nil {
		t.Fatalf("acquireFileLock() with stale lock: %v", err)
	}
	lock.release()
}
