package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openBrowser attempts to open url in the user's default browser.
// Returns an error if launching the browser fails, but callers should
// always print the URL as a fallback regardless of the error.
func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to open browser: %w", err)
	}

	// Detach — we don't wait for the browser to close.
	go func() { _ = cmd.Wait() }()

	return nil
}
