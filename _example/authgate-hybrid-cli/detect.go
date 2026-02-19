package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

// BrowserAvailability holds the result of checking whether a browser can be opened.
type BrowserAvailability struct {
	Available bool
	Reason    string // non-empty when Available is false, for logging/debugging
}

// checkBrowserAvailability determines whether a browser can be opened in the
// current environment. It uses a two-stage check:
//
//  1. Environment signals: SSH sessions without display forwarding, Linux
//     hosts with no display server.
//  2. Callback port availability: the local redirect server must be bindable.
//
// This function never attempts to open a browser itself; it only inspects
// the environment. Callers that pass the check should still handle
// openBrowser() failures as a secondary fallback.
func checkBrowserAvailability(port int) BrowserAvailability {
	// Stage 1a: SSH without X11/Wayland forwarding.
	// SSH_TTY / SSH_CLIENT / SSH_CONNECTION indicate a remote shell.
	// If a display is also present (X11 forwarding), the browser can still open.
	inSSH := os.Getenv("SSH_TTY") != "" ||
		os.Getenv("SSH_CLIENT") != "" ||
		os.Getenv("SSH_CONNECTION") != ""

	hasDisplay := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""

	if inSSH && !hasDisplay {
		return BrowserAvailability{false, "SSH session without display forwarding"}
	}

	// Stage 1b: Linux with no display server at all (headless / Docker / CI).
	if runtime.GOOS == "linux" && !hasDisplay {
		return BrowserAvailability{false, "no display server (DISPLAY/WAYLAND_DISPLAY not set)"}
	}

	// Stage 2: Verify the callback port can be bound.
	// A busy port means the redirect server cannot start.
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return BrowserAvailability{
			false,
			fmt.Sprintf("callback port %d unavailable: %v", port, err),
		}
	}
	ln.Close()

	return BrowserAvailability{Available: true}
}
