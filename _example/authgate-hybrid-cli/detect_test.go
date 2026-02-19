package main

import (
	"net"
	"testing"
)

func TestCheckBrowserAvailability_SSH_NoDisplay(t *testing.T) {
	t.Setenv("SSH_TTY", "/dev/pts/0")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(18888)

	if avail.Available {
		t.Error("expected browser unavailable in SSH session without display")
	}
	if avail.Reason == "" {
		t.Error("expected non-empty reason when browser is unavailable")
	}
}

func TestCheckBrowserAvailability_SSHClient_NoDisplay(t *testing.T) {
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "192.168.1.1 12345 22")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(18888)

	if avail.Available {
		t.Error("expected browser unavailable when SSH_CLIENT set and no display")
	}
}

func TestCheckBrowserAvailability_SSHConnection_NoDisplay(t *testing.T) {
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "192.168.1.1 12345 192.168.1.2 22")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(18888)

	if avail.Available {
		t.Error("expected browser unavailable when SSH_CONNECTION set and no display")
	}
}

func TestCheckBrowserAvailability_SSH_WithX11(t *testing.T) {
	// SSH with X11 forwarding: SSH_TTY is set but DISPLAY is also set.
	t.Setenv("SSH_TTY", "/dev/pts/0")
	t.Setenv("DISPLAY", ":10.0")
	t.Setenv("WAYLAND_DISPLAY", "")

	// Use a port that is definitely free (bind to :0 and get the port,
	// then close it; the brief gap is acceptable for a unit test).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot allocate test port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	avail := checkBrowserAvailability(port)

	// X11 forwarding over SSH should be detected as browser-capable
	// (DISPLAY is set, port is free).
	if !avail.Available {
		t.Errorf("expected browser available with SSH+X11 forwarding, got reason: %s", avail.Reason)
	}
}

func TestCheckBrowserAvailability_PortUnavailable(t *testing.T) {
	// Bind a port and keep it busy during the test.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot bind test port")
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Clear SSH vars so we reach the port-check stage.
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")
	// Pretend we have a display so the display check is bypassed.
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(port)

	if avail.Available {
		t.Errorf("expected browser unavailable when port %d is busy", port)
	}
	if avail.Reason == "" {
		t.Error("expected non-empty reason for busy port")
	}
}

func TestCheckBrowserAvailability_PortAvailable(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot allocate test port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(port)

	if !avail.Available {
		t.Errorf(
			"expected browser available with no SSH and free port, got reason: %s",
			avail.Reason,
		)
	}
}

func TestCheckBrowserAvailability_ReasonIsEmptyWhenAvailable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot allocate test port")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")

	avail := checkBrowserAvailability(port)

	if avail.Available && avail.Reason != "" {
		t.Errorf("expected empty reason when browser is available, got: %s", avail.Reason)
	}
}
