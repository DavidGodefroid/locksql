package main

import "runtime"

// hostOS is the platform locksql runs on (a variable for the tests).
var hostOS = runtime.GOOS

// windowsRefusal is printed for every command but version and help on
// Windows. The module builds there so that its CI runs the unit tests, but
// the console's separation from the agent relies on Unix accounts, socket
// peer credentials and terminals, which a native Windows build does not
// have: locksql runs in Docker instead.
const windowsRefusal = "locksql: native Windows is not supported: locksql runs in Docker; " +
	"install the locksql launcher in WSL 2 with Docker Desktop (scripts/install.sh) and run it there; " +
	"see docs/docker.md"

// hostModeRefusal is printed for the commands of the former host install
// (install, update, setup). locksql runs in Docker: the launcher on the
// host runs every command in the image and updates itself and the image.
// The host install code stays until a later release removes it.
func hostModeRefusal(cmd string) string {
	return "locksql " + cmd + ": the host install is gone: locksql runs in Docker. " +
		"Install the launcher with scripts/install.sh; `locksql update` on the host updates it and its image; " +
		"see docs/docker.md"
}

// platformAllows reports whether cmd may run on this platform.
func platformAllows(cmd string) bool {
	if hostOS != "windows" {
		return true
	}
	switch cmd {
	case "version", "--version", "help", "-h", "--help":
		return true
	}
	return false
}
