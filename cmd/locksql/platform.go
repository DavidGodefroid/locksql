package main

import "runtime"

// hostOS is the platform locksql runs on (a variable for the tests).
var hostOS = runtime.GOOS

// windowsRefusal is printed for every command but version and help on
// Windows. The module builds there so that its CI runs the unit tests, but
// the console's separation from the agent relies on Unix accounts, socket
// peer credentials and terminals, which a native Windows build does not
// have: locksql runs in Docker instead.
const windowsRefusal = "locksql: native Windows is not supported: run locksql in Docker " +
	"(Docker Desktop: the console and the agent's MCP server in Linux containers); " +
	"see docs/docker.md"

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
