package main

import "runtime"

// hostOS is the platform locksql runs on (a variable for the tests).
var hostOS = runtime.GOOS

// windowsRefusal is printed for every command but version and help on
// Windows. The module builds there so that its CI runs the unit tests, but
// the console's separation from the agent relies on Unix accounts, socket
// peer credentials and terminals, which a native Windows build does not
// have: locksql runs inside WSL2 instead.
const windowsRefusal = "locksql: native Windows is not supported: run locksql inside WSL2 " +
	"(console and agent in WSL, or a Windows agent launching `wsl locksql mcp`); " +
	"see docs/usage.md, section Windows (WSL2)"

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
