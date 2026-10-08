package sysconf

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Display kinds.
const (
	DisplayWayland = "wayland"
	DisplayX11     = "x11"
	DisplayTTY     = "tty"    // no graphical session (a text console or SSH)
	DisplayQuartz  = "quartz" // macOS
	DisplayUnknown = "unknown"
)

// Display is the graphical session a process runs in.
type Display struct {
	Kind string
	// Detail says what the kind was read from.
	Detail string
}

// getenv is os.Getenv; tests replace it.
var getenv = os.Getenv

// DetectDisplay reports the graphical session of the current process. On
// Linux an X11 session (or an X display without Wayland) lets any client
// read the keyboard and the screen of every other client, and send them
// synthetic input; Wayland isolates clients from each other.
func DetectDisplay() Display {
	if runtime.GOOS == "darwin" {
		return Display{Kind: DisplayQuartz, Detail: "macOS"}
	}
	st := strings.ToLower(getenv("XDG_SESSION_TYPE"))
	wl, x := getenv("WAYLAND_DISPLAY"), getenv("DISPLAY")
	switch {
	case st == "x11":
		return Display{Kind: DisplayX11, Detail: "XDG_SESSION_TYPE=x11"}
	case st == "wayland" || wl != "":
		if x != "" && wl == "" {
			return Display{Kind: DisplayX11, Detail: "DISPLAY set without WAYLAND_DISPLAY"}
		}
		return Display{Kind: DisplayWayland, Detail: "Wayland session"}
	case x != "":
		return Display{Kind: DisplayX11, Detail: "DISPLAY=" + x}
	case st == "tty" || getenv("SSH_TTY") != "" || st == "":
		return Display{Kind: DisplayTTY, Detail: "no graphical session"}
	}
	return Display{Kind: DisplayUnknown, Detail: "XDG_SESSION_TYPE=" + st}
}

// procRoot is /proc; tests replace it.
var procRoot = "/proc"

// LoginUID returns the account that opened the login session of the
// process (Linux audit loginuid), which sudo and su do not change. A
// console running as locksql whose loginuid is another account was started
// from that account's session: it shares its terminal and display.
func LoginUID() (int, bool) {
	return readInt(procRoot + "/self/loginuid")
}

// LegacyTIOCSTI reports whether the kernel still lets a process push
// characters into the input of a terminal it can open (TIOCSTI). It is off
// by default since Linux 6.2 (dev.tty.legacy_tiocsti = 0).
func LegacyTIOCSTI() (on, known bool) {
	n, ok := readInt(procRoot + "/sys/dev/tty/legacy_tiocsti")
	return n != 0, ok
}

// PtraceScope is the Yama ptrace scope (0: any process of the same user
// may attach to another), when the kernel has Yama.
func PtraceScope() (int, bool) {
	return readInt(procRoot + "/sys/kernel/yama/ptrace_scope")
}

func readInt(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v := strings.TrimSpace(string(b))
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, false
	}
	if n == 4294967295 { // (uid_t)-1: no login uid
		return -1, true
	}
	return int(n), true
}
