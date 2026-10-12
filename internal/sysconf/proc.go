package sysconf

// Proc is one ancestor of the current process.
type Proc struct {
	PID, UID int
	Comm     string
}

// CommLen is the length of a process name as the kernel keeps it
// (TASK_COMM_LEN - 1): /proc/<pid>/status shows longer names truncated.
const CommLen = 15

// DesktopEmulators are the terminal emulators `locksql window` starts;
// the console accepts desktop mode only below one of them, owned by the
// console account. Their full names: a name longer than CommLen appears in
// Proc.Comm truncated ("gnome-terminal-"), and matches by its prefix.
var DesktopEmulators = []string{"foot", "gnome-terminal-server"}
