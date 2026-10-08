package sysconf

import (
	"os"
	"syscall"
)

// TerminalOwner returns the owner of the terminal device behind f. A login
// session's terminal belongs to the account that opened it: a console run
// through sudo or su in someone else's terminal finds that account here.
func TerminalOwner(f *os.File) (int, bool) {
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
