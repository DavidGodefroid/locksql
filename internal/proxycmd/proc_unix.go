//go:build unix

package proxycmd

import (
	"os/exec"
	"syscall"
)

// detach runs cmd in a session of its own: it has no controlling terminal,
// so it cannot read the console's terminal or prompt there, and it leads a
// process group that kill ends as a whole.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// kill ends the command and the processes it started (ssh's children, a
// docker CLI plugin, ...).
func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
