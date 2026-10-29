//go:build unix

package proxycmd

import (
	"os/exec"
	"syscall"
)

// start runs cmd in a session of its own: it has no controlling terminal,
// so it cannot read the console's terminal or prompt there, and it leads a
// process group that kill ends as a whole, with the processes it started
// (ssh's children, a docker CLI plugin, ...).
func start(cmd *exec.Cmd) (kill func(), err error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid
	return func() { syscall.Kill(-pid, syscall.SIGKILL) }, nil
}
