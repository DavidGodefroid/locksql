//go:build windows

package proxycmd

import (
	"os/exec"
	"syscall"
)

// detachedProcess starts a console program without a console: it cannot
// read the console's input or prompt there.
const detachedProcess = 0x00000008

// detach runs cmd without the console's console, in a process group of
// its own.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | syscall.CREATE_NEW_PROCESS_GROUP}
}

// kill ends the command.
func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
