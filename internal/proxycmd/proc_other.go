//go:build !unix && !windows

package proxycmd

import "os/exec"

// detach leaves cmd as it is.
func detach(cmd *exec.Cmd) {}

// kill ends the command.
func kill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
