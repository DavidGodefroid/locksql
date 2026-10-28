//go:build !unix && !windows

package proxycmd

import "os/exec"

// start starts cmd; kill ends it.
func start(cmd *exec.Cmd) (kill func(), err error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() { cmd.Process.Kill() }, nil
}
