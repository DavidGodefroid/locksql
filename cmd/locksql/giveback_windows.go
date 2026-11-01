package main

import "errors"

// giveBack is not supported on Windows, where every command but the agent
// side refuses to run.
func giveBack(string, int, int, int) error {
	return errors.New("not supported on Windows")
}
