package console

import "os"

// cbreak refuses on Windows: the console needs a Unix terminal.
func cbreak(int) (func(), error) { return nil, errNoTerminal }

// notifyResize delivers nothing on Windows.
func notifyResize(chan<- os.Signal) func() { return func() {} }
