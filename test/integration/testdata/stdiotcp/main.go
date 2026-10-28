// Command stdiotcp relays its stdin and stdout to a TCP address, as nc or
// socat do; the database images ship neither. The integration tests copy
// it into a container and use it as the end of a proxy_command.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: stdiotcp host:port")
		os.Exit(2)
	}
	c, err := net.Dial("tcp", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	go func() {
		io.Copy(c, os.Stdin)
		c.(*net.TCPConn).CloseWrite()
	}()
	io.Copy(os.Stdout, c)
}
