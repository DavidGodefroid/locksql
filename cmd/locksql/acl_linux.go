package main

import "syscall"

// readACL returns the POSIX access ACL of path (system.posix_acl_access),
// or nil.
func readACL(path string) []byte {
	buf := make([]byte, 4096)
	n, err := syscall.Getxattr(path, "system.posix_acl_access", buf)
	if err != nil || n <= 0 {
		return nil
	}
	return buf[:n]
}
