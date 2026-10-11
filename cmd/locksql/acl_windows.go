package main

// readACL returns nil: Windows has no POSIX ACLs, and every command but
// version and help refuses to run there.
func readACL(string) []byte { return nil }
