package main

// readACL returns nil: macOS ACLs are not read (the project access check
// relies on the mode bits there).
func readACL(string) []byte { return nil }
