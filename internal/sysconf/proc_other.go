//go:build !linux

package sysconf

// ParentChain is not implemented outside Linux: it returns no ancestor,
// which desktop mode refuses.
func ParentChain() ([]Proc, error) { return nil, nil }
