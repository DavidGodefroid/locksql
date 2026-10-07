//go:build !windows

package client

func refusedOS(error) bool { return false }
