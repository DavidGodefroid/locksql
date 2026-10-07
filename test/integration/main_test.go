//go:build integration

package integration

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		StopAll()
		os.Exit(1)
	}()
	code := m.Run()
	StopAll()
	os.Exit(code)
}
