//go:build unix

package main

import (
	"flag"
	"slices"
	"testing"

	kconsole "github.com/DavidGodefroid/lockkit/console"
)

// The handoff passes every hub flag on (HubOptions.Args): the facade keys
// of a reveal and the approval devices reach the console account, and the
// command line parses back to the same hub options.
func TestHandoffForwardsFacadeKeys(t *testing.T) {
	hub := kconsole.HubOptions{URL: "https://hub.example", KeyFile: "/k/hub.pub", Instance: "sql-1",
		FacadeKeysFile: "/k/facades.json", DevicesFile: "/k/devices.json", RequireDevice: "prod-write", SealClear: true}
	argv := consoleArgs{project: "/p", hub: hub}.argv()
	if !slices.Contains(argv, "--facade-keys-file") {
		t.Fatalf("argv %q", argv)
	}
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.String("project", "", "")
	var back kconsole.HubOptions
	back.Register(fs)
	if err := fs.Parse(argv[1:]); err != nil {
		t.Fatal(err)
	}
	if back != hub {
		t.Fatalf("parsed back %+v, want %+v", back, hub)
	}
}
