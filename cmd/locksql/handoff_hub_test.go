//go:build unix

package main

import (
	"flag"
	"path/filepath"
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

// Relative hub files are the agent's, from its working directory: the
// console account gets them absolute.
func TestHandoffHubFilesAbsolute(t *testing.T) {
	cwd := t.TempDir()
	hub := kconsole.HubOptions{KeyFile: "hub.pub", FacadeKeysFile: "k/facades.json", DevicesFile: "/abs/devices.json"}
	absHubFiles(cwd, &hub)
	if hub.KeyFile != filepath.Join(cwd, "hub.pub") || hub.FacadeKeysFile != filepath.Join(cwd, "k/facades.json") || hub.DevicesFile != "/abs/devices.json" {
		t.Fatalf("%+v", hub)
	}
}
