//go:build windows

package console

import (
	"os"

	"golang.org/x/sys/windows"
)

// flushInput discards pending console input (FlushConsoleInputBuffer).
func flushInput(f *os.File) error {
	return windows.FlushConsoleInputBuffer(windows.Handle(f.Fd()))
}

// echoOff turns the console echo off, keeping line input, and returns the
// function that restores the previous mode.
func echoOff(f *os.File) (func(), error) {
	h := windows.Handle(f.Fd())
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	mode := (old &^ windows.ENABLE_ECHO_INPUT) | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, mode); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, old) }, nil
}
