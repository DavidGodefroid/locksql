package pii

import (
	kpii "github.com/DavidGodefroid/lockkit/pii"
)

// The detectors, mask modes and name heuristics come from lockkit's pii
// package, under their locksql names.

// Detector finds and masks one kind of personal value in a text.
type Detector = kpii.Detector

// Detectors returns the named detectors, de-duplicated, in a fixed order.
func Detectors(names []string) ([]Detector, error) { return kpii.Detectors(names) }

// Mask modes.
const (
	ModeRedact  = kpii.ModeRedact
	ModePartial = kpii.ModePartial
	ModeEmail   = kpii.ModeEmail
)

// ValidMode reports whether m is a mask mode.
func ValidMode(m string) bool { return kpii.ValidMode(m) }

// Redacted is the cell of a column masked in mode redact.
const Redacted = kpii.Redacted

// DetectLimit is how much of a text cell the detectors scan.
const DetectLimit = kpii.DetectLimit

// MaskValue masks one non-NULL cell in mode.
func MaskValue(v any, mode string) any { return kpii.MaskValue(v, mode) }

// CellText is the text of a cell value, as compared and substituted.
func CellText(v any) string { return kpii.CellText(v) }

// RedactedRef is a redacted cell that carries a reference to its value,
// which the console alone keeps.
func RedactedRef(name string) string { return kpii.RedactedRef(name) }

// Detects reports whether a detector would mask something in s.
func Detects(s string, ds []Detector) bool { return kpii.Detects(s, ds) }

func detect(v any, ds []Detector) any { return kpii.Detect(v, ds) }
