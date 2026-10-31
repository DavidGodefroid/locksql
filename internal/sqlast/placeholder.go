package sqlast

import "strings"

// PlaceholderRefusal is the refusal of a statement holding a placeholder
// ('${name}') or a cell reference ('${rN.R.C}'). Neither is supported:
// requests are decided in lockhub, where no value is typed, and masked
// cells are returned as <redacted>, without a reference to their value.
const PlaceholderRefusal = "placeholders ('${name}') and cell references ('${rN.R.C}') are not supported: requests are decided in lockhub, where no value is typed; write the value itself as a literal, or leave the filter out"

// isPlaceholder reports whether the body of a string literal (without
// quotes) has the "${...}" shape, well-formed or not.
func isPlaceholder(body string) bool { return strings.HasPrefix(body, "${") }
