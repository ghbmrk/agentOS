// Package compact shortens a tool result without dropping anything it says.
// It removes insignificant JSON whitespace only. It does not summarize,
// reorder keys, or call a model (ARC-2). Text that is not one JSON value
// is returned as it was.
package compact

import (
	"bytes"
	"encoding/json"
)

// JSON returns s with insignificant whitespace removed when s is one JSON
// value and the result is shorter. Otherwise it returns s.
func JSON(s string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return s
	}
	if buf.Len() >= len(s) {
		return s
	}
	return buf.String()
}
