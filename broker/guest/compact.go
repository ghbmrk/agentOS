package guest

import (
	"bytes"
	"encoding/json"
)

// compactJSON drops insignificant whitespace from a tool result that is
// one JSON value, when that makes it shorter. Strings, keys, and number
// text stay. Anything else is returned as it was. No model, no field cut.
func compactJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		return s
	}
	if buf.Len() >= len(s) {
		return s
	}
	return buf.String()
}
