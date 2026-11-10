// Package header holds the header names a plan route may pass and the one
// check on a declared header value, shared by the model and plan clerks and
// the old core's egress (#5278), so their lists and checks cannot drift.
package header

import (
	"errors"
	"strings"
)

// PassHeaders are the names a plan route may pass, each exactly as the
// shipped declaration's CLI sends or reads it (#4914). None carries a
// credential, reshapes the request or ends at the next hop, and only
// Content-Type frames it, which a refresh may not declare: the clerk sets
// its own.
var PassHeaders = []string{
	"Accept", "Content-Type", "User-Agent", "Openai-Beta", "Originator", "Version",
	"Session_id", "Conversation_id", "Chatgpt-Account-Id", "X-Openai-Internal-Codex-Responses-Lite",
	"Retry-After", "X-Request-Id", "Openai-Model",
}

// PassPrefixes are the answer-header prefixes a plan route may pass; no
// name the header corpus holds begins with one.
var PassPrefixes = []string{"X-Codex-"}

// Value refuses a declared header value that is empty, holds a byte other
// than visible ASCII or a space (so no line break or control character adds
// a header line or reaches the remote), or begins or ends with a space. The
// error says which rule it broke.
func Value(v string) error {
	switch {
	case v == "":
		return errors.New("the value is empty")
	case strings.ContainsFunc(v, func(r rune) bool { return r < ' ' || r > '~' }):
		return errors.New("the value holds a control character or a byte outside visible ASCII")
	case v[0] == ' ' || v[len(v)-1] == ' ':
		return errors.New("the value begins or ends with a space")
	}
	return nil
}
