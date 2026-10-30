package localapi

import "time"

// OpHeld lists what the box kept for the owner page in place of a text:
// what the owner channel withheld (CH-19, CH-21) and agent replies too
// long to text or that did not go (#993). It needs a token. Reading
// removes nothing (CH-19).
const OpHeld = "page_held"

// HeldOps are the held-text ops, served when agentosd keeps them.
var HeldOps = []string{OpHeld}

// The kinds of a HeldItem.
const (
	HeldSecret  = "secret"  // may carry a key (CH-19)
	HeldOneTime = "onetime" // carried a code, kept for hours (CH-19, #906)
	HeldCode    = "code"    // mentioned a code (CH-21)
	HeldLong    = "long"    // too long to text
	HeldUnsent  = "unsent"  // a text that did not go
)

// HeldItem is one kept text. An expired one is a stub: no text.
type HeldItem struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	At      time.Time `json:"at"`
	Text    string    `json:"text,omitempty"`
	Expired bool      `json:"expired,omitempty"`
	// CodeExpired says the item's code has expired (CH-19, #906).
	CodeExpired bool `json:"code_expired,omitempty"`
}

// HeldList is OpHeld's answer: the kept items newest first, then the
// expired stubs.
type HeldList struct {
	Items []HeldItem `json:"items"`
}
