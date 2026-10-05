// Package verb is the broker's closed verb list (SPEC ADP-2). Every
// operation an adapter declares maps to exactly one of these verbs, and
// the verb, never the adapter's author, fixes the operation's
// reversibility class. Changing the list is an owner-approved intent
// (OP-5, CHG-2), so it lives in code, not configuration.
package verb

const (
	Read          = "read"
	Draft         = "draft"
	Organize      = "organize"
	Send          = "send"
	Post          = "post"
	Buy           = "buy"
	Share         = "share"
	DeleteRemote  = "delete-remote"
	ChangeAccount = "change-account"
	RevealSecret  = "reveal-or-create-secret"
)

// Class is a verb's built-in reversibility class.
type Class int

const (
	// Reversible verbs leave nothing outside the box that cannot be taken
	// back: reading, drafts in the owner's own account, and organize
	// (ADP-2: changes only the owner sees that fully undo in the account,
	// each declared with its inverse and journaled with the prior state).
	Reversible Class = iota
	// Irreversible verbs reach or change the world (REV-2): every one is
	// gated by an owner approval or an owner pre-allowance (ADP-9).
	Irreversible
	// Secret verbs reveal or create a secret (CRED-6). They are
	// irreversible and keep per-action approval under any pre-allowance.
	Secret
)

var classes = map[string]Class{
	Read: Reversible, Draft: Reversible, Organize: Reversible,
	Send: Irreversible, Post: Irreversible, Buy: Irreversible, Share: Irreversible,
	DeleteRemote: Irreversible, ChangeAccount: Irreversible,
	RevealSecret: Secret,
}

// ClassOf returns v's class; false if v is not on the list. An unknown
// verb reports Secret, the strictest class, so a caller that ignores ok
// still fails closed.
func ClassOf(v string) (Class, bool) {
	c, ok := classes[v]
	if !ok {
		return Secret, false
	}
	return c, true
}

// Valid reports whether v is on the list.
func Valid(v string) bool {
	_, ok := classes[v]
	return ok
}
