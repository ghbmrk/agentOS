// Package key is the key-check library (SPEC KEY-1..KEY-4, KRN-2). A key is a
// signed chain of caveats over a root grant; the kernel and every clerk
// verify one with this package alone, from the chain plus the log's
// revocation entries, with no network and no model (KRN-3).
package key

// Verb is one entry of the closed verb list (SPEC VRB-2, KRN-4).
type Verb string

const (
	Read                 Verb = "read"
	Fetch                Verb = "fetch"
	Draft                Verb = "draft"
	Organize             Verb = "organize"
	Trash                Verb = "trash"
	Unsubscribe          Verb = "unsubscribe"
	Send                 Verb = "send"
	Post                 Verb = "post"
	Buy                  Verb = "buy"
	Share                Verb = "share"
	DeleteRemote         Verb = "delete-remote"
	ChangeAccount        Verb = "change-account"
	RevealOrCreateSecret Verb = "reveal-or-create-secret"
	Actuate              Verb = "actuate"
	ActuatePhysical      Verb = "actuate-physical"
	Present              Verb = "present"
)

// Class is a verb's fixed class (KRN-4): reversible, or irreversible at a
// risk tier.
type Class uint8

const (
	Reversible Class = iota
	IrreversibleLow
	IrreversibleHigh
)

// Irreversible reports whether the class needs a key plus its hold window,
// or an owner approval of the exact step.
func (c Class) Irreversible() bool { return c != Reversible }

var classes = map[Verb]Class{
	Read: Reversible, Fetch: Reversible, Draft: Reversible, Organize: Reversible,
	Trash: Reversible, Present: Reversible,
	Unsubscribe: IrreversibleLow, Send: IrreversibleLow, Post: IrreversibleLow, Actuate: IrreversibleLow,
	Buy: IrreversibleHigh, Share: IrreversibleHigh, DeleteRemote: IrreversibleHigh,
	ChangeAccount: IrreversibleHigh, RevealOrCreateSecret: IrreversibleHigh,
	ActuatePhysical: IrreversibleHigh,
}

// ClassOf returns v's class. An unknown verb reports the strictest class and
// false, so a caller that ignores ok still fails closed.
func ClassOf(v Verb) (Class, bool) {
	c, ok := classes[v]
	if !ok {
		return IrreversibleHigh, false
	}
	return c, true
}

// Valid reports whether v is on the list.
func Valid(v Verb) bool { _, ok := classes[v]; return ok }
