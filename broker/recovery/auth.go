package recovery

import "errors"

// Auth is the owner's authority for a tier-4 action (CH-3): a code from
// the code generator or the paper grid that the owner channel checked for
// this action, plus confirmation on the box's own Wi-Fi page; or the
// recovery key, which this package checks against the drive's own slot.
type Auth struct {
	// Code: the owner channel verified a high-tier code for this action.
	Code bool
	// Local: the owner confirmed on the local page (CH-7, CH-8).
	Local bool
	// Recovery, when set, replaces both.
	Recovery RecoveryKey
}

// ErrNotAuthorized is a tier-4 action without the owner's authority.
var ErrNotAuthorized = errors.New("recovery: needs an approval code and confirmation on the local Wi-Fi page, or the recovery key")

func (a Auth) check(b *Box) error {
	if a.Recovery.Valid() {
		if b.opens(a.Recovery) {
			return nil
		}
		return ErrNotAuthorized
	}
	if a.Code && a.Local {
		return nil
	}
	return ErrNotAuthorized
}
