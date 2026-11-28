package localui

import (
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/kernel/secret"
)

// recoveryOf is the recovery factor for key k. It lives in its own file so
// that the kernel/secret import changes no other test file's header, which
// mutgate would read as reaching every test there (#6000).
func recoveryOf(k []byte) seal.Recovery { return seal.Recovery{Key: secret.Hide(k)} }
