package vault

import (
	"sync/atomic"
	"testing"
)

// sealFault is the error InjectSealFault asks replaceKeys to return just
// after it seals. Atomic, so a test may set it while the vault runs.
var sealFault atomic.Pointer[error]

// InjectSealFault makes every slot change fail with err just after the
// next keys file is sealed, the point from which the change is decided
// (ErrSlotDecided). It is for tests of callers in other packages, which
// cannot reach the vault's write path, and panics outside a test binary.
// restore puts back the fault that was set before.
func InjectSealFault(err error) (restore func()) {
	if !testing.Testing() {
		panic("vault: InjectSealFault outside a test")
	}
	prev := sealFault.Swap(&err)
	return func() { sealFault.Store(prev) }
}

// injectedSealFault is the fault set by InjectSealFault, or nil.
func injectedSealFault() error {
	if p := sealFault.Load(); p != nil {
		return *p
	}
	return nil
}
