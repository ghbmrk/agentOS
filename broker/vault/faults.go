package vault

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
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

// syncFault is the error InjectSyncFault asks Sync to return. Atomic, so a
// test may set it while the vault runs.
var syncFault atomic.Pointer[error]

// InjectSyncFault makes every Sync fail with err, wrapped in
// durable.ErrDirSync as a real failure is, as if the vault file's name were
// not durable. It is for tests of callers in other packages, and
// panics outside a test binary. restore puts back the fault that was set
// before.
func InjectSyncFault(err error) (restore func()) {
	if !testing.Testing() {
		panic("vault: InjectSyncFault outside a test")
	}
	prev := syncFault.Swap(&err)
	return func() { syncFault.Store(prev) }
}

// injectedSyncFault is the fault set by InjectSyncFault, or nil.
func injectedSyncFault() error {
	if p := syncFault.Load(); p != nil {
		return *p
	}
	return nil
}

// stageFault is the error InjectStageFault asks replaceKeys to return once
// the staged keys file lands. Atomic, so a test may set it while the vault
// runs.
var stageFault atomic.Pointer[error]

// InjectStageFault makes every slot change fail with err, wrapped in
// durable.ErrDirSync as a real failure is, just after the staged next keys
// file lands, as if its directory sync had failed. The change is not
// decided yet, so the error does not wrap ErrSlotDecided. It is for tests
// of callers in other packages, and panics outside a test binary. restore
// puts back the fault that was set before.
func InjectStageFault(err error) (restore func()) {
	if !testing.Testing() {
		panic("vault: InjectStageFault outside a test")
	}
	prev := stageFault.Swap(&err)
	return func() { stageFault.Store(prev) }
}

// injectedStageFault is the fault set by InjectStageFault, wrapped in
// durable.ErrDirSync, or nil.
func injectedStageFault() error {
	if p := stageFault.Load(); p != nil && *p != nil {
		return fmt.Errorf("%w: %w", durable.ErrDirSync, *p)
	}
	return nil
}
