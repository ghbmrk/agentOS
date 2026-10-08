package pacingfile

import (
	"io"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/grants"
)

// StartManifest admits a single owned worker BEFORE reading configuration. The
// caller-trusted expected pin and authority/clock callbacks are supplied separately;
// pacing options come only from D49 canonical validated bytes. No config discovery,
// pin authentication, provisioning, second worker, retry or activation occurs.
//
// Retain reader ownership until complete slot Drain, even after a cancelled wait
// or retired status. Reader/clock callbacks must not await their own Drain. They
// may hang indefinitely, holding worker/slot; independent owner controls must exist.
// Another slot/direct reads escape this cooperating admission bound.
func (s *StartupSlot) StartManifest(reader io.Reader, expected [32]byte, cfg grants.Config) (*Startup, error) {
	if s == nil {
		return nil, ErrManifest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil || s.draining != nil || s.recovery != RecoveryIdle {
		return nil, ErrStartupOccupied
	}
	if reader == nil || expected == ([32]byte{}) || !manifestConfigValid(cfg) {
		return nil, ErrManifest
	}
	p := &Startup{opening: true, done: make(chan struct{})}
	s.current = p
	go p.openManifest(reader, expected, cfg)
	return p, nil
}

func (p *Startup) openManifest(reader io.Reader, expected [32]byte, cfg grants.Config) {
	session, err := constructManifestSession(reader, expected, cfg, &p.retirement)
	p.complete(session, err)
}

func constructManifestSession(reader io.Reader, expected [32]byte, cfg grants.Config, retired *atomic.Bool) (session *Session, err error) {
	// Contain the owned reader/pin boundary too. The inner existing constructor
	// still owns lease unwind and Gate.New panic containment; no raw errors escape.
	defer func() {
		if recover() != nil {
			session = nil
			err = ErrSessionRecovery
		}
	}()
	if retired.Load() {
		return nil, ErrSessionRetired
	}
	settings, err := ReadProvisionedManifest(reader, expected)
	if err != nil {
		return nil, ErrManifest
	}
	// A retirement observed here must not even acquire a lease. A later racing
	// retirement keeps D47 backend checks/late cleanup and never publishes a user.
	if retired.Load() {
		return nil, ErrSessionRetired
	}
	return constructSession(settings.manifest.Ledger, settings.bindConfig(cfg), retired)
}
