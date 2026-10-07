package owner

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
)

type contextLine struct {
	modem.Modem
	calls    int
	to, text string
	err      error
}

func (l *contextLine) SendContext(ctx context.Context, to, text string) error {
	l.calls++
	l.to, l.text = to, text
	if err := ctx.Err(); err != nil {
		return err
	}
	return l.err
}

// REQ: CH-19, REV-5
func TestContextInformPreservesDisclosureAndConfiguredOwner(t *testing.T) {
	r := newRig(t, nil)
	line := &contextLine{Modem: r.ch.cfg.Modem}
	r.ch.cfg.Modem = watchedLine{Modem: line, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "A fixed broker notice."); err != nil {
		t.Fatal(err)
	}
	if line.calls != 1 || line.to != r.ch.cfg.Owner || line.text != control.Fit(Disclose("A fixed broker notice.")) {
		t.Fatal(line.calls, line.to, line.text)
	}
}
func TestContextInformSecretTextBecomesExistingLocalPointer(t *testing.T) {
	r := newRig(t, nil)
	line := &contextLine{Modem: r.ch.cfg.Modem}
	r.ch.cfg.Modem = watchedLine{Modem: line, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "Use verification code 123456."); err != nil {
		t.Fatal(err)
	}
	if line.text != control.Fit(Hidden) {
		t.Fatal("disclosure bypass", line.text)
	}
}
func TestContextInformRefusesUnsupportedModemWithoutLegacySend(t *testing.T) {
	r := newRig(t, nil)
	original := r.ch.cfg.Modem
	r.ch.cfg.Modem = watchedLine{Modem: original, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "Fixed notice."); !errors.Is(err, ErrContextSendUnsupported) {
		t.Fatal(err)
	}
}
func TestFailedContextSendRecordsOwnerLineFailure(t *testing.T) {
	r := newRig(t, nil)
	line := &contextLine{Modem: r.ch.cfg.Modem, err: modem.ErrDown}
	r.ch.cfg.Modem = watchedLine{Modem: line, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "Fixed notice."); !errors.Is(err, modem.ErrDown) {
		t.Fatal(err)
	}
	if r.ch.lineFailed.Load() != r.ch.cfg.Now().UnixNano() {
		t.Fatal("missing failure provenance")
	}
}
func TestCanceledContextInformDoesNotInvokeModem(t *testing.T) {
	r := newRig(t, nil)
	line := &contextLine{Modem: r.ch.cfg.Modem}
	r.ch.cfg.Modem = watchedLine{Modem: line, c: r.ch}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.ch.InformContext(ctx, "Fixed notice."); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if line.calls != 0 {
		t.Fatal("already cancelled notice reached modem")
	}
}
func TestNilContextInformRefused(t *testing.T) {
	r := newRig(t, nil)
	if err := r.ch.InformContext(nil, "Fixed notice."); !errors.Is(err, ErrContextSendRequired) {
		t.Fatal(err)
	}
}

// REQ: REV-5
func TestNestedContextCapabilityRefusalDoesNotManufactureLineFailure(t *testing.T) {
	r := newRig(t, nil)
	// New wraps this legacy-only modem in watchedLine. A second wrapper can
	// delegate the optional interface and receive the inner refusal.
	r.ch.cfg.Modem = watchedLine{Modem: r.ch.cfg.Modem, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "Fixed notice."); err != ErrContextSendUnsupported {
		t.Fatal(err)
	}
	if r.ch.lineFailed.Load() != 0 {
		t.Fatal("capability refusal recorded as transport attempt")
	}
}
func TestJoinedContextErrorStillRecordsPossibleLineFailure(t *testing.T) {
	r := newRig(t, nil)
	line := &contextLine{Modem: r.ch.cfg.Modem, err: errors.Join(ErrContextSendUnsupported, modem.ErrDown)}
	r.ch.cfg.Modem = watchedLine{Modem: line, c: r.ch}
	if err := r.ch.InformContext(context.Background(), "Fixed notice."); !errors.Is(err, modem.ErrDown) {
		t.Fatal(err)
	}
	if r.ch.lineFailed.Load() != r.ch.cfg.Now().UnixNano() {
		t.Fatal("ambiguous transport failure lost provenance")
	}
}
