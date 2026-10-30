package kernel_test

// REQ: BAK-1, LOG-1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A rule added for new targets (#3901: no locator element led or trailed by
// a space) refuses a new add but not replay: a target logged before it
// still folds after a restart, and so does a later add signed over the
// count it made. Catches a tightening that silently drops logged targets.
func TestATighterTargetRuleKeepsLoggedTargets(t *testing.T) {
	r := newRig(t)
	old := kernel.BackupTarget{Name: "old", Kind: kernel.KindDir, Locator: "/mnt/usb "}
	if err := r.k.BackupTarget(1, old, target(r, r.owner, old)); !errors.Is(err, kernel.ErrTarget) {
		t.Fatalf("a new padded locator: %v", err)
	}
	// As logged before the rule: the kernel's own entry, written past it.
	type body struct {
		Target kernel.BackupTarget
		Cosign key.Cosign
	}
	if _, err := r.k.Log().Append(1, kernel.TBackupTarget, 1, body{old, key.Approve(r.owner.pass, kernel.BackupTargetHash(0, old))}); err != nil {
		t.Fatal(err)
	}
	must(t, r.k.Log().Anchor())
	r.boot(2)
	next := drive("nas")
	must(t, r.k.BackupTarget(3, next, target(r, r.owner, next)))
	r.boot(4)
	got := listed(r.k.State())
	if got["old"].BackupTarget != old || got["nas"].BackupTarget != next {
		t.Fatalf("after replay: %+v", r.k.State().BackupTargets())
	}
}
