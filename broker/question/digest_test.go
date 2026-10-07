package question

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func digestRig(t *testing.T) *rig {
	t.Helper()
	return newRig(t, func(c *Config) { c.Path = filepath.Join(t.TempDir(), "questions.json") })
}

// REQ: CH-15, OP-1, OP-2
func TestQuestionDigestPeekPersistsWithoutConsumption(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"Fixed first note."}
	r.b.refused = 2
	s, err := r.b.PeekDigest()
	if err != nil || s == nil || len(s.Lines) != 2 {
		t.Fatal(s, err)
	}
	if len(r.b.digest) != 1 || r.b.refused != 2 {
		t.Fatal("peek consumed notes")
	}
	b, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := b.PeekDigest()
	if err != nil || !reflect.DeepEqual(s, again) {
		t.Fatal(s, again, err)
	}
	if err = b.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if next, err := b.PeekDigest(); err != nil || next != nil {
		t.Fatal(next, err)
	}
}
func TestQuestionDigestAckPreservesLaterLinesAndGuardCounts(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	r.b.refused = 2
	r.b.notAskedMore = 3
	s, err := r.b.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	r.b.digest = append(r.b.digest, "Later.")
	r.b.refused += 4
	r.b.notAskedMore += 5
	if err = r.b.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.b.digest, []string{"Later."}) || r.b.refused != 4 || r.b.notAskedMore != 5 {
		t.Fatal(r.b.digest, r.b.refused, r.b.notAskedMore)
	}
	next, err := r.b.PeekDigest()
	if err != nil || next == nil || !strings.Contains(strings.Join(next.Lines, " "), "4 answers") {
		t.Fatal(next, err)
	}
}
func TestQuestionDigestExactOldAckIsIdempotentAfterLaterGeneration(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	first, _ := r.b.PeekDigest()
	if err := r.b.AckDigest(*first); err != nil {
		t.Fatal(err)
	}
	r.b.digest = []string{"Second."}
	second, _ := r.b.PeekDigest()
	if err := r.b.AckDigest(*second); err != nil {
		t.Fatal(err)
	}
	b, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.AckDigest(*first); err != nil {
		t.Fatal(err)
	}
}
func TestQuestionDigestTamperingCannotConsumeSource(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	s, _ := r.b.PeekDigest()
	s.Lines[0] = "Changed"
	if err := r.b.AckDigest(*s); !errors.Is(err, ErrDigestSnapshot) {
		t.Fatal(err)
	}
	if len(r.b.digest) != 1 {
		t.Fatal("tampered snapshot consumed source")
	}
}
func TestQuestionDigestSnapshotModeExcludesLegacyTake(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	s, _ := r.b.PeekDigest()
	if out := r.b.TakeDigest(); len(out) != 0 {
		t.Fatal("legacy method consumed pending snapshot")
	}
	if err := r.b.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	r.b.digest = []string{"Later."}
	if out := r.b.TakeDigest(); len(out) != 0 {
		t.Fatal("legacy method consumed new snapshot-mode notes")
	}
}
func TestQuestionDigestRequiresDurablePath(t *testing.T) {
	r := newRig(t, nil)
	r.b.digest = []string{"First."}
	if _, err := r.b.PeekDigest(); !errors.Is(err, ErrDigestPersistence) {
		t.Fatal(err)
	}
	if out := r.b.TakeDigest(); len(out) != 1 {
		t.Fatal("failed opt-in disabled legacy mode")
	}
}
func TestQuestionDigestFailureLeavesSourcePendingAndRequiresReopen(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	original := r.b.cfg.Path
	r.b.cfg.Path = t.TempDir()
	if s, err := r.b.PeekDigest(); s != nil || err == nil {
		t.Fatal(s, err)
	}
	if len(r.b.digest) != 1 {
		t.Fatal("failed save consumed source")
	}
	r.b.cfg.Path = original
	if _, err := r.b.PeekDigest(); err == nil {
		t.Fatal("uncertain source remained usable")
	}
}
func TestQuestionDigestAckFailureRestoresPendingCounters(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	r.b.refused = 2
	s, _ := r.b.PeekDigest()
	r.b.cfg.Path = t.TempDir()
	if err := r.b.AckDigest(*s); err == nil {
		t.Fatal("failed save acknowledged")
	}
	if len(r.b.digest) != 1 || r.b.refused != 2 {
		t.Fatal("failed save consumed source")
	}
	b, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := b.PeekDigest()
	if err != nil || again == nil || again.Hash != s.Hash {
		t.Fatal(again, err)
	}
}
func TestQuestionDigestDrainsBoundedPrefixesWithoutLosingCounts(t *testing.T) {
	r := digestRig(t)
	for i := 0; i < 70; i++ {
		r.b.digest = append(r.b.digest, "Fixed note.")
	}
	r.b.refused = 2
	first, err := r.b.PeekDigest()
	if err != nil || len(first.Lines) != 64 || first.Refused != 0 {
		t.Fatal(first, err)
	}
	if err = r.b.AckDigest(*first); err != nil {
		t.Fatal(err)
	}
	second, err := r.b.PeekDigest()
	if err != nil || len(second.Lines) != 7 || second.Refused != 2 {
		t.Fatal(second, err)
	}
}
func TestQuestionDigestTracksOnlyCapturedNotAskedLines(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"Not asked: first.", "First default."}
	r.b.notAskedLines = 1
	s, _ := r.b.PeekDigest()
	r.b.digest = append(r.b.digest, "Not asked: later.")
	r.b.notAskedLines++
	if err := r.b.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if r.b.notAskedLines != 1 {
		t.Fatal("older prefix consumed later not-asked count", r.b.notAskedLines)
	}
}
func TestQuestionDigestSnapshotCopiesCannotMutatePendingState(t *testing.T) {
	r := digestRig(t)
	r.b.digest = []string{"First."}
	s, _ := r.b.PeekDigest()
	s.Lines[0] = "changed"
	s.Prefix[0] = "changed"
	again, err := r.b.PeekDigest()
	if err != nil || again.Lines[0] != "First." || again.Prefix[0] != "First." {
		t.Fatal(again, err)
	}
}

func TestQuestionCounterOnlySnapshotPreservesLaterLine(t *testing.T) {
	r := digestRig(t)
	r.b.refused = 2
	s, err := r.b.PeekDigest()
	if err != nil {
		t.Fatal(err)
	}
	r.b.digest = append(r.b.digest, "Later notice.")
	if err = r.b.AckDigest(*s); err != nil {
		t.Fatal(err)
	}
	if len(r.b.digest) != 1 || r.b.refused != 0 {
		t.Fatal(r.b.digest, r.b.refused)
	}
}
