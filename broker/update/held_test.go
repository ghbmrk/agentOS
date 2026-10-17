package update

// REQ: SR3-6-f5a, SR3-6-f5b, UPD-8
// SR3-6-f5: an anchor that does not answer holds attestation authority,
// not the whole check, and the owner is told the step that works.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// SR3-6-f5a: for each way the anchor fails to answer, Check still returns
// the release for the owner's path, with no interim or independent
// authority, Stage refuses the attested copy, and the noted list is
// written.
func TestAnchorErrorHoldsOnlyAttestation(t *testing.T) {
	for _, c := range []struct {
		name        string
		read, raise error
	}{
		{"read-unanswered", errors.New("synthetic: anchor did not answer in time"), nil},
		{"read-locked", fmt.Errorf("update: anchor: %w", ErrAnchorLocked), nil},
		{"read-missing", ErrAnchorMissing, nil},
		{"read-elsewhere", ErrAnchorElsewhere, nil},
		{"raise", nil, errors.New("synthetic: raise refused")},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, box, pinned, _, a := anchoredInterimFix(t)
			policyFile := filepath.Join(f.store.Dir, allowListFile)
			before, err := os.ReadFile(policyFile)
			f.must(err)
			a.readErr, a.raiseErr = c.read, c.raise
			outside := newKey(t)
			allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))

			res, err := f.check(Options{Attestors: allow, InterimAttestors: pinned})
			if err != nil || res.Release == nil || !res.Release.OK() {
				t.Fatalf("an anchor error stopped the owner's check: release %v, err %v", res.Release, err)
			}
			cause := c.read
			if cause == nil {
				cause = c.raise
			}
			if want := AnchorHeldLine(fmt.Errorf("wrapped: %w", heldErr{cause})); res.Held == "" || res.Held != want {
				t.Fatalf("Held = %q, want %q", res.Held, want)
			}
			atts := [][]byte{pass(t, box, res.Release), pass(t, outside, res.Release)}
			v := res.Release.WithAttestations(atts, nil)
			if v.Security() || v.InterimAttestation() || res.Release.InterimAttestation() {
				t.Fatal("a held check granted attestation authority")
			}
			if n := res.Release.IndependentPasses(atts, nil); n != 0 {
				t.Fatalf("a held check counted %d independent passes", n)
			}
			if v.security || v.attested {
				t.Fatal("a held check's release carries attestation into Stage")
			}
			// Even marked attested, Stage refuses it: its policy never matches.
			forced := *v
			forced.attested = true
			if err := f.store.Stage(&forced); !errors.Is(err, ErrPolicyMoved) {
				t.Fatalf("Stage of a held check's attested release = %v, want ErrPolicyMoved", err)
			}
			// The anchor answers again: the held release still never
			// matches, while a fresh check does.
			a.readErr, a.raiseErr = nil, nil
			if v.Security() || res.Release.IndependentPasses(atts, nil) != 0 || f.store.Stage(&forced) == nil {
				t.Fatal("a held check's release gained authority once the anchor answered")
			}
			fresh, err := f.check(Options{Attestors: allow, InterimAttestors: pinned})
			if err != nil || fresh.Held != "" {
				t.Fatalf("a check once the anchor answered: held %q, err %v", fresh.Held, err)
			}
			if fresh.Release.IndependentPasses([][]byte{pass(t, outside, fresh.Release)}, nil) != 1 {
				t.Fatal("a check once the anchor answered did not count the outside pass")
			}
			after, err := os.ReadFile(policyFile)
			f.must(err)
			if string(after) == string(before) {
				t.Fatal("a held check did not write the noted allow-list")
			}
		})
	}
}

// SR3-6-f5a: NoteAttestors still reports the anchor error, after writing
// the noted list.
func TestNoteAttestorsReportsHeldAnchor(t *testing.T) {
	f, _, pinned, _, a := anchoredInterimFix(t)
	a.readErr = ErrAnchorLocked
	outside := newKey(t)
	allow := append(append([]ed25519.PublicKey{}, pinned...), outside.Public().(ed25519.PublicKey))
	err := f.store.NoteAttestors(allow, pinned)
	if !errors.Is(err, ErrAnchorLocked) || AnchorHeldLine(err) == "" {
		t.Fatalf("NoteAttestors with a locked anchor = %v, want the held anchor error", err)
	}
	if AnchorHeldLine(errors.New("synthetic: disk full")) != "" {
		t.Fatal("a non-anchor error has a held line")
	}
}

// SR3-6-f5a: an error that is not the anchor's still fails the check.
func TestNonAnchorNoteErrorStillFails(t *testing.T) {
	f, _, _, _, _ := anchoredInterimFix(t)
	if _, err := f.check(Options{Attestors: []ed25519.PublicKey{make(ed25519.PublicKey, 5)}}); err == nil {
		t.Fatal("a malformed allow-list did not fail the check")
	}
	f.must(os.Remove(filepath.Join(f.store.Dir, allowListFile)))
	f.must(os.Mkdir(filepath.Join(f.store.Dir, allowListFile), 0o700))
	if res, err := f.check(Options{}); err == nil {
		t.Fatalf("an unwritable policy file did not fail the check (held %q)", res.Held)
	}
}

// heldStep is each owner step an anchor-held line may name.
var heldStep = map[string]*regexp.Regexp{
	"unlock":     regexp.MustCompile(`(?i)unlock me with your card`),
	"trust":      regexp.MustCompile(`(?i)trust this PC again`),
	"restart":    regexp.MustCompile(`(?i)\brestart\b`),
	"move-drive": regexp.MustCompile(`(?i)move the drive back`),
}

// SR3-6-f5b (CH-12): each held line is GSM-7, within three segments,
// carries no raw error text, and names exactly the steps that work.
func TestAnchorHeldLinesNameOnlyStepsThatWork(t *testing.T) {
	canary := "synthetic-canary-7f3a"
	for _, c := range []struct {
		name  string
		err   error
		steps []string
	}{
		{"locked", ErrAnchorLocked, []string{"unlock"}},
		{"missing", ErrAnchorMissing, []string{"trust"}},
		{"elsewhere", ErrAnchorElsewhere, []string{"restart", "move-drive"}},
		{"unanswered", errors.New(canary), []string{"restart"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			line := AnchorHeldLine(fmt.Errorf("update: read the outside-attestor anchor: %w", heldErr{fmt.Errorf("%s: %w", canary, c.err)}))
			if line == "" {
				t.Fatal("no held line")
			}
			if n, gsm7 := modem.Segments(line); !gsm7 || n > 3 {
				t.Fatalf("%d segments, gsm7 %v: %q", n, gsm7, line)
			}
			for _, raw := range []string{canary, "update:", "anchor", "409", "503"} {
				if strings.Contains(line, raw) {
					t.Fatalf("held line carries %q: %q", raw, line)
				}
			}
			var named []string
			for s, re := range heldStep {
				if re.MatchString(line) {
					named = append(named, s)
				}
			}
			sort.Strings(named)
			want := append([]string(nil), c.steps...)
			sort.Strings(want)
			if strings.Join(named, ",") != strings.Join(want, ",") {
				t.Fatalf("held line names %v, want %v: %q", named, want, line)
			}
		})
	}
}
