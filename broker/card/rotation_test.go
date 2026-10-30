package card

// REQ: REC-4, HW-1

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// newRotRig is newRig for a rotation display of the parts p.
func newRotRig(t *testing.T, p Parts) *rig {
	t.Helper()
	x := &rig{}
	d, err := NewDisplay(DisplayConfig{
		Rotate:    &p,
		Authority: testAuthority(t),
		Generate: func(r io.Reader) (*Card, error) {
			c, err := Generate(r)
			if err == nil {
				cp := *c
				cp.GridSeed = bytes.Clone(c.GridSeed)
				x.gen = &cp
			}
			return c, err
		},
		Provision: func(c *Card) error {
			x.mu.Lock()
			defer x.mu.Unlock()
			if x.fail != nil {
				return x.fail
			}
			cp := *c
			cp.GridSeed = bytes.Clone(c.GridSeed)
			x.got = append(x.got, &cp)
			return nil
		},
		Journal: func(e string) { x.log = append(x.log, e) },
	})
	if err != nil {
		t.Fatal(err)
	}
	x.d = d
	return x
}

// rotAnswers are the values the rotation display asks for, read from the
// generated card as the owner reads them from the saved one.
func (x *rig) rotAnswers(p Parts) Answers {
	var a Answers
	w, g := x.d.Asks()
	if w > 0 {
		a.Word = strings.Fields(x.gen.VaultPassphrase)[w-1]
	}
	if g > 0 {
		a.Group = strings.Split(x.gen.RecoveryKey, "-")[g-1]
	}
	if !p.Passphrase && !p.Recovery {
		switch {
		case p.Setup:
			a.Check = x.gen.SetupCode
		case p.Grid:
			a.Check = GridCheck(x.gen.GridSeed)
		}
	}
	return a
}

// partSecrets are the secrets of the parts in p, and of the others.
func partSecrets(c *Card, p Parts) (in, out map[string]string) {
	in, out = map[string]string{}, map[string]string{}
	put := func(on bool, name, v string) {
		if on {
			in[name] = v
		} else {
			out[name] = v
		}
	}
	put(p.Setup, "setup secret", c.SetupSecret)
	put(p.Setup, "setup code", c.SetupCode)
	put(p.Passphrase, "passphrase", c.VaultPassphrase)
	put(p.Grid, "grid check", GridCheck(c.GridSeed))
	put(p.Recovery, "recovery key", c.RecoveryKey)
	return in, out
}

var rotations = []Parts{
	{Recovery: true},
	{Passphrase: true},
	{Passphrase: true, Recovery: true},
	{Setup: true},
	{Grid: true},
	{Setup: true, Grid: true},
	{Setup: true, Passphrase: true, Grid: true, Recovery: true},
}

// REC-4 under HW-1's confirm-then-erase: a rotation display shows the new
// values of the rotated parts only, keeps showing them through wrong
// confirms without provisioning, and on a right confirm provisions just
// those parts and erases its copy, as the first-boot display does.
func TestRotationDisplayConfirmThenErase(t *testing.T) {
	for _, p := range rotations {
		t.Run(fmt.Sprintf("%+v", p), func(t *testing.T) {
			x := newRotRig(t, p)
			in, out := partSecrets(x.gen, p)
			page, err := x.d.Page()
			if err != nil {
				t.Fatal(err)
			}
			for name, v := range in {
				if !bytes.Contains(page, []byte(v)) {
					t.Fatalf("page does not show the new %s", name)
				}
			}
			for name, v := range out {
				if bytes.Contains(page, []byte(v)) {
					t.Fatalf("page shows a %s that is not rotated", name)
				}
			}
			if !bytes.Contains(page, []byte("stay as on your current card")) {
				t.Fatal("page does not say the other parts stay")
			}

			w, g := x.d.Asks()
			if (w > 0) != p.Passphrase || (g > 0) != p.Recovery {
				t.Fatalf("asks word %d group %d for %+v", w, g, p)
			}
			right := x.rotAnswers(p)
			// Each asked value wrong on its own, and all blank.
			bads := []Answers{{}}
			if w > 0 {
				bads = append(bads, Answers{Word: "zzzzz", Group: right.Group, Check: right.Check})
			}
			if g > 0 {
				bads = append(bads, Answers{Word: right.Word, Group: "AAAAA", Check: right.Check})
			}
			if right.Check != "" {
				bads = append(bads, Answers{Word: right.Word, Group: right.Group, Check: "QQQQ"})
			}
			for _, bad := range bads {
				if err := x.d.ConfirmAnswers(bad); !errors.Is(err, ErrNotConfirmed) {
					t.Fatalf("confirm %+v: %v", bad, err)
				}
			}
			if len(x.got) != 0 || x.d.Confirmed() {
				t.Fatal("provisioned before a correct confirm")
			}
			if _, err := x.d.Page(); err != nil {
				t.Fatalf("display gone after wrong answers: %v", err)
			}

			seed, sheet := x.d.c.GridSeed, x.d.sheet
			if err := x.d.ConfirmAnswers(Answers{Word: strings.ToUpper(right.Word), Group: strings.ToLower(right.Group), Check: " " + strings.ToLower(right.Check)}); err != nil {
				t.Fatal(err)
			}
			if !x.d.Confirmed() || len(x.got) != 1 {
				t.Fatalf("confirmed %v, provisioned %d times", x.d.Confirmed(), len(x.got))
			}
			got := x.got[0]
			gin, gout := partSecrets(got, p)
			for name, v := range in {
				if gin[name] != v {
					t.Fatalf("provisioned %s differs from the one shown", name)
				}
			}
			for name, v := range gout {
				if name != "grid check" && v != "" {
					t.Fatalf("provisioned card carries a %s that is not rotated", name)
				}
			}
			if !p.Grid && len(got.GridSeed) != 0 {
				t.Fatal("provisioned card carries a grid that is not rotated")
			}
			// The same erase checks as TestDisplayConfirmThenErase and
			// TestDisplayEraseWipesMemory.
			if _, err := x.d.Page(); !errors.Is(err, ErrDisplayGone) {
				t.Fatalf("page after confirm: %v", err)
			}
			if err := x.d.ConfirmAnswers(right); !errors.Is(err, ErrDisplayGone) {
				t.Fatalf("confirm after erase: %v", err)
			}
			if x.d.c != nil || x.d.sheet != nil {
				t.Fatal("display still references the card")
			}
			if !bytes.Equal(seed, make([]byte, len(seed))) || !bytes.Equal(sheet, make([]byte, len(sheet))) {
				t.Fatal("display copy not zeroed")
			}
			for _, e := range x.log {
				for name, v := range secrets(x.gen) {
					if strings.Contains(e, v) {
						t.Fatalf("journal event carries the %s", name)
					}
				}
			}
		})
	}
}

// The prompt names only what the rotation display asks for.
func TestRotationPrompt(t *testing.T) {
	for p, want := range map[Parts]string{
		{Recovery: true}:                   "Type group %[2]d of your new recovery key.",
		{Passphrase: true}:                 "Type word %[1]d of your new vault passphrase.",
		{Passphrase: true, Recovery: true}: "Type word %[1]d of your new vault passphrase and group %[2]d of your new recovery key.",
		{Setup: true}:                      "Type your new setup code.",
		{Grid: true}:                       "Type the check code printed under your new grid.",
	} {
		x := newRotRig(t, p)
		w, g := x.d.Asks()
		if strings.Contains(want, "%") {
			want = fmt.Sprintf(want, w, g)
		}
		if got := x.d.Prompt(); got != want {
			t.Fatalf("%+v: prompt %q", p, got)
		}
	}
}

// An aborted rotation: Discard erases the display without provisioning,
// and so does a provisioner that says the rotation lapsed (ErrDiscard).
func TestRotationDiscard(t *testing.T) {
	x := newRotRig(t, Parts{Recovery: true})
	seed, sheet := x.d.c.GridSeed, x.d.sheet
	x.d.Discard()
	if len(x.got) != 0 || x.d.Confirmed() {
		t.Fatal("discard provisioned")
	}
	if x.d.c != nil || !bytes.Equal(sheet, make([]byte, len(sheet))) || !bytes.Equal(seed, make([]byte, len(seed))) {
		t.Fatal("discard kept the display copy")
	}
	if err := x.d.ConfirmAnswers(x.rotAnswers(Parts{Recovery: true})); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("confirm after discard: %v", err)
	}
	if !contains(x.log, EventDiscarded) {
		t.Fatalf("journal %q", x.log)
	}
	x.d.Discard() // idempotent

	y := newRotRig(t, Parts{Recovery: true})
	y.fail = fmt.Errorf("pending lapsed: %w", ErrDiscard)
	err := y.d.ConfirmAnswers(y.rotAnswers(Parts{Recovery: true}))
	if !errors.Is(err, ErrDiscard) || y.d.Confirmed() {
		t.Fatalf("lapsed provision: %v", err)
	}
	if _, err := y.d.Page(); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("display kept after the rotation lapsed: %v", err)
	}

	// Any other provisioning failure keeps the display: part of the new
	// card may already be in effect.
	z := newRotRig(t, Parts{Recovery: true})
	z.fail = errors.New("vault busy")
	if err := z.d.ConfirmAnswers(z.rotAnswers(Parts{Recovery: true})); err == nil {
		t.Fatal("failing provision confirmed")
	}
	if _, err := z.d.Page(); err != nil {
		t.Fatalf("display gone after a failed provision: %v", err)
	}
	if err := z.d.Discard(); err != nil {
		t.Fatalf("cancel refused before anything took effect: %v", err)
	}
}

// Once part of a new card is in effect, the owner has confirmed from
// their copy and the rotation is used up (Pending lapses after a partial
// write), so the display erases its copy, names the step that finishes
// (CH-12), and refuses cancel; retries never revive it.
func TestRotationInEffectErasesAndNamesTheNextStep(t *testing.T) {
	p := Parts{Passphrase: true, Recovery: true}
	x := newRotRig(t, p)
	x.fail = fmt.Errorf("slot written, card not stored: %w", ErrInEffect)
	right := x.rotAnswers(p)
	if err := x.d.ConfirmAnswers(right); !errors.Is(err, ErrInEffect) {
		t.Fatalf("partial provision: %v", err)
	}
	// From here the provisioner behaves like a used Pending: it lapses.
	x.fail = fmt.Errorf("pending lapsed: %w", ErrDiscard)
	if _, err := x.d.Page(); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("display kept after a confirmed partial provision: %v", err)
	}
	if x.d.Confirmed() {
		t.Fatal("a partial provision reported as confirmed")
	}
	if !contains(x.log, EventInEffect) || contains(x.log, EventDiscarded) {
		t.Fatalf("journal: %q", x.log)
	}
	if err := x.d.Discard(); !errors.Is(err, ErrInEffect) {
		t.Fatalf("discard after a partial provision: %v", err)
	}
	if err := x.d.ConfirmAnswers(right); !errors.Is(err, ErrDisplayGone) {
		t.Fatalf("retry after a partial provision: %v", err)
	}
	h := x.d.Handler(paired, "/home")
	for _, f := range []url.Values{nil, {"cancel": {"1"}}, {"word": {right.Word}, "group": {right.Group}}} {
		method := "POST"
		if f == nil {
			method = "GET"
		}
		w := do(t, h, method, "/rotate/card", f, true, nil)
		b := w.Body.String()
		// Not every part need be in effect (#1090 review F3): the text
		// keeps both cards and finishes with whichever one works.
		if w.Code != http.StatusGone || !strings.Contains(b, "already in effect") || !strings.Contains(b, "start a new card") ||
			!strings.Contains(b, "Keep the new card, and your current one") || !strings.Contains(b, "whichever card works") ||
			strings.Contains(b, "from now on") ||
			strings.Contains(b, "confirm again") || strings.Contains(b, "current card stays in effect") ||
			strings.Contains(b, x.gen.RecoveryKey) {
			t.Fatalf("%s %v after a partial provision: %d %q", method, f, w.Code, b)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestRotationNeedsAPart(t *testing.T) {
	_, err := NewDisplay(DisplayConfig{Rotate: &Parts{}, Authority: testAuthority(t), Provision: func(*Card) error { return nil }})
	if err == nil {
		t.Fatal("rotation of nothing shown")
	}
}

// The rotation page posts the check field when neither factor rotates,
// and its gone page after a discard does not claim a confirm.
func TestRotationHandler(t *testing.T) {
	p := Parts{Setup: true}
	x := newRotRig(t, p)
	h := x.d.Handler(paired, "/home")
	w := do(t, h, "GET", "/rotate/card", nil, true, nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `name="check"`) || strings.Contains(body, `name="word"`) || strings.Contains(body, `name="group"`) {
		t.Fatalf("GET: %d", w.Code)
	}
	w = do(t, h, "GET", "/rotate/card?save=1", nil, true, nil)
	if !strings.Contains(w.Header().Get("Content-Disposition"), "agentos-new-card-parts.html") {
		t.Fatalf("save name %q", w.Header().Get("Content-Disposition"))
	}
	right := x.rotAnswers(p)
	if w := do(t, h, "POST", "/rotate/card", url.Values{"check": {"QQQQ"}}, true, nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong POST: %d", w.Code)
	}
	if w := do(t, h, "POST", "/rotate/card", url.Values{"check": {right.Check}}, true, nil); w.Code != http.StatusSeeOther || !x.d.Confirmed() {
		t.Fatalf("right POST: %d", w.Code)
	}

	y := newRotRig(t, p)
	y.d.Discard()
	w = do(t, y.d.Handler(paired, "/home"), "GET", "/rotate/card", nil, true, nil)
	if w.Code != http.StatusGone || strings.Contains(w.Body.String(), "You confirmed") {
		t.Fatalf("GET after discard: %d %q", w.Code, w.Body.String())
	}
}

// The rotation page's cancel discards the new card (an aborted rotation);
// the first-boot page has no cancel.
func TestRotationHandlerCancel(t *testing.T) {
	x := newRotRig(t, Parts{Recovery: true})
	h := x.d.Handler(paired, "/home")
	if w := do(t, h, "POST", "/rotate/card", url.Values{"cancel": {"1"}}, false, nil); w.Code != http.StatusForbidden {
		t.Fatalf("unpaired cancel: %d", w.Code)
	}
	if w := do(t, h, "POST", "/rotate/card", url.Values{"cancel": {"1"}}, true, map[string]string{"Origin": "http://evil.example"}); w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin cancel: %d", w.Code)
	}
	if _, err := x.d.Page(); err != nil {
		t.Fatal("refused cancel discarded the card")
	}
	if w := do(t, h, "POST", "/rotate/card", url.Values{"cancel": {"1"}}, true, nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" {
		t.Fatalf("cancel: %d", w.Code)
	}
	if _, err := x.d.Page(); !errors.Is(err, ErrDisplayGone) || len(x.got) != 0 {
		t.Fatal("cancel kept or provisioned the card")
	}

	y := newRig(t)
	if strings.Contains(string(must(y.d.Page())), `name="cancel"`) {
		t.Fatal("first-boot page offers cancel")
	}
	if w := do(t, y.d.Handler(paired, "/setup"), "POST", "/card", url.Values{"cancel": {"1"}}, true, nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("first-boot cancel: %d", w.Code)
	}
}

// REQ: REC-4
// A card the box already made (the lost-card route, D-201 route B) shows
// no cancel and never says the current card stays in effect: the old card
// opens nothing any more. A posted cancel is not a cancel, and the confirm
// still provisions. Revert mutant: Made ignored (the page offers cancel).
func TestMadeCardOffersNoCancel(t *testing.T) {
	var gen Card
	confirmed := 0
	d, err := NewDisplay(DisplayConfig{Rotate: &Parts{Recovery: true}, Made: true, Authority: testAuthority(t),
		Generate: func(r io.Reader) (*Card, error) {
			c, err := Generate(r)
			if err == nil {
				gen = *c
			}
			return c, err
		},
		Provision: func(*Card) error { confirmed++; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	page := string(must(d.Page()))
	if strings.Contains(page, `name="cancel"`) || strings.Contains(page, "stays in effect") || !strings.Contains(page, "already opens my store") {
		t.Fatalf("made card page: %q", page)
	}
	h := d.Handler(paired, "/recovery/")
	if w := do(t, h, "POST", "/card", url.Values{"cancel": {"1"}}, true, nil); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("cancel of a made card: %d", w.Code)
	}
	if _, err := d.Page(); err != nil {
		t.Fatal("a cancel discarded a made card")
	}
	_, g := d.Asks()
	if w := do(t, h, "POST", "/card", url.Values{"group": {strings.Split(gen.RecoveryKey, "-")[g-1]}}, true, nil); w.Code != http.StatusSeeOther || confirmed != 1 {
		t.Fatalf("confirm of a made card: %d, provisioned %d", w.Code, confirmed)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// REQ: REC-4, HW-1, CH-9
//
// Every rotation sheet, whatever its parts, prints the authority's name,
// fingerprint and the address-bar line: the owner may keep only the
// newest sheet. It catches a rotation sheet without them.
func TestRotationSheetPrintsTheFingerprint(t *testing.T) {
	for _, p := range []Parts{{Setup: true}, {Passphrase: true}, {Grid: true}, {Recovery: true}, allParts} {
		page, err := newRotRig(t, p).d.Page()
		if err != nil {
			t.Fatal(err)
		}
		want := append(printedFingerprint(testFingerprint(t)), `<span class="mono">`+PageName+`</span>`,
			template.HTMLEscapeString(AddressBarLine), template.HTMLEscapeString(TrustLine))
		for _, w := range want {
			if !strings.Contains(string(page), w) {
				t.Fatalf("rotation of %+v lacks %q", p, w)
			}
		}
	}
}
