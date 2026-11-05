package key

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
)

// REQ: KEY-2, CH-3

// ch3 is CH-3's table, each row's floor as a rung (D-307, D-311). A row
// whose proof names no rung states the rung of the place it is given: the
// owner page at home is P3.
var ch3 = map[string]Rung{
	"STOP (pause all dispatch)":                                                                                       P0,
	"Task chat, STATUS":                                                                                               P0,
	"Approve a low-risk irreversible effect (CH-10)":                                                                  P1,
	"Approve a high-risk irreversible effect (CH-10)":                                                                 P3,
	"Unlock on an unknown host (STO-2)":                                                                               P3,
	"New key (device keys except as the rows below say), raise budget, adopt a release":                               P3,
	"Turn the computer-use retry back on for a site or all sites (CLK-5)":                                             P3,
	"Connect devices or a hub from a connection plan":                                                                 P3,
	"Connect a verified device that needs no secret, read only (DEV-10)":                                              P3,
	"Key `actuate` or `present` on, or cut off from its vendor cloud, a connected device not marked safety or access": P1,
	"Key `actuate-physical` on a connected device":                                                                    P3,
	"Physical action in the unsafe direction, or a value outside `actuate` bounds that":                               P3,
	"Start a reverse-engineering task (DEV-12)":                                                                       P3,
	"Write firmware or software to a device (DEV-12)":                                                                 P3,
}

// TestCH3RowsAreTheFloor reads CH-3's table from SPEC.md: every row is a
// case here, at the rung its proof names first, and each holds as a rung
// caveat: an owner event at that rung or above passes, one below is refused.
func TestCH3RowsAreTheFloor(t *testing.T) {
	spec, err := os.ReadFile("../../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(spec)
	s = s[strings.Index(s, "- **CH-3** "):]
	s = s[:strings.Index(s, "\n- **CH-4** ")]
	first := regexp.MustCompile(`\bP([0-4])\b`)
	rows := 0
	for _, line := range strings.Split(s, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) != 4 || cells[1] == " Action " || strings.HasPrefix(cells[1], "---") {
			continue
		}
		action, proof := strings.TrimSpace(cells[1]), cells[2]
		var want Rung = -1
		for prefix, r := range ch3 {
			if strings.HasPrefix(action, prefix) {
				want = r
			}
		}
		if want < 0 {
			t.Errorf("CH-3 row %q is no case here", action)
			continue
		}
		rows++
		if m := first.FindStringSubmatch(proof); m != nil && Rung(m[1][0]-'0') != want {
			t.Errorf("%q: SPEC names P%s first, the case P%d", action, m[1], want)
		}
		o, h, k := root(t)
		d, err := Derive(k, h.priv, gen(3).pub, LimitRung(want))
		if err != nil {
			t.Fatal(err)
		}
		v := verified(t, d, o, gen(3))
		for r := P0; r <= P4; r++ {
			st := step(Trash)
			st.Rung = r
			got := v.Authorize(st, ctx(1, nil))
			if r >= want && got != nil || r < want && (got == nil || got.Code != RRung) {
				t.Errorf("%q at P%d: %v", action, r, got)
			}
		}
	}
	if rows != len(ch3) {
		t.Errorf("SPEC's CH-3 has %d rows, the cases %d", rows, len(ch3))
	}
}

// A rung caveat only narrows: a later link may ask for more, never less, and
// a rung outside P0 to P4 is malformed (KEY-3).
func TestRungOnlyRises(t *testing.T) {
	o, h, k := root(t)
	h2 := gen(3)
	d, err := Derive(k, h.priv, h2.pub, LimitRung(P1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Derive(d, h2.priv, gen(4).pub, LimitRung(P3)); err != nil {
		t.Fatalf("raise: %v", err)
	}
	e := Extend(d, h2.priv, Link{Caveats: []Caveat{LimitRung(P0)}, Holder: gen(4).pub})
	if _, err := Chain(e, []PublicKey{o.pk}); !errors.Is(err, ErrLoosens) {
		t.Fatalf("lower: %v", err)
	}
	for _, bad := range []Rung{-1, P4 + 1} {
		e := Extend(k, h.priv, Link{Caveats: []Caveat{LimitRung(bad)}, Holder: gen(4).pub})
		if _, err := Chain(e, []PublicKey{o.pk}); !errors.Is(err, ErrMalformed) {
			t.Fatalf("rung %d: %v", bad, err)
		}
	}
	lo, _ := Fold([]Caveat{LimitRung(P1)})
	hi, _ := Fold([]Caveat{LimitRung(P3)})
	if !hi.Within(lo) || lo.Within(hi) {
		t.Fatal("within: a lower rung is wider")
	}
}

// A voice check can lower an event's rung, never raise it (D-153).
func TestVoiceOnlyLowers(t *testing.T) {
	for r := P0; r <= P4; r++ {
		for heard := P0; heard <= P4; heard++ {
			if got := Lower(r, heard); got != min(r, heard) {
				t.Fatalf("Lower(P%d, P%d) = P%d", r, heard, got)
			}
		}
	}
}
