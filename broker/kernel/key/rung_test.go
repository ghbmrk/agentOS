package key

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// REQ: KEY-2, CH-3

// ch3Rows names each CH-3 row's act, so its floor is worth.go's (D-307,
// D-311) and the two CH-3 tables in this package cannot drift.
var ch3Rows = map[string]Act{
	"STOP (pause all dispatch)":                                                                                       ActStop,
	"Task chat, STATUS":                                                                                               ActChat,
	"Approve a low-risk irreversible effect (CH-10)":                                                                  ActApproveLow,
	"Approve a high-risk irreversible effect (CH-10)":                                                                 ActApproveHigh,
	"Unlock on an unknown host (STO-2)":                                                                               ActUnlock,
	"New key (device keys except as the rows below say), raise budget, adopt a release":                               ActGrant,
	"Turn the computer-use retry back on for a site or all sites (CLK-5)":                                             ActRetryOn,
	"Connect devices or a hub from a connection plan":                                                                 ActDeviceConnect,
	"Connect a verified device that needs no secret, read only (DEV-10)":                                              ActDeviceReadOnly,
	"Key `actuate` or `present` on, or cut off from its vendor cloud, a connected device not marked safety or access": ActDeviceKeyLow,
	"Key `actuate-physical` on a connected device":                                                                    ActDeviceKeySafety,
	"Physical action in the unsafe direction, or a value outside `actuate` bounds that":                               ActPhysicalUnsafe,
	"Start a reverse-engineering task (DEV-12)":                                                                       ActReverseEngineer,
	"Write firmware or software to a device (DEV-12)":                                                                 ActFirmwareWrite,
}

// spelled is how CH-3's proof column names a rung first.
var spelled = map[string]Proof{"P0": P0, "P1": P1, "P2": P2, "P3": P3, "P4": P4,
	"P3 with local confirmation": P3Local, "Local confirmation": P3Local}

// TestCH3RowsAreTheFloor reads CH-3's table from SPEC.md: every row is a
// case here, at worth.go's floor, which is the rung its proof names first
// (a row naming none is given on the owner page, P3), and each holds as a rung
// caveat: an owner event at that rung or above passes, one below is refused.
func TestCH3RowsAreTheFloor(t *testing.T) {
	spec, err := os.ReadFile("../../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(spec)
	s = s[strings.Index(s, "- **CH-3** "):]
	s = s[:strings.Index(s, "\n- **CH-4** ")]
	first := regexp.MustCompile(`\bP[0-4]( with local confirmation)?\b|^ Local confirmation`)
	rows := 0
	for _, line := range strings.Split(s, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) != 4 || cells[1] == " Action " || strings.HasPrefix(cells[1], "---") {
			continue
		}
		action, proof := strings.TrimSpace(cells[1]), cells[2]
		want, ok := P0, false
		for prefix, a := range ch3Rows {
			if strings.HasPrefix(action, prefix) {
				want, ok = floor[a].proof, true
			}
		}
		if !ok {
			t.Errorf("CH-3 row %q is no case here", action)
			continue
		}
		rows++
		if m := strings.TrimSpace(first.FindString(proof)); m != "" && spelled[m] != want {
			t.Errorf("%q: SPEC names %s first, the floor %v", action, m, want)
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
				t.Errorf("%q at %v: %v", action, r, got)
			}
		}
	}
	if rows != len(ch3Rows) {
		t.Errorf("SPEC's CH-3 has %d rows, the cases %d", rows, len(ch3Rows))
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
	if _, err := Derive(d, h2.priv, gen(4).pub, LimitRung(P4)); err != nil {
		t.Fatalf("raise: %v", err)
	}
	e := Extend(d, h2.priv, Link{Caveats: []Caveat{LimitRung(P0)}, Holder: gen(4).pub})
	if _, err := Chain(e, []PublicKey{o.pk}); !errors.Is(err, ErrLoosens) {
		t.Fatalf("lower: %v", err)
	}
	for _, bad := range []int64{-1, int64(P4) + 1} {
		e := Extend(k, h.priv, Link{Caveats: []Caveat{{Kind: KRung, N: bad}}, Holder: gen(4).pub})
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
				t.Fatalf("Lower(%v, %v) = %v", r, heard, got)
			}
		}
	}
}

// A refusal names rungs as CH-3 does (P3Local, not its ordinal).
func TestRungNames(t *testing.T) {
	got := fmt.Sprint(P0, P1, P2, P3, P3Local, P4, PRecovery, PRecovery+1)
	if got != "P0 P1 P2 P3 P3Local P4 PRecovery Proof(7)" {
		t.Fatal(got)
	}
	o, h, k := root(t)
	d, _ := Derive(k, h.priv, gen(3).pub, LimitRung(P3Local))
	st := step(Trash)
	st.Rung = P3
	if rf := verified(t, d, o, gen(3)).Authorize(st, ctx(1, nil)); rf == nil || rf.Detail != "P3, the key asks P3Local" {
		t.Fatalf("%v", rf)
	}
}
