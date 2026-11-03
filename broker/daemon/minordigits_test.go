package daemon

// REQ: CH-10

import (
	"encoding/xml"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"testing"
)

// listOne is ISO 4217 List One as published on 2026-01-01, vendored
// unchanged: SIX's list-one.xml, as the iso4217 1.16.20260101 wheel on PyPI
// ships it (iso4217/table.xml, sha256 838dfb99…e291c9). Replace it with the
// next published list and update minorDigits in the same change.
const listOne, listOneDate = "testdata/iso4217-list-one-2026-01-01.xml", "2026-01-01"

// notHeld are List One codes with a 0, 2 or 3 digit minor unit that
// minorDigits leaves out, each with its reason; a code here that is not
// in the list, or that minorDigits holds, fails.
var notHeld = map[string]string{
	"XAD": "Arab Accounting Dinar: the Arab Monetary Fund's unit of account, not money a household holds, like XDR",
}

// listOneDigits reads List One: each non-fund code whose minor unit is 0,
// 2 or 3 digits, at its digits, less notHeld. Funds, metals, drawing
// rights, test codes and 4-digit or N.A. units are out, as minorDigits'
// comment says.
func listOneDigits(t *testing.T) map[string]int {
	t.Helper()
	b, err := os.ReadFile(listOne)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Published string `xml:"Pblshd,attr"`
		Entries   []struct {
			Name struct {
				IsFund string `xml:"IsFund,attr"`
			} `xml:"CcyNm"`
			Code  string `xml:"Ccy"`
			Minor string `xml:"CcyMnrUnts"`
		} `xml:"CcyTbl>CcyNtry"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Published != listOneDate || len(doc.Entries) < 200 {
		t.Fatalf("%s: published %q with %d entries, want %s", listOne, doc.Published, len(doc.Entries), listOneDate)
	}
	want := map[string]int{}
	for _, e := range doc.Entries {
		d, err := strconv.Atoi(e.Minor)
		if e.Code == "" || e.Name.IsFund == "true" || err != nil || d != 0 && d != 2 && d != 3 {
			continue
		}
		if old, dup := want[e.Code]; dup && old != d {
			t.Fatalf("%s is listed at %d and %d digits", e.Code, old, d)
		}
		want[e.Code] = d
	}
	for c := range notHeld {
		if _, ok := want[c]; !ok {
			t.Errorf("notHeld names %s, which List One %s does not list with a minor unit: delete it", c, listOneDate)
		}
		delete(want, c)
	}
	return want
}

// digitsDiff is each way have differs from want.
func digitsDiff(have, want map[string]int) []string {
	var bad []string
	for _, c := range slices.Sorted(maps.Keys(want)) {
		if got, ok := have[c]; !ok {
			bad = append(bad, fmt.Sprintf("lacks %s (%d digits in List One %s)", c, want[c], listOneDate))
		} else if got != want[c] {
			bad = append(bad, fmt.Sprintf("has %s at %d digits, List One %s at %d", c, got, listOneDate, want[c]))
		}
	}
	for _, c := range slices.Sorted(maps.Keys(have)) {
		if _, ok := want[c]; !ok {
			why := "which List One " + listOneDate + " does not list as a currency in circulation"
			if r, ok := notHeld[c]; ok {
				why = "which notHeld leaves out (" + r + ")"
			}
			bad = append(bad, "holds "+c+", "+why)
		}
	}
	return bad
}

// minorDigits is List One's minor units for every currency in circulation
// (#4910, #3141), exactly, and a loosened copy is not: one with a code at
// the wrong scale, one keeping a withdrawn code (ANG, BGN), one missing a
// new code (XCG), one holding a notHeld code (positive controls). Catches
// an amount read at the wrong scale, and a list left behind List One.
func TestMinorDigitsFollowListOne(t *testing.T) {
	want := listOneDigits(t)
	for _, b := range digitsDiff(minorDigits, want) {
		t.Errorf("minorDigits %s", b)
	}
	for name, edit := range map[string]func(m map[string]int){
		"JPY at 2":      func(m map[string]int) { m["JPY"] = 2 },
		"KWD at 2":      func(m map[string]int) { m["KWD"] = 2 },
		"ANG kept":      func(m map[string]int) { m["ANG"] = 2 },
		"BGN kept":      func(m map[string]int) { m["BGN"] = 2 },
		"XCG missing":   func(m map[string]int) { delete(m, "XCG") },
		"XAD held":      func(m map[string]int) { m["XAD"] = 2 },
		"CLF (4) held":  func(m map[string]int) { m["CLF"] = 4 },
		"fund USN held": func(m map[string]int) { m["USN"] = 2 },
	} {
		m := maps.Clone(minorDigits)
		edit(m)
		if len(digitsDiff(m, want)) == 0 {
			t.Errorf("a copy of minorDigits with %s passes", name)
		}
	}
}
