package recovery

// REQ: REC-4, CH-9

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// pageParts are every part the page offers since WIFI-del-a2: all but
// Wi-Fi (CH-9, D-178). Since WIFI-del-e they are every part there is.
var pageParts = AllParts

// WIFI-del-a2 (#3234, Security finding 1 on #3340): the page offers no
// Wi-Fi part, so a box whose rotation mark is unreadable, which owes
// every part, still finishes a rotation of the page's parts, and the mark
// clears so Backup resumes. It catches a vault that keeps owing Wi-Fi and
// so refuses every rotation the page can send.
func TestAnUnreadableMarkFinishesWithoutWiFi(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Put(RotationName, KindRotation, []byte("garbage-not-json-at-all")))
	if _, err := x.rotate(pageParts, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); err != nil {
		t.Fatalf("a rotation of the page's parts: %v", err)
	}
	if parts, ok := RotationUnfinished(x.b); ok {
		t.Fatalf("still owed: %v", parts)
	}
}

// An unfinished rotation from before WIFI-del-a2 that included Wi-Fi is
// finished by a rotation of its other parts, and the mark clears.
func TestAnOwedWiFiPartIsSettledByAnyRotation(t *testing.T) {
	x := newBox(t)
	must(t, markRotation(x.b, []Part{partWiFi, PartSetup}, false, t0))
	if _, err := x.rotate([]Part{PartSetup}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); err != nil {
		t.Fatalf("a rotation of the owed part but Wi-Fi: %v", err)
	}
	if parts, ok := RotationUnfinished(x.b); ok {
		t.Fatalf("still owed: %v", parts)
	}
	var buf bytes.Buffer
	must(t, Backup(x.b, x.roots(), &buf, t0))
}

// REQ: REC-4, CH-9
//
// WIFI-del-e (#3365): the card has no Wi-Fi part. AllParts has none,
// BeginRotate refuses "wifi" as an unknown part, and a mark from before
// WIFI-del-a2 that owes it never reports it: owing only Wi-Fi is owing
// nothing, so Backup is not held by it. It catches a rotation that still
// asks for, or waits on, a Wi-Fi password no device uses.
func TestRotationHasNoWiFiPart(t *testing.T) {
	for _, q := range AllParts {
		if q == "wifi" {
			t.Fatal("AllParts still has a Wi-Fi part")
		}
	}
	x := newBox(t)
	if _, err := BeginRotate(x.b, []Part{"wifi"}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}, t0); err == nil {
		t.Fatal("a Wi-Fi rotation was begun")
	}
	must(t, markRotation(x.b, []Part{partWiFi, PartGrid}, false, t0))
	if parts, ok := RotationUnfinished(x.b); !ok || len(parts) != 1 || parts[0] != PartGrid {
		t.Fatalf("owed %v %v, want [grid]", parts, ok)
	}
	y := newBox(t)
	must(t, markRotation(y.b, []Part{partWiFi}, false, t0))
	if parts, ok := RotationUnfinished(y.b); ok {
		t.Fatalf("a mark owing only Wi-Fi reports %v", parts)
	}
	var buf bytes.Buffer
	if err := Backup(y.b, y.roots(), &buf, t0); errors.Is(err, ErrRotationUnfinished) {
		t.Fatal("a mark owing only Wi-Fi holds Backup")
	}
}

// REQ: HW-1
//
// A card stored before WIFI-del-e carries the Wi-Fi name and password. It
// still decodes (the strict decode would otherwise lock the box out of
// its own card), the Wi-Fi is dropped, and a newly encoded card has none.
func TestAStoredCardWithWiFiStillDecodes(t *testing.T) {
	old := []byte(`{"WiFiName":"SYNTH-OLD1","WiFiPassword":"SYNT-HETI-COLD-CARD","SetupSecret":"SYNTHETIC-SETUP","SetupCode":"SYNT-CODE","GridSeed":"AQID"}`)
	c, err := DecodeCard(old)
	if err != nil {
		t.Fatalf("an old stored card: %v", err)
	}
	if c.SetupSecret != "SYNTHETIC-SETUP" || c.SetupCode != "SYNT-CODE" || !bytes.Equal(c.GridSeed, []byte{1, 2, 3}) {
		t.Fatalf("old card decoded as %#v", c.SetupSecret)
	}
	enc, err := EncodeCard(c)
	must(t, err)
	var fields map[string]any
	must(t, json.Unmarshal(enc, &fields))
	for _, k := range []string{"WiFiName", "WiFiPassword"} {
		if _, ok := fields[k]; ok {
			t.Fatalf("a new stored card carries %s", k)
		}
	}
	if bytes.Contains(enc, []byte("SYNT-HETI-COLD-CARD")) {
		t.Fatal("re-encoding kept the old Wi-Fi password")
	}
	// A box whose vault holds such a card still loads it and rotates.
	x := newBox(t)
	must(t, x.b.V.Put(CardName, KindCard, []byte(`{"WiFiName":"SYNTH-OLD1","WiFiPassword":"SYNT-HETI-COLD-CARD","SetupSecret":"`+x.card.SetupSecret+`","SetupCode":"`+x.card.SetupCode+`","GridSeed":null}`)))
	if _, err := x.b.LoadCard(); err != nil {
		t.Fatalf("load an old card: %v", err)
	}
	if _, err := x.rotate([]Part{PartGrid}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); err != nil {
		t.Fatalf("rotate from an old card: %v", err)
	}
}
