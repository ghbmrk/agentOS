package recovery

// REQ: REC-4, CH-9

import (
	"bytes"
	"testing"
)

// pageParts are every part the page offers since WIFI-del-a2: all but
// Wi-Fi (CH-9, D-178).
var pageParts = []Part{PartSetup, PartPassphrase, PartGrid, PartRecovery}

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
	must(t, markRotation(x.b, []Part{PartWiFi, PartSetup}, false, t0))
	if _, err := x.rotate([]Part{PartSetup}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); err != nil {
		t.Fatalf("a rotation of the owed part but Wi-Fi: %v", err)
	}
	if parts, ok := RotationUnfinished(x.b); ok {
		t.Fatalf("still owed: %v", parts)
	}
	var buf bytes.Buffer
	must(t, Backup(x.b, x.roots(), &buf, t0))
}
