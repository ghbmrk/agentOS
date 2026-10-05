package recovery

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: REC-4, REC-1

// After the recovery key changes, the box names where older backups are,
// and deletes the reachable ones only on a tier-4 answer, once a backup
// under the new key is verified.
func TestOlderBackupsAreNamedAndDeletedOnlyWithApproval(t *testing.T) {
	x := newBox(t)
	logged := func(dest string, at time.Time) {
		t.Helper()
		var buf bytes.Buffer
		sum, err := BackupSum(x.b, x.roots(), &buf, at)
		must(t, err)
		e, err := RecordBackup(x.b, dest, at, sum, bytes.NewReader(buf.Bytes()))
		must(t, err)
		if !e.Verified {
			t.Fatal("an intact read-back is not verified")
		}
	}
	logged("USB stick A", t0.Add(-48*time.Hour))
	logged("Home NAS", t0.Add(-24*time.Hour))
	// A read-back that differs is not verified.
	if e, _ := RecordBackup(x.b, "USB stick A", t0.Add(-time.Hour), make([]byte, 32), strings.NewReader("x")); e.Verified {
		t.Fatal("a damaged read-back is verified")
	}
	if n, _ := OldBackupsNote(x.b); n != "" {
		t.Fatalf("note before any key change: %q", n)
	}

	p, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Recovery: x.rk}, nil, testGen, nil, t0)
	must(t, err)
	_, err = p.Commit(x.b, p.answer, t0)
	must(t, err)
	want := "Backups made before 2026-10-05 still open with your old card. Delete them from Home NAS and USB stick A once the new backup is done."
	if n, _ := OldBackupsNote(x.b); n != want {
		t.Fatalf("note: %q", n)
	}
	// The next digest carries it once.
	if l, _ := DigestLine(x.b); l != want {
		t.Fatalf("digest: %q", l)
	}
	if l, _ := DigestLine(x.b); l != "" {
		t.Fatalf("digest repeated: %q", l)
	}
	reach := func(d string) bool { return d == "USB stick A" }
	// No offer before a verified backup under the new key.
	if _, ok, _ := OfferDelete(x.b, reach); ok {
		t.Fatal("offered before the new backup")
	}
	logged("USB stick A", t0.Add(time.Hour))
	off, ok, err := OfferDelete(x.b, reach)
	must(t, err)
	if !ok || off.Text != "Delete the 2 older backups at USB stick A now?" || len(off.Elsewhere) != 1 || off.Elsewhere[0] != "Home NAS" {
		t.Fatalf("offer: %+v %v", off, ok)
	}
	// Declining keeps them and repeats the digest line once.
	must(t, DeclineDelete(x.b))
	if l, _ := DigestLine(x.b); l != want {
		t.Fatalf("digest after decline: %q", l)
	}
	// Approval is tier-4.
	for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: x.rk}} {
		if _, err := ApproveDelete(x.b, off, a); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("auth %+v: %v", a, err)
		}
	}
	gone, err := ApproveDelete(x.b, off, Auth{Code: true, Local: true})
	must(t, err)
	if len(gone) != 2 {
		t.Fatalf("deleted %d", len(gone))
	}
	// The new backup stays; the unreachable one stays named.
	if n, _ := OldBackupsNote(x.b); !strings.Contains(n, "Delete them from Home NAS once") {
		t.Fatalf("after delete: %q", n)
	}
	if _, ok, _ := OfferDelete(x.b, reach); ok {
		t.Fatal("offered again with nothing reachable")
	}
}
