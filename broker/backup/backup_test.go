package backup

// REQ: BAK-1

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

// readAll opens a content object and reads every section.
func readAll(t *testing.T, obj, rk []byte) (Manifest, map[string][]byte, []byte) {
	t.Helper()
	m, secs, err := Open(bytes.NewReader(obj), rk)
	must(t, err)
	got := map[string][]byte{}
	var plain []byte
	for {
		s, r, err := secs.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		must(t, err)
		b, err := io.ReadAll(r)
		must(t, err)
		got[s.Name], plain = b, append(plain, b...)
	}
	return m, got, plain
}

func TestManifestCarriesPageCAAndEdgeOnly(t *testing.T) {
	r := newRig(t)
	sub := r.open()
	r.seal(sub, "hello")
	rcp := recipient(t, rk1)
	in := r.input(rcp)
	tg := &MemTarget{}
	rec, obj := r.backup(rcp, tg)

	m, secs, plain := readAll(t, obj, rk1)
	if string(m.PageCA) != "page-ca-canary" || string(m.EdgeKey) != "edge-key-canary" ||
		!reflect.DeepEqual(m.RevokedEdge, in.RevokedEdge) {
		t.Fatalf("manifest lost the page CA, edge key or revoked record: %+v", m)
	}
	if m.BackupID != rec.BackupID || m.Recipient != rcp.ID() || m.Created != in.Created || m.Version != 1 {
		t.Fatalf("manifest header fields: %+v", m)
	}
	if !bytes.Equal(secs["log"], r.log.B) || len(m.Sections) != 2 || m.Sections[1].Name != "content/mail" {
		t.Fatalf("sections: %+v", m.Sections)
	}
	if rec.ContentSum != sumHex(obj) {
		t.Fatal("the record's content sum is not the object's")
	}
	// No kernel log key and no holder key anywhere in what opens.
	full, err := openBytes(obj, rk1, KindContent)
	must(t, err)
	tobj, err := tg.GetTable(rec.BackupID, rec.Generation)
	must(t, err)
	tb, err := openBytes(tobj, rk1, KindKeyTable)
	must(t, err)
	for name, secret := range map[string][]byte{"log key": logKeyCanary[:], "holder key": r.holder} {
		for _, form := range forms(secret) {
			if bytes.Contains(full, form) || bytes.Contains(plain, form) || bytes.Contains(tb, form) {
				t.Errorf("the %s is in the backup", name)
			}
		}
	}

	// Sections outside log and content/<store> are refused.
	for _, bad := range [][]string{{"keys"}, {"content/"}, {"content/key-table"}, {"content/../x"}, {"content/Mail"},
		{"log", "log"}, {"holder"}, {"content/a/b"}} {
		in := r.input(rcp)
		in.Sections = nil
		for _, n := range bad {
			in.Sections = append(in.Sections, src(n, []byte("x")))
		}
		if _, err := Write(io.Discard, &MemTarget{}, in); !errors.Is(err, ErrSection) {
			t.Errorf("sections %q: %v, want ErrSection", bad, err)
		}
	}
	// A section that changes between the hash and the copy is refused.
	n := 0
	in = r.input(rcp)
	in.Sections = []Source{{Name: "log", Open: func() (io.ReadCloser, error) {
		n++
		return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{byte(n)}, 10))), nil
	}}}
	if _, err := Write(io.Discard, &MemTarget{}, in); !errors.Is(err, ErrChanged) {
		t.Errorf("a changing section: %v, want ErrChanged", err)
	}
}
