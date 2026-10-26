package backup

// REQ: BAK-1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
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

	// Sections outside log and content/<store> are refused, as is a store
	// name the kernel refuses.
	for _, bad := range [][]string{{"keys"}, {"content/"}, {"content/key-table"}, {"log", "log"}, {"holder"},
		{"content/" + strings.Repeat("a", 65)}, {"content/a\x01b"}, {"content/a\u202eb"}, {"content/\xff"}} {
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

// Every store name the kernel takes is a section name, so no store makes
// Write refuse the backup.
func TestSectionNamesMatchTheKernelsStoreNames(t *testing.T) {
	r := newRig(t)
	rcp := recipient(t, rk1)
	for _, store := range []string{"mail", "Mail", "post box", "a/b", "..", "Ünïcode", strings.Repeat("a", 64)} {
		if !kernel.ValidStore(store) {
			t.Fatalf("fixture: the kernel refuses %q", store)
		}
		in := r.input(rcp)
		in.Sections = []Source{src("log", []byte("l")), src("content/"+store, []byte("x"))}
		var buf bytes.Buffer
		if _, err := Write(&buf, &MemTarget{}, in); err != nil {
			t.Errorf("store %q: %v", store, err)
			continue
		}
		if _, got, _ := readAll(t, buf.Bytes(), rk1); string(got["content/"+store]) != "x" {
			t.Errorf("store %q does not read back", store)
		}
	}
	for _, store := range []string{"", kernel.KeyTable, strings.Repeat("a", 65), "a\nb", "a\u202eb"} {
		if validSection("content/"+store) != kernel.ValidStore(store) {
			t.Errorf("store %q: section %v, kernel %v", store, validSection("content/"+store), kernel.ValidStore(store))
		}
	}
}

// contentObject seals a content object white-box: m's sections are
// followed by data and then trailing, whatever m says.
func contentObject(t *testing.T, rcp Recipient, gen uint64, m Manifest, data, trailing []byte) []byte {
	t.Helper()
	id, err := parseID(m.BackupID)
	must(t, err)
	mb, err := json.Marshal(m)
	must(t, err)
	body := binary.BigEndian.AppendUint32(nil, uint32(len(mb)))
	body = append(append(append(body, mb...), data...), trailing...)
	return sealBytes(t, rcp, KindContent, id, gen, body)
}

func manifestFor(rcp Recipient, secs ...Section) Manifest {
	return Manifest{Version: version, BackupID: strings.Repeat("ab", idLen), Recipient: rcp.ID(), Sections: secs}
}

func section(name string, b []byte) Section {
	return Section{Name: name, Length: int64(len(b)), SHA256: sumHex(b)}
}

func TestASectionErrorSticks(t *testing.T) {
	rcp := recipient(t, rk1)
	t.Run("wrong sum", func(t *testing.T) {
		bad := section("log", []byte("logged"))
		bad.SHA256 = sumHex([]byte("other!"))
		obj := contentObject(t, rcp, 0, manifestFor(rcp, bad), []byte("logged"), nil)
		_, secs, err := Open(bytes.NewReader(obj), rk1)
		must(t, err)
		_, r, err := secs.Next()
		must(t, err)
		if _, err := io.ReadAll(r); !errors.Is(err, ErrSum) {
			t.Fatalf("read: %v, want ErrSum", err)
		}
		// The caller drops that error: every later Read and Next still
		// says ErrSum, never io.EOF.
		if _, err := r.Read(make([]byte, 1)); !errors.Is(err, ErrSum) {
			t.Fatalf("second read: %v, want ErrSum", err)
		}
		for range 2 {
			if _, _, err := secs.Next(); !errors.Is(err, ErrSum) {
				t.Fatalf("next: %v, want ErrSum", err)
			}
		}
	})
	t.Run("wrong sum, reader never read", func(t *testing.T) {
		bad := section("log", []byte("logged"))
		bad.SHA256 = sumHex(nil)
		obj := contentObject(t, rcp, 0, manifestFor(rcp, bad), []byte("logged"), nil)
		_, secs, err := Open(bytes.NewReader(obj), rk1)
		must(t, err)
		_, _, err = secs.Next()
		must(t, err)
		for range 2 {
			if _, _, err := secs.Next(); !errors.Is(err, ErrSum) {
				t.Fatalf("next: %v, want ErrSum", err)
			}
		}
	})
	t.Run("empty section, wrong sum", func(t *testing.T) {
		bad := section("log", nil)
		bad.SHA256 = sumHex([]byte("x"))
		obj := contentObject(t, rcp, 0, manifestFor(rcp, bad), nil, nil)
		_, secs, err := Open(bytes.NewReader(obj), rk1)
		must(t, err)
		for range 2 {
			if _, _, err := secs.Next(); !errors.Is(err, ErrSum) {
				t.Fatalf("next: %v, want ErrSum", err)
			}
		}
	})
}

func TestOpenRefusesTrailingBytesAndATableGeneration(t *testing.T) {
	rcp := recipient(t, rk1)
	m := manifestFor(rcp, section("log", []byte("logged")))
	// The control: the same object, well formed, reads to io.EOF.
	ok := contentObject(t, rcp, 0, m, []byte("logged"), nil)
	if _, got, _ := readAll(t, ok, rk1); string(got["log"]) != "logged" {
		t.Fatalf("control: %q", got["log"])
	}

	_, secs, err := Open(bytes.NewReader(contentObject(t, rcp, 0, m, []byte("logged"), []byte{0})), rk1)
	must(t, err)
	_, r, err := secs.Next()
	must(t, err)
	_, err = io.ReadAll(r)
	must(t, err)
	for range 2 {
		if _, _, err := secs.Next(); !errors.Is(err, ErrSum) {
			t.Fatalf("a byte after the last section: %v, want ErrSum", err)
		}
	}

	// A content object is generation 0; any other is refused.
	for _, gen := range []uint64{1, firstGeneration + 1} {
		if _, _, err := Open(bytes.NewReader(contentObject(t, rcp, gen, m, []byte("logged"), nil)), rk1); !errors.Is(err, ErrHeader) {
			t.Errorf("generation %d: %v, want ErrHeader", gen, err)
		}
	}
}
