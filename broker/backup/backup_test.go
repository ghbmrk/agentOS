package backup

// REQ: BAK-1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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

func TestManifestCarriesPageCAOnly(t *testing.T) {
	r := newRig(t)
	sub := r.open()
	r.seal(sub, "hello")
	rcp := recipient(t, rk1)
	in := r.input(rcp)
	tg := &MemTarget{}
	rec, obj := r.backup(rcp, tg)

	m, secs, plain := readAll(t, obj, rk1)
	if string(m.PageCA) != "page-ca-canary" || rec.PageCA != "CAFE F00D" {
		t.Fatalf("manifest or record lost the page CA: %+v %q", m, rec.PageCA)
	}
	if m.BackupID != rec.BackupID || m.Recipient != rcp.ID() || m.Created != in.Created || m.Version != manifestVersion {
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

// REQ: BAK-1, HW-15
// MIG-4-recovery-f1 decision 4: the edge key and its revocations are log
// entries, so the manifest has no copy of them that could disagree with
// the log. The new version has neither field and refuses one that names
// them; a version 1 backup, which had both, still opens, and they are
// dropped unread.
func TestManifestHasNoEdgeFields(t *testing.T) {
	r := newRig(t)
	sub := r.open()
	r.seal(sub, "hello")
	rcp := recipient(t, rk1)
	rec, obj := r.backup(rcp, &MemTarget{})
	full, err := openBytes(obj, rk1, KindContent)
	must(t, err)
	n := binary.BigEndian.Uint32(full)
	var raw map[string]json.RawMessage
	must(t, json.Unmarshal(full[4:4+n], &raw))
	for _, f := range []string{"edge_key", "revoked_edge"} {
		if _, ok := raw[f]; ok {
			t.Errorf("the manifest has %s", f)
		}
	}
	if string(raw["version"]) != "2" {
		t.Fatalf("manifest version %s, want 2", raw["version"])
	}

	// craft seals a manifest of version v, with the edge fields when edge
	// is set, before the rig's sections, as Write would.
	in := r.input(rcp)
	craft := func(v int, edge bool) []byte {
		id, err := parseID(rec.BackupID)
		must(t, err)
		m := map[string]any{"version": v, "backup_id": rec.BackupID, "created": in.Created,
			"recipient": rcp.ID(), "page_ca": in.PageCA}
		if edge {
			m["edge_key"], m["revoked_edge"] = []byte("edge-key-canary"), [][]byte{[]byte("revoked-fp-1")}
		}
		var secs []Section
		var body []byte
		for _, s := range in.Sections {
			var b bytes.Buffer
			n, sum, err := hashSource(s, &b)
			must(t, err)
			secs, body = append(secs, Section{Name: s.Name, Length: n, SHA256: sum}), append(body, b.Bytes()...)
		}
		m["sections"] = secs
		mb, err := json.Marshal(m)
		must(t, err)
		var out bytes.Buffer
		sw, err := sealTo(&out, rcp, header{kind: KindContent, backupID: id})
		must(t, err)
		_, err = sw.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(mb))), append(mb, body...)...))
		must(t, err)
		must(t, sw.Close())
		return out.Bytes()
	}
	old, got, _ := readAll(t, craft(1, true), rk1)
	if old.Version != 1 || string(old.PageCA) != "page-ca-canary" || !bytes.Equal(got["log"], r.log.B) {
		t.Fatalf("a version 1 backup does not open: %+v", old)
	}
	readAll(t, craft(1, false), rk1) // version 1 without the fields opens too
	for name, obj := range map[string][]byte{"v2 with edge fields": craft(2, true), "v3": craft(3, false)} {
		if _, _, err := Open(bytes.NewReader(obj), rk1); err == nil {
			t.Errorf("%s opened", name)
		}
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): a source that fails to open or to read fails
// the backup with its own error, on the hash pass and on the copy pass;
// every reader Write opens is closed; and a recipient whose keys do not
// load is refused before any source is opened.
func TestWriteReportsEverySourceFailure(t *testing.T) {
	r := newRig(t)
	r.seal(r.open(), "hello")
	rcp := recipient(t, rk1)
	// A sealer stands in for each reader's Close: a Write after its Close
	// fails, so it shows whether Write closed the reader.
	type readCloser struct {
		io.Reader
		io.Closer
	}
	var closers []io.WriteCloser
	opens := 0
	// source's n'th Open (from 1) fails when failOpen is n, and its reader
	// fails after three bytes when failRead is n.
	source := func(failOpen, failRead int) Source {
		calls := 0
		return Source{Name: "log", Open: func() (io.ReadCloser, error) {
			calls++
			opens++
			if calls == failOpen {
				return nil, errDown
			}
			var rd io.Reader = bytes.NewReader([]byte("logged"))
			if calls == failRead {
				pr, pw := io.Pipe()
				pw.CloseWithError(errDown)
				rd = io.MultiReader(bytes.NewReader([]byte("log")), pr)
			}
			c, err := sealTo(io.Discard, rcp, header{kind: KindContent})
			must(t, err)
			closers = append(closers, c)
			return readCloser{rd, c}, nil
		}}
	}
	write := func(rcp Recipient, s Source) (*MemTarget, []byte, error) {
		in := r.input(rcp)
		in.Sections = []Source{s}
		tg := &MemTarget{}
		var buf bytes.Buffer
		_, err := Write(&buf, tg, in)
		return tg, buf.Bytes(), err
	}
	allClosed := func(name string) {
		t.Helper()
		for i, c := range closers {
			if _, err := c.Write(nil); err == nil {
				t.Errorf("%s: reader %d was not closed", name, i)
			}
		}
		closers = nil
	}

	_, obj, err := write(rcp, source(0, 0))
	must(t, err)
	if _, got, _ := readAll(t, obj, rk1); string(got["log"]) != "logged" {
		t.Fatalf("control: %q", got["log"])
	}
	allClosed("control")
	for _, c := range []struct {
		name               string
		failOpen, failRead int
	}{{"open on the hash pass", 1, 0}, {"open on the copy pass", 2, 0},
		{"read on the hash pass", 0, 1}, {"read on the copy pass", 0, 2}} {
		tg, _, err := write(rcp, source(c.failOpen, c.failRead))
		if !errors.Is(err, errDown) {
			t.Errorf("%s: %v, want the source's error", c.name, err)
		}
		if len(tg.m) != 0 {
			t.Errorf("%s: a key table was put", c.name)
		}
		allClosed(c.name)
	}

	// A recipient whose keys do not load is refused before any source is
	// read; one whose X25519 key is a low-order point loads, and fails
	// the key agreement, before a byte is written.
	for name, bad := range map[string]Recipient{
		"short X25519 key": {X: rcp.X[:31], EK: rcp.EK},
		"short ML-KEM key": {X: rcp.X, EK: rcp.EK[:len(rcp.EK)-1]},
	} {
		opens = 0
		if _, _, err := write(bad, source(0, 0)); err == nil || opens != 0 {
			t.Errorf("%s: %v after %d opens, want an error before any", name, err, opens)
		}
	}
	tg, obj, err := write(Recipient{X: make([]byte, 32), EK: rcp.EK}, source(0, 0))
	if err == nil || len(obj) != 0 || len(tg.m) != 0 {
		t.Errorf("low-order X25519 key: %v, %d bytes written, %d tables", err, len(obj), len(tg.m))
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): a manifest of exactly 1 MiB is written and
// opens; one base64 step over it is refused by Write, and a length prefix
// over 1 MiB is refused by Open before it is read.
func TestTheManifestLimitIsOneMiBExactly(t *testing.T) {
	r := newRig(t)
	rcp := recipient(t, rk1)
	write := func(created int64, pageCA []byte) ([]byte, error) {
		in := r.input(rcp)
		in.Created, in.PageCA = created, pageCA
		var buf bytes.Buffer
		_, err := Write(&buf, &MemTarget{}, in)
		return buf.Bytes(), err
	}
	manifestLen := func(obj []byte) int {
		full, err := openBytes(obj, rk1, KindContent)
		must(t, err)
		return int(binary.BigEndian.Uint32(full))
	}
	// The page CA is base64 in the manifest, 4 bytes for every 3, so the
	// created time's digit count sets the length modulo 4.
	var created int64
	var pageCA []byte
	for c := int64(1); c <= 1000 && pageCA == nil; c *= 10 {
		obj, err := write(c, []byte{})
		must(t, err)
		if gap := maxManifest - manifestLen(obj); gap%4 == 0 {
			created, pageCA = c, make([]byte, gap/4*3)
		}
	}
	if pageCA == nil {
		t.Fatal("no created time gives a manifest of exactly 1 MiB")
	}
	obj, err := write(created, pageCA)
	must(t, err)
	if n := manifestLen(obj); n != maxManifest {
		t.Fatalf("manifest is %d bytes, want %d", n, maxManifest)
	}
	if m, _, _ := readAll(t, obj, rk1); len(m.PageCA) != len(pageCA) {
		t.Fatalf("a 1 MiB manifest does not read back: %d page CA bytes", len(m.PageCA))
	}
	if _, err := write(created, make([]byte, len(pageCA)+3)); err == nil {
		t.Error("Write took a manifest over 1 MiB")
	}

	var id [idLen]byte
	over := sealBytes(t, rcp, KindContent, id, 0, binary.BigEndian.AppendUint32(nil, maxManifest+1))
	if _, _, err := Open(bytes.NewReader(over), rk1); !errors.Is(err, ErrHeader) {
		t.Errorf("a length prefix over 1 MiB: %v, want ErrHeader", err)
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): Open reports each way a content object fails
// with its own error: another or a short recovery key, a manifest that is
// not JSON, a negative section length and a repeated section.
func TestOpenReportsEachBadObject(t *testing.T) {
	rcp := recipient(t, rk1)
	ok := contentObject(t, rcp, 0, manifestFor(rcp, section("log", []byte("logged"))), []byte("logged"), nil)
	if _, _, err := Open(bytes.NewReader(ok), rk2); !errors.Is(err, ErrOpen) {
		t.Errorf("another recovery key: %v, want ErrOpen", err)
	}
	if _, _, err := Open(bytes.NewReader(ok), rk1[:minRK-1]); !errors.Is(err, ErrShortKey) {
		t.Errorf("a short recovery key: %v, want ErrShortKey", err)
	}
	var id [idLen]byte
	notJSON := sealBytes(t, rcp, KindContent, id, 0, append(binary.BigEndian.AppendUint32(nil, 5), "{bad}"...))
	var syntax *json.SyntaxError
	if _, _, err := Open(bytes.NewReader(notJSON), rk1); !errors.As(err, &syntax) {
		t.Errorf("a manifest that is not JSON: %v, want its syntax error", err)
	}
	negative := section("log", nil)
	negative.Length = -1
	if _, _, err := Open(bytes.NewReader(contentObject(t, rcp, 0, manifestFor(rcp, negative), nil, nil)), rk1); !errors.Is(err, ErrHeader) {
		t.Errorf("a negative section length: %v, want ErrHeader", err)
	}
	mb, err := json.Marshal(manifestFor(rcp, section("log", nil)))
	must(t, err)
	mid, err := parseID(manifestFor(rcp).BackupID)
	must(t, err)
	trailing := append(binary.BigEndian.AppendUint32(nil, uint32(len(mb)+2)), append(mb, " x"...)...)
	if _, _, err := Open(bytes.NewReader(sealBytes(t, rcp, KindContent, mid, 0, trailing)), rk1); err == nil {
		t.Error("a manifest with a byte after its JSON value opened")
	}
	twice := manifestFor(rcp, section("log", nil), section("log", nil))
	if _, _, err := Open(bytes.NewReader(contentObject(t, rcp, 0, twice, nil, nil)), rk1); !errors.Is(err, ErrSection) {
		t.Errorf("a repeated section: %v, want ErrSection", err)
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): a section reader returns io.EOF with the read
// that ends its section, and once its section has ended it never reads the
// object again, so a fault after the section is reported by Next, not by
// the section that read back whole.
func TestASectionEndsWithItsLastRead(t *testing.T) {
	secs := &Sections{r: bytes.NewReader([]byte("logged")), list: []Section{section("log", []byte("logged"))}}
	_, rd, err := secs.Next()
	must(t, err)
	p := make([]byte, 64)
	if n, err := rd.Read(p); n != 6 || err != io.EOF {
		t.Errorf("the read that ends the section: %d, %v, want 6, io.EOF", n, err)
	}

	pr, pw := io.Pipe()
	pw.CloseWithError(errDown)
	secs = &Sections{r: pr, list: []Section{section("log", nil)}}
	_, rd, err = secs.Next()
	must(t, err)
	for range 2 {
		if n, err := rd.Read(p); n != 0 || err != io.EOF {
			t.Errorf("an ended section read the object: %d, %v, want 0, io.EOF", n, err)
		}
	}
	if _, _, err := secs.Next(); !errors.Is(err, errDown) {
		t.Errorf("next after the section: %v, want the object's error", err)
	}
}

// REQ: BAK-1
// MUT-backup-names (#5036): MemTarget refuses a second put of one
// generation and keeps the first, and an append-only one refuses a delete.
func TestMemTargetKeepsTheFirstPut(t *testing.T) {
	tg := &MemTarget{}
	must(t, tg.PutTable("id", 1, []byte("first")))
	if err := tg.PutTable("id", 1, []byte("second")); !errors.Is(err, ErrExists) {
		t.Errorf("second put: %v, want ErrExists", err)
	}
	if b, err := tg.GetTable("id", 1); err != nil || string(b) != "first" {
		t.Errorf("after a refused put: %q, %v, want the first", b, err)
	}
	tg.Append = true
	if err := tg.DeleteTable("id", 1); err == nil {
		t.Error("an append-only target deleted")
	}
	if b, err := tg.GetTable("id", 1); err != nil || string(b) != "first" {
		t.Errorf("after a refused delete: %q, %v, want the first", b, err)
	}
}
