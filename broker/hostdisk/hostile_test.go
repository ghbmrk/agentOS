package hostdisk

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"testing"
)

// REQ: HW-8, HW-8a

// regpt edits the primary GPT header, fixes both CRCs over the entry array
// it then names, and destroys the backup, so only the edited copy counts.
func regpt(b []byte, sector int, edit func(h []byte)) []byte {
	b = append([]byte(nil), b...)
	h := b[sector : sector+92]
	edit(h)
	ss := uint64(sector)
	entLBA := binary.LittleEndian.Uint64(h[72:])
	n := uint64(binary.LittleEndian.Uint32(h[80:])) * uint64(binary.LittleEndian.Uint32(h[84:]))
	if off := entLBA * ss; off+n <= uint64(len(b)) && off+n >= off {
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(b[off:off+n]))
	}
	binary.LittleEndian.PutUint32(h[16:], 0)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
	copy(b[len(b)-sector:], make([]byte, sector))
	return b
}

// Security H3 on HOST-1a: the table is hostile input. A GPT with too many
// or oddly sized entries, or an entry array outside the disk, is
// unreadable; a partition past the end of the disk is not described.
func TestProbeBoundsHostileGPT(t *testing.T) {
	const sector = 512
	base := windowsLaptop(sector)
	put32 := func(off int, v uint32) func([]byte) {
		return func(h []byte) { binary.LittleEndian.PutUint32(h[off:], v) }
	}
	put64 := func(off int, v uint64) func([]byte) {
		return func(h []byte) { binary.LittleEndian.PutUint64(h[off:], v) }
	}
	for name, edit := range map[string]func([]byte){
		"129 entries":         put32(80, 129),
		"entry size 1024":     put32(84, 1024),
		"entry size 132":      put32(84, 132),
		"entry size 64":       put32(84, 64),
		"entries past end":    put64(72, 1<<40),
		"entries at LBA 0":    put64(72, 0),
		"entries LBA wraps":   put64(72, 1<<63),
		"header size 600":     put32(12, 600),
		"header in wrong LBA": put64(24, 7),
	} {
		img := regpt(base, sector, edit)
		rec := &recorder{r: bytes.NewReader(img)}
		d, err := Probe(rec, int64(len(img)), sector)
		if !errors.Is(err, ErrUnreadableTable) || d.Problem != ProblemTable || !d.NeedsSecondConfirm() {
			t.Errorf("%s: %v %+v", name, err, d)
		}
		checkReads(t, rec, int64(len(img)), sector)
	}
	// The edit helper itself keeps a valid table valid.
	if _, err := Probe(bytes.NewReader(regpt(base, sector, func([]byte) {})), int64(len(base)), sector); err != nil {
		t.Fatalf("control: %v", err)
	}

	// A partition reaching past the disk is described as far as the disk
	// goes, one starting past it or ending before it starts is left out,
	// and either way the disk is flagged partly unreadable, which needs
	// the second confirmation (L3 on #172).
	b := gptDisk(sector, 2048, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{
		{typ: tBasic, start: 64, n: 64, sig: SigNTFS},
		{typ: tBasic, start: 1000, n: 1 << 40},
		{typ: tBasic, start: 1 << 62, n: 4},
	})
	d := probeBytes(t, b, sector)
	if len(d.Partitions) != 2 || d.Partitions[1].Size != (2048-1000)*sector || d.Problem != ProblemPartial || !d.NeedsSecondConfirm() {
		t.Fatalf("%+v", d)
	}
	// The last sector is on the disk; one past it is not.
	for n, want := range map[int64]Problem{1048: ProblemNone, 1049: ProblemPartial} {
		b := gptDisk(sector, 2048, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{{typ: tBasic, start: 1000, n: n}})
		if d := probeBytes(t, b, sector); len(d.Partitions) != 1 || d.Partitions[0].Size != 1048*sector || d.Problem != want {
			t.Errorf("n=%d: %+v", n, d)
		}
	}
	b = regpt(gptDisk(sector, 2048, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{{typ: tBasic, start: 64, n: 64}}), sector, func([]byte) {})
	binary.LittleEndian.PutUint64(b[2*sector+40:], 63) // last before first
	b = regpt(b, sector, func([]byte) {})
	if d := probeBytes(t, b, sector); len(d.Partitions) != 0 || d.Problem != ProblemPartial {
		t.Errorf("inverted: %+v", d)
	}
}

// The checked multiply and the budgeted reader hold at their edges.
func TestProbeArithmeticAndBudget(t *testing.T) {
	for _, c := range []struct {
		a, b uint64
		ok   bool
	}{
		{1 << 31, 1 << 31, true},
		{1<<63 - 1, 1, true},
		{1 << 32, 1 << 31, false},
		{3, 1 << 62, false},
		{1 << 33, 1 << 33, false},
	} {
		if v, ok := mul(c.a, c.b); ok != c.ok || ok && uint64(v) != c.a*c.b {
			t.Errorf("mul(%d, %d) = %d, %v", c.a, c.b, v, ok)
		}
	}
	bud := &budget{r: bytes.NewReader(make([]byte, 100)), size: 100, left: 10}
	if err := bud.read(make([]byte, 10), 90); err != nil {
		t.Fatalf("within budget: %v", err)
	}
	if err := bud.read(make([]byte, 1), 0); !errors.Is(err, errBudget) {
		t.Errorf("past budget: %v", err)
	}
	bud.left = 1000
	for _, c := range [][2]int64{{-1, 1}, {91, 10}, {0, 101}, {100, 1}} {
		if err := bud.read(make([]byte, c[1]), c[0]); err == nil {
			t.Errorf("read %d at %d outside a 100-byte disk", c[1], c[0])
		}
	}
	if bud.left != 1000 {
		t.Errorf("refused reads spent budget: %d", bud.left)
	}
}

// failAt is a disk whose reads at or past off fail (a bad sector).
type failAt struct {
	r   io.ReaderAt
	off int64
}

func (f failAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.off {
		return 0, errors.New("medium error")
	}
	return f.r.ReadAt(p, off)
}

// A partition whose first bytes cannot be read is listed without a
// signature and flags the disk partly unreadable.
func TestProbeBadSectorInWindow(t *testing.T) {
	b := mbrDisk(4096, []tpart{
		{mbr: 0x07, start: 64, n: 1000, sig: SigNTFS},
		{mbr: 0x07, start: 2000, n: 1000, sig: SigBitLocker},
	})
	d, err := Probe(failAt{bytes.NewReader(b), 2000 * 512}, int64(len(b)), 512)
	if err != nil || len(d.Partitions) != 2 || d.Partitions[1].Signature != SigNone || d.Problem != ProblemPartial || !d.NeedsSecondConfirm() {
		t.Fatalf("%v %+v", err, d)
	}
}

// Two readings of a disk's start: the one the kernel uses is described,
// and the disk is flagged ambiguous, which needs the second confirmation
// (L3 on #172).
func TestProbeAmbiguousTables(t *testing.T) {
	// A volume boot record whose boot code also parses as an MBR.
	b := mbrDisk(4096, []tpart{{mbr: 0x07, start: 64, n: 1000, sig: SigNTFS}})
	writeSig(b, SigNTFS)
	d := probeBytes(t, b, 512)
	if d.Signature != SigNTFS || d.Table != TableMBR || len(d.Partitions) != 1 || d.Problem != ProblemAmbiguous || !d.NeedsSecondConfirm() {
		t.Errorf("volume and MBR: %+v", d)
	}
	// Ambiguity outranks a partition past the end: both need the second
	// confirmation, and ambiguity says more.
	b = mbrDisk(4096, []tpart{{mbr: 0x07, start: 64, n: 8000}})
	writeSig(b, SigNTFS)
	if d := probeBytes(t, b, 512); d.Problem != ProblemAmbiguous {
		t.Errorf("ambiguous and partial: %+v", d)
	}
	// A GPT whose protective MBR was wiped: nothing else, so the GPT.
	b = windowsLaptop(512)
	copy(b[446:510], make([]byte, 64))
	d = probeBytes(t, b, 512)
	if d.Table != TableGPT || len(d.Partitions) != 4 || d.Problem != ProblemAmbiguous || !d.HasBitLocker {
		t.Errorf("GPT without protective MBR: %+v", d)
	}
	// A stale GPT under a new MBR: the MBR, as the kernel reads it.
	b = windowsLaptop(512)
	b[446+4] = 0x07
	d = probeBytes(t, b, 512)
	if d.Table != TableMBR || len(d.Partitions) != 1 || d.Problem != ProblemAmbiguous {
		t.Errorf("stale GPT: %+v", d)
	}
}

// An MBR partition reaching past the disk, or starting past it, is listed
// and flags the disk partly unreadable.
func TestProbeMBROutOfRange(t *testing.T) {
	for _, c := range []struct {
		p    tpart
		size int64
	}{{tpart{mbr: 0x07, start: 100, n: 29}, 28 * 512}, {tpart{mbr: 0x07, start: 100, n: 1 << 30}, 28 * 512}, {tpart{mbr: 0x07, start: 128, n: 4}, 0}} {
		d := probeBytes(t, mbrDisk(128, []tpart{c.p}), 512)
		if len(d.Partitions) != 1 || d.Partitions[0].Size != c.size || d.Problem != ProblemPartial || !d.NeedsSecondConfirm() {
			t.Errorf("%+v: %+v", c.p, d)
		}
	}
	if d := probeBytes(t, mbrDisk(128, []tpart{{mbr: 0x07, start: 100, n: 28}}), 512); d.Problem != ProblemNone || d.Partitions[0].Size != 28*512 {
		t.Errorf("last sector: %+v", d)
	}
}

// A hybrid MBR is read as the GPT behind it; with no valid GPT copy it is
// unreadable, never described from its MBR entries.
func TestProbeHybridMBR(t *testing.T) {
	b := windowsLaptop(512)
	e := b[446+16:]
	e[4] = 0x07
	binary.LittleEndian.PutUint32(e[8:], 224)
	binary.LittleEndian.PutUint32(e[12:], 3200)
	if d := probeBytes(t, b, 512); d.Table != TableGPT || len(d.Partitions) != 4 {
		t.Fatalf("hybrid: %+v", d)
	}
	b[512+20] ^= 0xFF
	b[len(b)-512+20] ^= 0xFF
	d, err := Probe(bytes.NewReader(b), int64(len(b)), 512)
	if !errors.Is(err, ErrUnreadableTable) || len(d.Partitions) != 0 {
		t.Fatalf("hybrid without GPT: %v %+v", err, d)
	}
}

// ebrChain builds an MBR disk whose extended partition at sector 100 holds
// EBRs at 100+links[i], each pointing at the next.
func ebrChain(links []uint32) []byte {
	b := mbrDisk(8192, []tpart{{mbr: 0x05, start: 100, n: 8000}})
	for i, l := range links {
		e := b[(100+int(l))*512:]
		e[510], e[511] = 0x55, 0xAA
		e[446+4] = 0x83
		binary.LittleEndian.PutUint32(e[446+8:], 1)
		binary.LittleEndian.PutUint32(e[446+12:], 1)
		if i+1 < len(links) {
			e[462+4] = 0x05
			binary.LittleEndian.PutUint32(e[462+8:], links[i+1])
		}
	}
	return b
}

// Extended-partition chains are capped at 64 and a loop is caught.
func TestProbeBoundsEBRChain(t *testing.T) {
	var ok []uint32
	for i := 0; i < 64; i++ {
		ok = append(ok, uint32(2*i))
	}
	if d := probeBytes(t, ebrChain(ok), 512); len(d.Partitions) != 64 {
		t.Fatalf("64 logical partitions: %d", len(d.Partitions))
	}
	// Logical partitions are numbered by count, as the kernel does: an
	// empty EBR takes no number.
	gap := ebrChain([]uint32{0, 4, 8})
	gap[(100+4)*512+446+4] = 0
	if d := probeBytes(t, gap, 512); len(d.Partitions) != 2 || d.Partitions[0].Number != 5 || d.Partitions[1].Number != 6 {
		t.Fatalf("numbering: %+v", d.Partitions)
	}
	long := append(ok, 200)
	if _, err := Probe(bytes.NewReader(ebrChain(long)), 8192*512, 512); !errors.Is(err, ErrUnreadableTable) {
		t.Fatalf("65 logical partitions: %v", err)
	}
	// A loop is caught when it closes, not by running into the cap.
	loop := []uint32{0, 4, 2, 4}
	rec := &recorder{r: bytes.NewReader(ebrChain(loop))}
	if _, err := Probe(rec, 8192*512, 512); !errors.Is(err, ErrUnreadableTable) {
		t.Fatalf("loop: %v", err)
	}
	if len(rec.seen) > 6 {
		t.Fatalf("loop read %d times", len(rec.seen))
	}
	back := []uint32{0, 4, 0}
	if _, err := Probe(bytes.NewReader(ebrChain(back)), 8192*512, 512); !errors.Is(err, ErrUnreadableTable) {
		t.Fatalf("loop back to first: %v", err)
	}
}

// canaryDisk carries an owner's labels where the formats keep them: GPT
// partition names, a FAT volume label, an ext label, and GUIDs.
func canaryDisk() []byte {
	b := gptDisk(512, 4096, "ca7a1111-2222-4333-8444-555566667777", []tpart{
		{typ: tESP, start: 64, n: 128, sig: SigFAT, name: "CANARY-GPT-7731", uuid: "ca7a0001-2222-4333-8444-555566667777"},
		{typ: tLinux, start: 192, n: 512, sig: SigExt, name: "CANARY-GPT-7732", uuid: "ca7a0002-2222-4333-8444-555566667777"},
	})
	copy(b[64*512+71:], "CANARYFAT77")
	copy(b[192*512+1024+120:], "CANARY-EXT-7733")
	return b
}

var canaries = []string{"CANARY", "canary", "ca7a", "CA7A", "7731", "7732", "7733", "5555", "6666"}

func leaksCanary(t *testing.T, what string, v any) {
	t.Helper()
	j, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{string(j), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
		for _, c := range canaries {
			if strings.Contains(out, c) {
				t.Errorf("%s output carries %q: %s", what, c, out)
			}
		}
	}
}

// Security H4 on HOST-1a: what the probe returns is booleans, enums and
// sizes; no label, partition name or GUID is decoded or kept.
func TestProbeKeepsNoLabelsOrGUIDs(t *testing.T) {
	d := probeBytes(t, canaryDisk(), 512)
	if len(d.Partitions) != 2 || d.Partitions[0].Signature != SigFAT || d.Partitions[1].Signature != SigExt {
		t.Fatalf("%+v", d)
	}
	leaksCanary(t, "probe", d)
}

// recorded totals and bounds-checks every read a probe makes.
func checkReads(t *testing.T, rec *recorder, size int64, sector int) {
	t.Helper()
	var total int64
	for _, s := range rec.seen {
		if s[0] < 0 || s[1] > size {
			t.Fatalf("read [%d, %d) outside a %d-byte disk", s[0], s[1], size)
		}
		total += s[1] - s[0]
	}
	if total > readBudget(int64(sector)) {
		t.Fatalf("read %d bytes, budget %d", total, readBudget(int64(sector)))
	}
}

// Native fuzzing of Probe over arbitrary disk contents (security H3): no
// panic, no read outside the disk, never more than the read budget.
func FuzzProbe(f *testing.F) {
	// Small seeds keep the fuzzer fast; the table logic is the same at
	// any disk size.
	small := []tpart{
		{typ: tESP, start: 40, n: 16, sig: SigFAT},
		{typ: tMSR, start: 56, n: 8},
		{typ: tBasic, start: 64, n: 16, sig: SigBitLocker},
		{typ: tWinRE, start: 80, n: 8, sig: SigNTFS},
	}
	f.Add(gptDisk(512, 128, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", small), 512)
	f.Add(gptDisk(4096, 24, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{{typ: tBasic, start: 6, n: 4, sig: SigNTFS}}), 4096)
	f.Add(mbrDisk(64, []tpart{{mbr: 0x07, start: 8, n: 16, sig: SigNTFS}, {mbr: 0x05, start: 30, n: 30}}), 512)
	f.Add(make([]byte, 600), 512)
	f.Fuzz(func(t *testing.T, b []byte, sector int) {
		if sector != 4096 {
			sector = 512
		}
		rec := &recorder{r: bytes.NewReader(b)}
		d, err := Probe(rec, int64(len(b)), sector)
		checkReads(t, rec, int64(len(b)), sector)
		if err != nil && d.Problem == ProblemNone {
			t.Fatalf("error %v without a problem", err)
		}
		for _, p := range d.Partitions {
			if p.Size < 0 || p.Start > int64(len(b)) {
				t.Fatalf("partition %+v on a %d-byte disk", p, len(b))
			}
		}
	})
}
