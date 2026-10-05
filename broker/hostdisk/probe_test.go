package hostdisk

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
)

// REQ: HW-8, HW-8a

// tpart is one partition of a synthetic disk: its GPT type (or MBR type
// byte), its start and length in sectors, and the signature written at
// its start.
type tpart struct {
	typ   string
	mbr   byte
	start int64
	n     int64
	sig   Signature
	uuid  string
	name  string
}

const (
	tESP   = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	tMSR   = "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
	tBasic = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	tWinRE = "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"
	tLinux = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
)

// writeSig puts sig's identifying bytes at the start of a partition, the
// way each format lays them out.
func writeSig(b []byte, sig Signature) {
	switch sig {
	case SigNTFS:
		copy(b[3:], "NTFS    ")
		b[510], b[511] = 0x55, 0xAA
	case SigBitLocker:
		copy(b[3:], "-FVE-FS-")
		b[510], b[511] = 0x55, 0xAA
	case SigFAT:
		copy(b[82:], "FAT32   ")
		b[510], b[511] = 0x55, 0xAA
	case SigExFAT:
		copy(b[3:], "EXFAT   ")
	case SigReFS:
		copy(b[3:], "ReFS\x00\x00\x00\x00")
	case SigExt:
		b[1024+56], b[1024+57] = 0x53, 0xEF
	case SigLUKS:
		copy(b, "LUKS\xba\xbe")
	case SigSwap:
		copy(b[4096-10:], "SWAPSPACE2")
	case SigLVM:
		copy(b[512:], "LABELONE")
		copy(b[512+24:], "LVM2 001")
	case SigAPFS:
		copy(b[32:], "NXSB")
	}
}

// guidBytes encodes a GUID string in GPT's mixed-endian layout.
func guidBytes(s string) []byte {
	h := strings.ReplaceAll(s, "-", "")
	var raw [16]byte
	for i := 0; i < 16; i++ {
		var v byte
		for _, c := range h[2*i : 2*i+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				v |= byte(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= byte(c-'A') + 10
			}
		}
		raw[i] = v
	}
	out := make([]byte, 16)
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

// gptDisk builds a GPT disk of n sectors with primary and backup tables.
func gptDisk(sector int, n int64, diskUUID string, parts []tpart) []byte {
	ss := int64(sector)
	b := make([]byte, n*ss)
	// Protective MBR.
	b[446+4] = 0xEE
	binary.LittleEndian.PutUint32(b[446+8:], 1)
	binary.LittleEndian.PutUint32(b[446+12:], uint32(n-1))
	b[510], b[511] = 0x55, 0xAA

	const entries, esize = 128, 128
	ent := make([]byte, entries*esize)
	for i, p := range parts {
		e := ent[i*esize:]
		copy(e[0:], guidBytes(p.typ))
		u := p.uuid
		if u == "" {
			u = "00000000-0000-0000-0000-0000000000" + string(rune('a'+i)) + "1"
		}
		copy(e[16:], guidBytes(u))
		binary.LittleEndian.PutUint64(e[32:], uint64(p.start))
		binary.LittleEndian.PutUint64(e[40:], uint64(p.start+p.n-1))
		for j, r := range p.name {
			binary.LittleEndian.PutUint16(e[56+2*j:], uint16(r))
		}
		if p.sig != SigNone {
			writeSig(b[p.start*ss:(p.start+p.n)*ss], p.sig)
		}
	}
	entSectors := int64(len(ent)) / ss
	header := func(my, alt, entLBA int64) []byte {
		h := make([]byte, 92)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], uint64(my))
		binary.LittleEndian.PutUint64(h[32:], uint64(alt))
		binary.LittleEndian.PutUint64(h[40:], uint64(2+entSectors))
		binary.LittleEndian.PutUint64(h[48:], uint64(n-2-entSectors))
		copy(h[56:], guidBytes(diskUUID))
		binary.LittleEndian.PutUint64(h[72:], uint64(entLBA))
		binary.LittleEndian.PutUint32(h[80:], entries)
		binary.LittleEndian.PutUint32(h[84:], esize)
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(ent))
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		return h
	}
	copy(b[1*ss:], header(1, n-1, 2))
	copy(b[2*ss:], ent)
	copy(b[(n-1-entSectors)*ss:], ent)
	copy(b[(n-1)*ss:], header(n-1, 1, n-1-entSectors))
	return b
}

// mbrDisk builds an MBR disk with up to four primary partitions.
func mbrDisk(n int64, parts []tpart) []byte {
	b := make([]byte, n*512)
	for i, p := range parts {
		e := b[446+16*i:]
		e[4] = p.mbr
		binary.LittleEndian.PutUint32(e[8:], uint32(p.start))
		binary.LittleEndian.PutUint32(e[12:], uint32(p.n))
		if p.sig != SigNone {
			writeSig(b[p.start*512:(p.start+p.n)*512], p.sig)
		}
	}
	b[510], b[511] = 0x55, 0xAA
	return b
}

// windowsLaptop is the usual Windows 11 layout: ESP, MSR, the BitLocker
// system volume and the recovery partition.
func windowsLaptop(sector int) []byte {
	return gptDisk(sector, 4096, "6c1e57a0-3b1f-4c4e-9a52-1f0c7d6e2b11", []tpart{
		{typ: tESP, start: 64, n: 128, sig: SigFAT, name: "EFI system partition"},
		{typ: tMSR, start: 192, n: 32},
		{typ: tBasic, start: 224, n: 3200, sig: SigBitLocker, name: "Basic data partition"},
		{typ: tWinRE, start: 3424, n: 256, sig: SigNTFS},
	})
}

func probeBytes(t *testing.T, b []byte, sector int) Disk {
	t.Helper()
	d, err := Probe(bytes.NewReader(b), int64(len(b)), sector)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return d
}

// The HW-8a list describes a Windows disk from the partition table and
// volume signatures alone: it holds Windows, BitLocker and a boot loader,
// so taking it needs the second confirmation.
func TestProbeDescribesAWindowsDisk(t *testing.T) {
	for _, sector := range []int{512, 4096} {
		d := probeBytes(t, windowsLaptop(sector), sector)
		if d.Table != TableGPT {
			t.Fatalf("sector %d: table %q", sector, d.Table)
		}
		if d.TableUUID != "6c1e57a0-3b1f-4c4e-9a52-1f0c7d6e2b11" {
			t.Errorf("sector %d: table uuid %q", sector, d.TableUUID)
		}
		want := []struct {
			kind Kind
			sig  Signature
			size int64
		}{
			{KindESP, SigFAT, 128},
			{KindMSR, SigNone, 32},
			{KindBasicData, SigBitLocker, 3200},
			{KindWinRE, SigNTFS, 256},
		}
		if len(d.Partitions) != len(want) {
			t.Fatalf("sector %d: %d partitions: %+v", sector, len(d.Partitions), d.Partitions)
		}
		for i, w := range want {
			p := d.Partitions[i]
			if p.Kind != w.kind || p.Signature != w.sig || p.Size != w.size*int64(sector) || p.Number != i+1 {
				t.Errorf("sector %d: partition %d = %+v, want %+v", sector, i, p, w)
			}
		}
		if d.Partitions[0].Name != "EFI system partition" {
			t.Errorf("name %q", d.Partitions[0].Name)
		}
		if !d.HoldsWindows || !d.HasBitLocker || !d.HasBootLoader || !d.NeedsSecondConfirm() {
			t.Errorf("sector %d: flags %+v", sector, d)
		}
	}
}

// A plain NTFS data disk is not Windows and needs only the one erase
// confirmation (HW-8a; the UX walkthrough's "WD Blue, 1 partition, Data").
func TestProbeDataDiskNeedsOneConfirmation(t *testing.T) {
	b := gptDisk(512, 4096, "11111111-2222-3333-4444-555555555555", []tpart{
		{typ: tBasic, start: 64, n: 3900, sig: SigNTFS, name: "Data"},
	})
	d := probeBytes(t, b, 512)
	if d.HoldsWindows || d.HasBitLocker || d.HasBootLoader || d.NeedsSecondConfirm() {
		t.Fatalf("flags %+v", d)
	}
	if len(d.Partitions) != 1 || d.Partitions[0].Signature != SigNTFS || d.Partitions[0].Name != "Data" {
		t.Fatalf("partitions %+v", d.Partitions)
	}
}

// Every signature the list names is recognized from the first 4 KiB.
func TestProbeRecognizesEachSignature(t *testing.T) {
	sigs := []Signature{SigNTFS, SigBitLocker, SigFAT, SigExFAT, SigReFS, SigExt, SigLUKS, SigSwap, SigLVM, SigAPFS, SigNone}
	var parts []tpart
	for i, s := range sigs {
		parts = append(parts, tpart{typ: tLinux, start: int64(64 + 32*i), n: 32, sig: s})
	}
	d := probeBytes(t, gptDisk(512, 1024, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", parts), 512)
	if len(d.Partitions) != len(sigs) {
		t.Fatalf("%d partitions", len(d.Partitions))
	}
	for i, s := range sigs {
		if got := d.Partitions[i].Signature; got != s {
			t.Errorf("partition %d: %q, want %q", i+1, got, s)
		}
	}
}

// An MBR disk (older PCs, legacy BIOS installs) is described too; Windows
// is read from an active NTFS partition next to a recovery partition.
func TestProbeMBRDisk(t *testing.T) {
	b := mbrDisk(4096, []tpart{
		{mbr: 0x07, start: 64, n: 1000, sig: SigNTFS},
		{mbr: 0x07, start: 1064, n: 2000, sig: SigBitLocker},
		{mbr: 0x27, start: 3064, n: 500, sig: SigNTFS},
	})
	d := probeBytes(t, b, 512)
	if d.Table != TableMBR || len(d.Partitions) != 3 {
		t.Fatalf("%+v", d)
	}
	if d.Partitions[2].Kind != KindWinRE || d.Partitions[1].Signature != SigBitLocker {
		t.Fatalf("%+v", d.Partitions)
	}
	if !d.HoldsWindows || !d.HasBitLocker || !d.NeedsSecondConfirm() {
		t.Fatalf("flags %+v", d)
	}
}

// A disk with no partition table but a volume on the whole device (a
// BitLocker To Go stick, an ext4 disk made without partitions) shows that.
func TestProbeWholeDiskVolume(t *testing.T) {
	b := make([]byte, 64*1024)
	writeSig(b, SigBitLocker)
	d := probeBytes(t, b, 512)
	if d.Table != TableNone || d.Signature != SigBitLocker || !d.HasBitLocker || !d.NeedsSecondConfirm() {
		t.Fatalf("%+v", d)
	}
	blank := probeBytes(t, make([]byte, 64*1024), 512)
	if blank.Table != TableNone || blank.Signature != SigNone || blank.NeedsSecondConfirm() {
		t.Fatalf("blank: %+v", blank)
	}
}

// A damaged primary GPT falls back to the backup copy, the way firmware
// and partitioning tools do; a disk with both copies damaged is reported
// as unreadable and treated as needing the second confirmation, since what
// it holds cannot be told.
func TestProbeGPTBackupAndDamage(t *testing.T) {
	b := windowsLaptop(512)
	b[512+20] ^= 0xFF // primary header CRC field
	d := probeBytes(t, b, 512)
	if len(d.Partitions) != 4 || !d.HasBitLocker {
		t.Fatalf("backup not used: %+v", d)
	}

	b = windowsLaptop(512)
	b[2*512+40] ^= 0xFF // primary entry array, under its CRC
	d = probeBytes(t, b, 512)
	if len(d.Partitions) != 4 {
		t.Fatalf("entry CRC not checked: %+v", d)
	}

	b = windowsLaptop(512)
	b[512+20] ^= 0xFF
	b[len(b)-512+20] ^= 0xFF
	d, err := Probe(bytes.NewReader(b), int64(len(b)), 512)
	if !errors.Is(err, ErrUnreadableTable) {
		t.Fatalf("err %v", err)
	}
	if d.Table != TableGPT || !d.NeedsSecondConfirm() {
		t.Fatalf("damaged disk: %+v", d)
	}
}

// Truncated or lying tables do not make the probe read outside the disk
// or panic, and partitions past the end are listed without a signature.
func TestProbeTruncatedAndOutOfRange(t *testing.T) {
	b := windowsLaptop(512)
	for _, n := range []int{0, 100, 511, 512, 1024, 3000} {
		if _, err := Probe(bytes.NewReader(b[:n]), int64(n), 512); err == nil && n >= 1024 {
			// A short read of a real table is an error, never a guess.
			t.Errorf("len %d: no error", n)
		}
	}
	b = mbrDisk(128, []tpart{{mbr: 0x07, start: 100, n: 1 << 30}})
	d := probeBytes(t, b, 512)
	if len(d.Partitions) != 1 || d.Partitions[0].Signature != SigNone {
		t.Fatalf("%+v", d)
	}
	if _, err := Probe(bytes.NewReader(b), int64(len(b)), 0); err == nil {
		t.Fatal("sector size 0 accepted")
	}
}

// recorder is a ReaderAt that remembers every byte range read.
type recorder struct {
	r    io.ReaderAt
	mu   sync.Mutex
	seen [][2]int64
}

func (r *recorder) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	r.seen = append(r.seen, [2]int64{off, off + int64(len(p))})
	r.mu.Unlock()
	return r.r.ReadAt(p, off)
}

// HW-8: "no file system on a host disk is opened". The probe reads the
// partition tables (both GPT copies) and at most the first 4 KiB of each
// partition, and nothing else, whatever the partition holds.
func TestProbeReadsOnlyTablesAndSignatureWindows(t *testing.T) {
	const sector = 512
	const window = 4096 // HW-8: signatures only, never file system data
	b := windowsLaptop(sector)
	rec := &recorder{r: bytes.NewReader(b)}
	if _, err := Probe(rec, int64(len(b)), sector); err != nil {
		t.Fatal(err)
	}
	n := int64(len(b))
	entBytes := int64(128 * 128)
	allowed := [][2]int64{
		{0, 2 * sector},                     // MBR and primary header
		{2 * sector, 2*sector + entBytes},   // primary entries
		{n - sector - entBytes, n},          // backup entries and header
		{64 * sector, 64*sector + window},   // ESP
		{192 * sector, 192*sector + window}, // MSR
		{224 * sector, 224*sector + window}, // BitLocker volume
		{3424 * sector, 3424*sector + window},
	}
	for _, s := range rec.seen {
		ok := false
		for _, a := range allowed {
			if s[0] >= a[0] && s[1] <= a[1] {
				ok = true
			}
		}
		if !ok {
			t.Errorf("read [%d, %d) is outside the tables and signature windows", s[0], s[1])
		}
	}
	// A partition table that lists the whole disk as one partition still
	// gets only its first window read.
	big := gptDisk(sector, 1<<15, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{{typ: tBasic, start: 64, n: 1<<15 - 200, sig: SigNTFS}})
	rec = &recorder{r: bytes.NewReader(big)}
	if _, err := Probe(rec, int64(len(big)), sector); err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, s := range rec.seen {
		total += s[1] - s[0]
	}
	if limit := int64(2*sector) + 2*entBytes + sector + window; total > limit {
		t.Fatalf("read %d bytes, more than %d", total, limit)
	}
}

// Probe's partitions come back in table order, with GPT GUIDs in the
// lower-case textual form systemd uses for LoaderDevicePartUUID.
func TestProbePartitionUUIDs(t *testing.T) {
	b := gptDisk(512, 2048, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", []tpart{
		{typ: tLinux, start: 64, n: 64, uuid: "0E5B0A6F-1C2D-4E3F-8A9B-0C1D2E3F4A5B"},
		{typ: tLinux, start: 128, n: 64, uuid: "9F8E7D6C-5B4A-3928-1706-F5E4D3C2B1A0"},
	})
	d := probeBytes(t, b, 512)
	got := []string{d.Partitions[0].UUID, d.Partitions[1].UUID}
	if !sort.SliceIsSorted(d.Partitions, func(i, j int) bool { return d.Partitions[i].Start < d.Partitions[j].Start }) {
		t.Fatal("order")
	}
	if got[0] != "0e5b0a6f-1c2d-4e3f-8a9b-0c1d2e3f4a5b" || got[1] != "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0" {
		t.Fatalf("uuids %v", got)
	}
	if !d.HasPartition("0E5B0A6F-1C2D-4E3F-8A9B-0C1D2E3F4A5B") || d.HasPartition("00000000-0000-0000-0000-000000000000") {
		t.Fatal("HasPartition")
	}
}
