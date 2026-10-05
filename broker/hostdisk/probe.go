// Package hostdisk describes the host PC's disks without touching them
// (HW-8, HW-8a). It reads a disk's partition table and, for each
// partition, at most its first WindowSize bytes to recognize the volume
// signature, so the local page can say what a disk holds (Windows,
// BitLocker, a boot loader, a data volume) before the owner gives it to
// the box. It opens no file system, never mounts, and never writes.
//
// The partition table is hostile input: every count, size and LBA is
// bounded and checked before use, and a disk's total reads are capped.
// What comes out is booleans, enums and sizes only: no volume label,
// partition name, GUID or serial is decoded, kept or logged (security H4
// on HOST-1a).
package hostdisk

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math/bits"
)

// WindowSize is how much of a partition (or of a disk with no partition
// table) is read to recognize its volume signature. Every signature below
// lies inside it; no file system structure past it is read.
const WindowSize = 4096

// Bounds on a partition table (security H3 on HOST-1a). A table outside
// them is unreadable, never partly trusted.
const (
	maxGPTEntries   = 128
	minGPTEntrySize = 128
	maxGPTEntrySize = 512
	maxGPTArray     = 32 << 10
	maxLogical      = 64
)

// ErrUnreadableTable means the disk has a partition table the probe could
// not read (both GPT copies damaged or out of bounds, a looping or too long
// extended-partition chain, or a disk shorter than its table).
var ErrUnreadableTable = errors.New("hostdisk: partition table unreadable")

// Table is the kind of partition table.
type Table string

const (
	TableGPT  Table = "gpt"
	TableMBR  Table = "mbr"
	TableNone Table = "none"
)

// Signature is what a volume's first bytes say it is.
type Signature string

const (
	SigNone      Signature = ""
	SigNTFS      Signature = "ntfs"
	SigBitLocker Signature = "bitlocker"
	SigFAT       Signature = "fat"
	SigExFAT     Signature = "exfat"
	SigReFS      Signature = "refs"
	SigExt       Signature = "ext"
	SigLUKS      Signature = "luks"
	SigSwap      Signature = "swap"
	SigLVM       Signature = "lvm"
	SigAPFS      Signature = "apfs"
)

// Kind is what the partition table says a partition is for.
type Kind string

const (
	KindESP       Kind = "esp"
	KindBIOSBoot  Kind = "bios-boot"
	KindMSR       Kind = "msr"
	KindBasicData Kind = "basic-data"
	KindWinRE     Kind = "windows-recovery"
	KindLinux     Kind = "linux"
	KindLinuxSwap Kind = "linux-swap"
	KindOther     Kind = "other"
)

// Problem says why a disk could not be described (potency R1 on HOST-1a:
// such a disk is listed, never dropped).
type Problem string

const (
	ProblemNone        Problem = ""
	ProblemTable       Problem = "unreadable-table"
	ProblemPartial     Problem = "partly-unreadable" // a partition reaches past the disk, or its start could not be read
	ProblemAmbiguous   Problem = "ambiguous-table"   // two readings of the disk's start disagree; both are described
	ProblemOpen        Problem = "cannot-open"
	ProblemSizeUnknown Problem = "size-unknown"
)

// gptKinds maps GPT type GUIDs, as on disk (mixed-endian), to kinds.
var gptKinds = map[[16]byte]Kind{
	onDisk("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"): KindESP,
	onDisk("21686148-6449-6e6f-744e-656564454649"): KindBIOSBoot,
	onDisk("e3c9e316-0b5c-4db8-817d-f92df00215ae"): KindMSR,
	onDisk("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"): KindBasicData,
	onDisk("de94bba4-06d1-4d40-a16a-bfd50179d6ac"): KindWinRE,
	onDisk("0fc63daf-8483-4772-8e79-3d69d8477de4"): KindLinux,
	onDisk("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f"): KindLinuxSwap,
}

var mbrKinds = map[byte]Kind{
	0xEF: KindESP,
	0x27: KindWinRE,
	0x07: KindBasicData, // NTFS, exFAT, BitLocker
	0x01: KindBasicData, 0x04: KindBasicData, 0x06: KindBasicData,
	0x0B: KindBasicData, 0x0C: KindBasicData, 0x0E: KindBasicData,
	0x83: KindLinux,
	0x82: KindLinuxSwap,
}

// Partition is one entry of a disk's partition table.
type Partition struct {
	Number    int       `json:"number"` // 1-based, as the kernel numbers it
	Start     int64     `json:"-"`      // bytes; used only to read the window
	Size      int64     `json:"size"`   // bytes
	Kind      Kind      `json:"kind"`
	Active    bool      `json:"active,omitempty"` // MBR boot flag
	Signature Signature `json:"signature,omitempty"`
}

// Bus is how a disk is attached (potency R2 on HOST-1a).
type Bus string

const (
	BusNVMe   Bus = "nvme"
	BusSATA   Bus = "sata"
	BusUSB    Bus = "usb"
	BusMMC    Bus = "mmc"
	BusVirtIO Bus = "virtio"
	BusSCSI   Bus = "scsi"
	BusOther  Bus = "other"
)

// Disk describes one host disk for the HW-8a list.
type Disk struct {
	Name          string      `json:"name"`  // kernel name, e.g. "nvme0n1"
	Model         string      `json:"model"` // the drive's own model string (HW-8a), printable ASCII
	Size          int64       `json:"size"`  // bytes
	Bus           Bus         `json:"bus"`
	Removable     bool        `json:"removable"`
	Table         Table       `json:"table"`
	Signature     Signature   `json:"signature,omitempty"` // a volume on the whole disk
	Partitions    []Partition `json:"partitions"`
	HoldsWindows  bool        `json:"holds_windows"`
	HasBitLocker  bool        `json:"has_bitlocker"`
	HasBootLoader bool        `json:"has_boot_loader"`
	Problem       Problem     `json:"problem,omitempty"`
}

// NeedsSecondConfirm reports whether taking the disk needs HW-8a's second,
// separate confirmation: it holds BitLocker, Windows, or a boot loader the
// host may start from, or it could not be read, so what it holds is unknown.
func (d Disk) NeedsSecondConfirm() bool {
	return d.HasBitLocker || d.HoldsWindows || d.HasBootLoader || d.Problem != ProblemNone
}

// readBudget caps the bytes one probe reads: the MBR, both GPT copies at
// their largest, every EBR, and a window per partition.
func readBudget(ss int64) int64 {
	return 512 + 2*(ss+maxGPTArray) + maxLogical*ss + (maxGPTEntries+1)*WindowSize
}

// budget is a ReaderAt that refuses reads outside the disk and past the
// probe's read budget.
type budget struct {
	r    io.ReaderAt
	size int64
	left int64
}

var errBudget = errors.New("hostdisk: read budget spent")

func (b *budget) read(p []byte, off int64) error {
	n := int64(len(p))
	if off < 0 || n > b.size || off > b.size-n {
		return io.ErrUnexpectedEOF
	}
	if n > b.left {
		return errBudget
	}
	b.left -= n
	got, err := b.r.ReadAt(p, off)
	if int64(got) == n {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// mul multiplies two non-negative values, reporting overflow past int64.
func mul(a, b uint64) (int64, bool) {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 || lo > 1<<63-1 {
		return 0, false
	}
	return int64(lo), true
}

// Probe describes the disk behind r, size bytes long with the given
// logical sector size. It reads only the partition table and each
// partition's first WindowSize bytes. A table it cannot read is returned
// as ErrUnreadableTable with Disk.Problem set.
func Probe(r io.ReaderAt, size int64, sector int) (Disk, error) {
	d, _, err := probe(r, size, sector, [16]byte{})
	return d, err
}

// probe is Probe that also reports whether the GPT lists a partition with
// unique GUID want (on-disk form), without keeping any GUID.
func probe(r io.ReaderAt, size int64, sector int, want [16]byte) (Disk, bool, error) {
	if sector < 512 || sector > 65536 || sector&(sector-1) != 0 {
		return Disk{}, false, errors.New("hostdisk: bad sector size")
	}
	if size < 0 {
		return Disk{}, false, errors.New("hostdisk: bad size")
	}
	ss := int64(sector)
	b := &budget{r: r, size: size, left: readBudget(ss)}
	d := Disk{Size: size, Table: TableNone, Partitions: []Partition{}}
	fail := func(err error) (Disk, bool, error) {
		d.Problem = ProblemTable
		return d, false, err
	}
	mbr := make([]byte, 512)
	if err := b.read(mbr, 0); err != nil {
		return fail(ErrUnreadableTable)
	}
	bootSig := mbr[510] == 0x55 && mbr[511] == 0xAA
	protective := false
	if bootSig {
		for i := 0; i < 4; i++ {
			if mbr[446+16*i+4] == 0xEE {
				protective = true
			}
		}
	}
	found, partial := false, false
	if protective {
		// A hybrid MBR (0xEE beside other entries) is read as the GPT it
		// fronts; if no GPT copy is valid the disk is unreadable, never
		// described from the hybrid entries.
		d.Table = TableGPT
		parts, ok, err := probeGPT(b, size, ss, want, &partial)
		if err != nil {
			return fail(err)
		}
		d.Partitions, found = parts, ok
	} else {
		w := make([]byte, min(int64(WindowSize), size))
		if err := b.read(w, 0); err != nil {
			return fail(ErrUnreadableTable)
		}
		d.Signature = detect(w)
		if bootSig && validMBR(mbr) {
			parts, err := probeMBR(b, size, ss, mbr, &partial)
			switch {
			case err != nil && d.Signature == SigNone:
				return fail(err)
			case err == nil:
				d.Table, d.Partitions = TableMBR, parts
			}
			if d.Signature != SigNone {
				// A volume at sector 0 whose boot code also parses as a
				// partition table: either may be real.
				d.Problem = ProblemAmbiguous
			}
		}
		// A valid primary GPT with no protective MBR (sector 0 rewritten
		// by an MBR-only tool, or a stale GPT under a new MBR). Like the
		// kernel, the MBR or volume reading wins; the disk is flagged.
		// With nothing else on the disk the GPT is described.
		var gptCut bool
		if parts, ok, err := readGPT(b, size, ss, 1, want, &gptCut); err == nil {
			d.Problem = ProblemAmbiguous
			if d.Table == TableNone && d.Signature == SigNone {
				d.Table, d.Partitions, found, partial = TableGPT, parts, ok, gptCut
			}
		}
	}
	for i := range d.Partitions {
		p := &d.Partitions[i]
		if p.Start < 0 || p.Start >= size || p.Size <= 0 {
			partial = true
			continue
		}
		w := make([]byte, min(int64(WindowSize), p.Size, size-p.Start))
		if err := b.read(w, p.Start); err != nil {
			partial = true
			continue
		}
		p.Signature = detect(w)
	}
	if partial && d.Problem == ProblemNone {
		d.Problem = ProblemPartial
	}
	summarize(&d)
	return d, found, nil
}

func summarize(d *Disk) {
	hasNTFS := false
	if d.Signature == SigBitLocker {
		d.HasBitLocker = true
	}
	for _, p := range d.Partitions {
		switch p.Kind {
		case KindMSR, KindWinRE:
			d.HoldsWindows = true
		case KindESP, KindBIOSBoot:
			d.HasBootLoader = true
		}
		if p.Active {
			d.HasBootLoader = true
		}
		switch p.Signature {
		case SigBitLocker:
			d.HasBitLocker = true
			hasNTFS = true
		case SigNTFS:
			hasNTFS = true
		}
	}
	if d.HasBootLoader && hasNTFS {
		d.HoldsWindows = true
	}
}

// detect recognizes a volume from its first bytes.
func detect(b []byte) Signature {
	at := func(off int, s string) bool {
		return len(b) >= off+len(s) && string(b[off:off+len(s)]) == s
	}
	boot55 := len(b) >= 512 && b[510] == 0x55 && b[511] == 0xAA
	switch {
	case at(0, "LUKS\xba\xbe"):
		return SigLUKS
	case at(3, "-FVE-FS-"):
		return SigBitLocker
	case at(3, "NTFS    "):
		return SigNTFS
	case at(3, "EXFAT   "):
		return SigExFAT
	case at(3, "ReFS\x00\x00\x00\x00"):
		return SigReFS
	case at(32, "NXSB"):
		return SigAPFS
	case boot55 && (at(82, "FAT32   ") || at(54, "FAT12   ") || at(54, "FAT16   ") || at(54, "FAT     ")):
		return SigFAT
	case at(1024+56, "\x53\xef"):
		return SigExt
	case at(4096-10, "SWAPSPACE2"), at(4096-10, "SWAP-SPACE"):
		return SigSwap
	}
	for _, off := range []int{0, 512, 1024, 1536} {
		if at(off, "LABELONE") && at(off+24, "LVM2 001") {
			return SigLVM
		}
	}
	return SigNone
}

// onDisk turns a textual GUID into GPT's on-disk mixed-endian bytes.
func onDisk(s string) [16]byte {
	var raw [16]byte
	j := 0
	for i := 0; i < len(s) && j < 32; i++ {
		c := s[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue
		}
		raw[j/2] = raw[j/2]<<4 | v
		j++
	}
	var out [16]byte
	out[0], out[1], out[2], out[3] = raw[3], raw[2], raw[1], raw[0]
	out[4], out[5] = raw[5], raw[4]
	out[6], out[7] = raw[7], raw[6]
	copy(out[8:], raw[8:])
	return out
}

// probeGPT reads the primary GPT, else the backup. partial is set when a
// valid table lists a partition the probe cannot fully describe.
func probeGPT(b *budget, size, ss int64, want [16]byte, partial *bool) ([]Partition, bool, error) {
	for _, lba := range []int64{1, size/ss - 1} {
		if lba < 1 {
			continue
		}
		if parts, found, err := readGPT(b, size, ss, lba, want, partial); err == nil {
			return parts, found, nil
		}
	}
	return nil, false, ErrUnreadableTable
}

var errGPT = errors.New("hostdisk: GPT copy invalid")

func readGPT(b *budget, size, ss, lba int64, want [16]byte, partial *bool) ([]Partition, bool, error) {
	sectors := uint64(size / ss)
	h := make([]byte, ss)
	off, ok := mul(uint64(lba), uint64(ss))
	if !ok {
		return nil, false, errGPT
	}
	if err := b.read(h, off); err != nil {
		return nil, false, err
	}
	if string(h[:8]) != "EFI PART" {
		return nil, false, errGPT
	}
	hsize := int64(binary.LittleEndian.Uint32(h[12:]))
	if hsize < 92 || hsize > ss {
		return nil, false, errGPT
	}
	crc := binary.LittleEndian.Uint32(h[16:])
	hc := append([]byte(nil), h[:hsize]...)
	binary.LittleEndian.PutUint32(hc[16:], 0)
	if crc32.ChecksumIEEE(hc) != crc {
		return nil, false, errGPT
	}
	if binary.LittleEndian.Uint64(h[24:]) != uint64(lba) {
		return nil, false, errGPT
	}
	entLBA := binary.LittleEndian.Uint64(h[72:])
	num := uint64(binary.LittleEndian.Uint32(h[80:]))
	esize := uint64(binary.LittleEndian.Uint32(h[84:]))
	if esize < minGPTEntrySize || esize > maxGPTEntrySize || esize%8 != 0 || num > maxGPTEntries || num*esize > maxGPTArray {
		return nil, false, errGPT
	}
	if entLBA < 1 || entLBA >= sectors {
		return nil, false, errGPT
	}
	entOff, ok := mul(entLBA, uint64(ss))
	if !ok {
		return nil, false, errGPT
	}
	ent := make([]byte, num*esize)
	if err := b.read(ent, entOff); err != nil {
		return nil, false, err
	}
	if crc32.ChecksumIEEE(ent) != binary.LittleEndian.Uint32(h[88:]) {
		return nil, false, errGPT
	}
	parts := []Partition{}
	found, cut := false, false
	for i := uint64(0); i < num; i++ {
		e := ent[i*esize : (i+1)*esize]
		var typ, uniq [16]byte
		copy(typ[:], e[0:16])
		copy(uniq[:], e[16:32])
		if typ == ([16]byte{}) {
			continue
		}
		first, last := binary.LittleEndian.Uint64(e[32:]), binary.LittleEndian.Uint64(e[40:])
		if last < first || first >= sectors {
			cut = true
			continue // outside the disk: not a partition the probe can describe
		}
		if last >= sectors {
			cut, last = true, sectors-1 // described as far as the disk goes
		}
		start, _ := mul(first, uint64(ss))
		n, _ := mul(last-first+1, uint64(ss))
		kind, ok := gptKinds[typ]
		if !ok {
			kind = KindOther
		}
		if want != ([16]byte{}) && uniq == want {
			found = true
		}
		parts = append(parts, Partition{Number: int(i + 1), Start: start, Size: n, Kind: kind})
	}
	*partial = *partial || cut
	return parts, found, nil
}

func validMBR(mbr []byte) bool {
	any := false
	for i := 0; i < 4; i++ {
		e := mbr[446+16*i:]
		if e[0] != 0x00 && e[0] != 0x80 {
			return false
		}
		if e[4] != 0 {
			any = true
		}
	}
	return any
}

func isExtended(t byte) bool { return t == 0x05 || t == 0x0F || t == 0x85 }

func probeMBR(b *budget, size, ss int64, mbr []byte, partial *bool) ([]Partition, error) {
	sectors := uint64(size / ss)
	parts := []Partition{}
	cut := false
	add := func(e []byte, base uint64, number int) {
		t := e[4]
		first := base + uint64(binary.LittleEndian.Uint32(e[8:]))
		count := uint64(binary.LittleEndian.Uint32(e[12:]))
		kind, ok := mbrKinds[t]
		if !ok {
			kind = KindOther
		}
		p := Partition{Number: number, Kind: kind, Active: e[0] == 0x80, Start: -1}
		if first < sectors {
			p.Start, _ = mul(first, uint64(ss))
			p.Size, _ = mul(min(count, sectors-first), uint64(ss))
		}
		if first >= sectors || count > sectors-first {
			cut = true
		}
		parts = append(parts, p)
	}
	extStart := uint64(0)
	hasExt := false
	for i := 0; i < 4; i++ {
		e := mbr[446+16*i : 446+16*i+16]
		switch {
		case e[4] == 0:
		case isExtended(e[4]):
			if !hasExt {
				extStart, hasExt = uint64(binary.LittleEndian.Uint32(e[8:])), true
			}
		default:
			add(e, 0, i+1)
		}
	}
	if !hasExt {
		*partial = *partial || cut
		return parts, nil
	}
	ebr := make([]byte, 512)
	seen := map[uint64]bool{}
	next := uint64(0)
	logical := 0
	for n := 0; n < maxLogical; n++ {
		at := extStart + next
		if seen[at] || at >= sectors {
			return nil, ErrUnreadableTable
		}
		seen[at] = true
		off, _ := mul(at, uint64(ss))
		if err := b.read(ebr, off); err != nil {
			return nil, ErrUnreadableTable
		}
		if ebr[510] != 0x55 || ebr[511] != 0xAA {
			return nil, ErrUnreadableTable
		}
		if e := ebr[446:462]; e[4] != 0 {
			// The kernel numbers logical partitions by count, skipping
			// empty EBRs.
			add(e, at, 5+logical)
			logical++
		}
		link := ebr[462:478]
		if !isExtended(link[4]) {
			*partial = *partial || cut
			return parts, nil
		}
		next = uint64(binary.LittleEndian.Uint32(link[8:]))
	}
	return nil, ErrUnreadableTable
}
