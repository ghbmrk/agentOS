// Package hostdisk describes the host PC's disks without touching them
// (HW-8, HW-8a). It reads a disk's partition table and, for each
// partition, at most its first WindowSize bytes to recognize the volume
// signature, so the local page can say what a disk holds (Windows,
// BitLocker, a boot loader, a data volume) before the owner gives it to
// the box. It opens no file system, never mounts, and never writes: the
// only way in is a read-only io.ReaderAt (see OpenReadOnly), and a source
// test keeps the package free of write, mount and exec calls.
package hostdisk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

// WindowSize is how much of a partition (or of a disk with no partition
// table) is read to recognize its volume signature. Every signature below
// lies inside it; no file system structure past it is read.
const WindowSize = 4096

// ErrUnreadableTable means the disk has a partition table the probe could
// not read (both GPT copies damaged, or the disk shorter than its table).
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

var gptKinds = map[string]Kind{
	"c12a7328-f81f-11d2-ba4b-00a0c93ec93b": KindESP,
	"21686148-6449-6e6f-744e-656564454649": KindBIOSBoot,
	"e3c9e316-0b5c-4db8-817d-f92df00215ae": KindMSR,
	"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": KindBasicData,
	"de94bba4-06d1-4d40-a16a-bfd50179d6ac": KindWinRE,
	"0fc63daf-8483-4772-8e79-3d69d8477de4": KindLinux,
	"0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": KindLinuxSwap,
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
	Start     int64     `json:"start"`  // bytes
	Size      int64     `json:"size"`   // bytes
	Kind      Kind      `json:"kind"`
	TypeGUID  string    `json:"type_guid,omitempty"` // GPT only, lower case
	UUID      string    `json:"uuid,omitempty"`      // GPT only, lower case
	MBRType   byte      `json:"mbr_type,omitempty"`  // MBR only
	Active    bool      `json:"active,omitempty"`    // MBR boot flag
	Name      string    `json:"name,omitempty"`      // GPT label
	Signature Signature `json:"signature,omitempty"`
}

// Disk describes one host disk for the HW-8a list.
type Disk struct {
	Name          string      `json:"name"` // kernel name, e.g. "nvme0n1"
	Model         string      `json:"model"`
	Size          int64       `json:"size"` // bytes
	Table         Table       `json:"table"`
	TableUUID     string      `json:"table_uuid,omitempty"`
	Signature     Signature   `json:"signature,omitempty"` // a volume on the whole disk
	Partitions    []Partition `json:"partitions"`
	HoldsWindows  bool        `json:"holds_windows"`
	HasBitLocker  bool        `json:"has_bitlocker"`
	HasBootLoader bool        `json:"has_boot_loader"`
	// Unreadable is why the disk could not be described, or empty.
	Unreadable string `json:"unreadable,omitempty"`
}

// NeedsSecondConfirm reports whether taking the disk needs HW-8a's second,
// separate confirmation: it holds BitLocker, Windows, or a boot loader the
// host may start from, or it could not be read, so what it holds is unknown.
func (d Disk) NeedsSecondConfirm() bool {
	return d.HasBitLocker || d.HoldsWindows || d.HasBootLoader || d.Unreadable != ""
}

// HasPartition reports whether the disk's table lists a partition with the
// given GPT unique GUID (any case).
func (d Disk) HasPartition(uuid string) bool {
	uuid = strings.ToLower(uuid)
	for _, p := range d.Partitions {
		if p.UUID != "" && p.UUID == uuid {
			return true
		}
	}
	return false
}

// Probe describes the disk behind r, size bytes long with the given
// logical sector size. It reads only the partition table and each
// partition's first WindowSize bytes. A table it cannot read is returned
// as ErrUnreadableTable with Disk.Unreadable set.
func Probe(r io.ReaderAt, size int64, sector int) (Disk, error) {
	if sector < 512 || sector > 65536 || sector&(sector-1) != 0 {
		return Disk{}, fmt.Errorf("hostdisk: bad sector size %d", sector)
	}
	d := Disk{Size: size, Table: TableNone, Partitions: []Partition{}}
	fail := func(err error) (Disk, error) {
		d.Unreadable = err.Error()
		return d, err
	}
	mbr := make([]byte, 512)
	if err := readFull(r, size, mbr, 0); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrUnreadableTable, err))
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
	if protective {
		d.Table = TableGPT
		if err := probeGPT(r, size, int64(sector), &d); err != nil {
			return fail(err)
		}
	} else {
		w := make([]byte, min(int64(WindowSize), size))
		if err := readFull(r, size, w, 0); err != nil {
			return fail(fmt.Errorf("%w: %v", ErrUnreadableTable, err))
		}
		if sig := detect(w); sig != SigNone {
			d.Signature = sig
		} else if bootSig && validMBR(mbr) {
			d.Table = TableMBR
			d.TableUUID = fmt.Sprintf("%08x", binary.LittleEndian.Uint32(mbr[440:]))
			if err := probeMBR(r, size, int64(sector), mbr, &d); err != nil {
				return fail(err)
			}
		}
	}
	for i := range d.Partitions {
		p := &d.Partitions[i]
		if p.Start < 0 || p.Start >= size || p.Size <= 0 {
			continue
		}
		w := make([]byte, min(int64(WindowSize), p.Size, size-p.Start))
		if err := readFull(r, size, w, p.Start); err == nil {
			p.Signature = detect(w)
		}
	}
	summarize(&d)
	return d, nil
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

func readFull(r io.ReaderAt, size int64, b []byte, off int64) error {
	if off < 0 || off+int64(len(b)) > size {
		return io.ErrUnexpectedEOF
	}
	n, err := r.ReadAt(b, off)
	if n == len(b) {
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
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

// guid formats a GPT on-disk GUID (mixed-endian) in lower-case text.
func guid(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(b[0:]), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}

func probeGPT(r io.ReaderAt, size, ss int64, d *Disk) error {
	last := size/ss - 1
	var firstErr error
	for _, lba := range []int64{1, last} {
		if lba < 1 {
			continue
		}
		parts, diskGUID, err := readGPT(r, size, ss, lba)
		if err == nil {
			d.TableUUID = diskGUID
			d.Partitions = parts
			return nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("disk too small")
	}
	return fmt.Errorf("%w: %v", ErrUnreadableTable, firstErr)
}

const (
	maxGPTEntries   = 1024
	maxGPTEntrySize = 4096
	maxGPTArray     = 1 << 20
)

func readGPT(r io.ReaderAt, size, ss, lba int64) ([]Partition, string, error) {
	h := make([]byte, ss)
	if err := readFull(r, size, h, lba*ss); err != nil {
		return nil, "", err
	}
	if string(h[:8]) != "EFI PART" {
		return nil, "", errors.New("no GPT signature")
	}
	hsize := int64(binary.LittleEndian.Uint32(h[12:]))
	if hsize < 92 || hsize > ss {
		return nil, "", errors.New("bad GPT header size")
	}
	want := binary.LittleEndian.Uint32(h[16:])
	hc := append([]byte(nil), h[:hsize]...)
	binary.LittleEndian.PutUint32(hc[16:], 0)
	if crc32.ChecksumIEEE(hc) != want {
		return nil, "", errors.New("GPT header CRC mismatch")
	}
	if int64(binary.LittleEndian.Uint64(h[24:])) != lba {
		return nil, "", errors.New("GPT header in the wrong place")
	}
	entLBA := binary.LittleEndian.Uint64(h[72:])
	num := int64(binary.LittleEndian.Uint32(h[80:]))
	esize := int64(binary.LittleEndian.Uint32(h[84:]))
	if esize < 128 || esize > maxGPTEntrySize || esize%8 != 0 || num > maxGPTEntries || num*esize > maxGPTArray {
		return nil, "", errors.New("bad GPT entry array")
	}
	if entLBA > uint64(size/ss) {
		return nil, "", errors.New("GPT entry array outside the disk")
	}
	ent := make([]byte, num*esize)
	if err := readFull(r, size, ent, int64(entLBA)*ss); err != nil {
		return nil, "", err
	}
	if crc32.ChecksumIEEE(ent) != binary.LittleEndian.Uint32(h[88:]) {
		return nil, "", errors.New("GPT entry CRC mismatch")
	}
	var parts []Partition
	for i := int64(0); i < num; i++ {
		e := ent[i*esize : (i+1)*esize]
		typ := guid(e[0:16])
		if typ == "00000000-0000-0000-0000-000000000000" {
			continue
		}
		first, lastLBA := binary.LittleEndian.Uint64(e[32:]), binary.LittleEndian.Uint64(e[40:])
		if lastLBA < first || first > uint64(1<<62)/uint64(ss) || lastLBA > uint64(1<<62)/uint64(ss) {
			continue
		}
		kind, ok := gptKinds[typ]
		if !ok {
			kind = KindOther
		}
		parts = append(parts, Partition{
			Number:   int(i + 1),
			Start:    int64(first) * ss,
			Size:     int64(lastLBA-first+1) * ss,
			Kind:     kind,
			TypeGUID: typ,
			UUID:     guid(e[16:32]),
			Name:     utf16Name(e[56:128]),
		})
	}
	if parts == nil {
		parts = []Partition{}
	}
	return parts, guid(h[56:72]), nil
}

func utf16Name(b []byte) string {
	var u []uint16
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
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

const maxLogical = 128

func probeMBR(r io.ReaderAt, size, ss int64, mbr []byte, d *Disk) error {
	add := func(e []byte, base int64, number int) {
		t := e[4]
		start := (base + int64(binary.LittleEndian.Uint32(e[8:]))) * ss
		n := int64(binary.LittleEndian.Uint32(e[12:])) * ss
		kind, ok := mbrKinds[t]
		if !ok {
			kind = KindOther
		}
		d.Partitions = append(d.Partitions, Partition{
			Number: number, Start: start, Size: n, Kind: kind, MBRType: t, Active: e[0] == 0x80,
		})
	}
	var extStart int64 = -1
	for i := 0; i < 4; i++ {
		e := mbr[446+16*i : 446+16*i+16]
		switch {
		case e[4] == 0:
		case isExtended(e[4]):
			if extStart < 0 {
				extStart = int64(binary.LittleEndian.Uint32(e[8:]))
			}
		default:
			add(e, 0, i+1)
		}
	}
	if extStart < 0 {
		return nil
	}
	ebr := make([]byte, 512)
	next := int64(0)
	for n := 0; n < maxLogical; n++ {
		at := extStart + next
		if err := readFull(r, size, ebr, at*ss); err != nil {
			return fmt.Errorf("%w: extended partition: %v", ErrUnreadableTable, err)
		}
		if ebr[510] != 0x55 || ebr[511] != 0xAA {
			return fmt.Errorf("%w: extended partition: no boot signature", ErrUnreadableTable)
		}
		if e := ebr[446:462]; e[4] != 0 {
			add(e, at, 5+n)
		}
		link := ebr[462:478]
		if !isExtended(link[4]) {
			return nil
		}
		nx := int64(binary.LittleEndian.Uint32(link[8:]))
		if nx <= next {
			return fmt.Errorf("%w: extended partition loops", ErrUnreadableTable)
		}
		next = nx
	}
	return fmt.Errorf("%w: too many logical partitions", ErrUnreadableTable)
}
