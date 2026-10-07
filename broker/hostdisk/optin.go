package hostdisk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// The internal-disk opt-in (HW-8a; HOST-1d part 1). The local page offers
// one host disk from the HW-8a list with its model, size, connection and
// partitions, says plainly that everything on it will be erased, and asks
// for a second, separate confirmation when it holds Windows, BitLocker or a
// boot loader, or could not be read whole. Accept takes the owner's yes
// only for the disk exactly as the page showed it, with the local
// confirmation and an approval code (CH-3 tier 4). This file decides and
// words; it erases, encrypts and writes nothing. Erasing and the vault-held
// key are the next part's (P2-4, P2-1), and the page itself is P2-2's.

// Fixed owner wording.
const (
	EraseText = "Everything on this disk will be erased. Nothing on it can be recovered afterwards."
	// MovesText says what moving the drive costs (HW-8a).
	MovesText = "I keep only what I can rebuild on this disk: model files, caches, swap and older snapshots. Your vault, my journal and everything needed to undo my work stay on the AgentOS Drive. If the drive moves to another PC, only what was on this disk is lost, and I rebuild it there."

	secondWindows  = "This disk holds Windows. Erasing it removes Windows and everything on it."
	secondEncrypt  = "This disk holds an encrypted Windows volume (BitLocker). Erasing it removes that volume and everything in it."
	secondBoot     = "Your PC may start from this disk. Once it is erased, the PC can no longer start Windows or another system from it."
	secondUnread   = "I couldn't read all of this disk, so I can't tell you everything it holds."
	secondQuestion = "Confirm separately that you want me to erase it."
)

// Refusals.
var (
	ErrDriveUnknown = errors.New("hostdisk: the AgentOS Drive could not be told apart from host disks")
	ErrNotListed    = errors.New("hostdisk: not a disk on the HW-8a list")
	ErrRemovable    = errors.New("hostdisk: removable media cannot be given to the box")
	ErrAlreadyGiven = errors.New("hostdisk: the box already has an internal disk")
	ErrChanged      = errors.New("hostdisk: the disk changed since the page showed it")
	ErrNeedLocal    = errors.New("hostdisk: needs the local confirmation on the page")
	ErrNeedCode     = errors.New("hostdisk: needs an approval code")
	ErrNeedSecond   = errors.New("hostdisk: needs the second confirmation")
)

// Offer is what the page shows for one disk.
type Offer struct {
	// Disk is the kernel name, for the page's form only: never shown (H13).
	Disk string
	// Lines describe the disk: model, size, connection, partitions.
	Lines []string
	Erase string
	// Second is the second confirmation's text, "" when none is needed.
	Second string
	Moves  string
	// Token binds a yes to the disk as described here.
	Token string
}

// Consent is the owner's answer on the page.
type Consent struct {
	Token string
	// Local: confirmed on the page on the box's own Wi-Fi.
	Local bool
	// Code: an approval code the owner channel checked (CH-3 tier 4).
	Code bool
	// Second: the separate second confirmation.
	Second bool
}

// OfferDisk describes disk name from l for the page. given is the disk the
// box already has, if any (HW-8a: one internal disk).
func OfferDisk(l Listing, name, given string) (Offer, error) {
	d, err := pick(l, name, given)
	if err != nil {
		return Offer{}, err
	}
	o := Offer{Disk: d.Name, Erase: EraseText, Moves: MovesText, Token: offerToken(d)}
	model := d.Model
	if model == "" {
		model = "no model name"
	}
	o.Lines = append(o.Lines, "Model: "+model, "Size: "+size(d.Size), "Connected by: "+busName[d.Bus])
	switch {
	case d.Problem == ProblemTable || d.Problem == ProblemOpen || d.Problem == ProblemSizeUnknown:
		o.Lines = append(o.Lines, "Partitions: could not be read")
	case len(d.Partitions) == 0 && d.Signature != SigNone:
		o.Lines = append(o.Lines, "No partitions; the whole disk is one "+sigName(d.Signature)+" volume")
	case len(d.Partitions) == 0:
		o.Lines = append(o.Lines, "No partitions")
	}
	for _, p := range d.Partitions {
		line := fmt.Sprintf("Partition %d: %s, %s", p.Number, size(p.Size), kindName[p.Kind])
		if p.Signature != SigNone && p.Kind != KindESP {
			line += " (" + sigName(p.Signature) + ")"
		}
		o.Lines = append(o.Lines, line)
	}
	if d.NeedsSecondConfirm() {
		var parts []string
		switch {
		case d.HasBitLocker:
			parts = append(parts, secondEncrypt)
		case d.HoldsWindows:
			parts = append(parts, secondWindows)
		}
		if d.HasBootLoader {
			parts = append(parts, secondBoot)
		}
		if d.Problem != ProblemNone {
			parts = append(parts, secondUnread)
		}
		parts = append(parts, secondQuestion)
		for i, p := range parts {
			if i > 0 {
				o.Second += " "
			}
			o.Second += p
		}
	}
	return o, nil
}

// Accept checks the owner's yes against a fresh listing and returns the
// disk to give the box. Every refusal of OfferDisk applies again.
func Accept(l Listing, name, given string, c Consent) (Disk, error) {
	d, err := pick(l, name, given)
	if err != nil {
		return Disk{}, err
	}
	switch {
	case c.Token == "" || c.Token != offerToken(d):
		return Disk{}, ErrChanged
	case !c.Local:
		return Disk{}, ErrNeedLocal
	case !c.Code:
		return Disk{}, ErrNeedCode
	case d.NeedsSecondConfirm() && !c.Second:
		return Disk{}, ErrNeedSecond
	}
	return d, nil
}

func pick(l Listing, name, given string) (Disk, error) {
	if l.Health != HealthOK {
		return Disk{}, ErrDriveUnknown
	}
	if given != "" {
		return Disk{}, ErrAlreadyGiven
	}
	for _, d := range l.Disks {
		if name != "" && d.Name == name {
			if d.Removable || d.Bus == BusUSB {
				return Disk{}, ErrRemovable
			}
			return d, nil
		}
	}
	return Disk{}, ErrNotListed
}

// offerToken hashes everything the page showed and where each partition starts,
// so a yes is stale once the disk differs in any of it.
func offerToken(d Disk) string {
	b, _ := json.Marshal(d)
	h := sha256.New()
	h.Write(b)
	for _, p := range d.Partitions {
		fmt.Fprintf(h, "|%d@%d", p.Number, p.Start)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// size is decimal, as disks are sold.
func size(n int64) string {
	f := float64(n)
	switch {
	case f >= 1e12:
		return fmt.Sprintf("%.1f TB", f/1e12)
	case f >= 10e9:
		return fmt.Sprintf("%.0f GB", f/1e9)
	case f >= 1e9:
		return fmt.Sprintf("%.1f GB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.0f MB", f/1e6)
	}
	return fmt.Sprintf("%.0f KB", f/1e3)
}

var busName = map[Bus]string{
	BusNVMe: "NVMe", BusSATA: "SATA", BusUSB: "USB", BusMMC: "memory card slot",
	BusVirtIO: "virtual disk", BusSCSI: "SCSI", BusOther: "other", "": "unknown",
}

var kindName = map[Kind]string{
	KindESP: "boot partition", KindBIOSBoot: "boot partition", KindMSR: "Windows reserved",
	KindBasicData: "Windows or data volume", KindWinRE: "Windows recovery", KindLinux: "Linux",
	KindLinuxSwap: "Linux swap", KindOther: "other", "": "other",
}

var sigNames = map[Signature]string{
	SigBitLocker: "encrypted", SigLUKS: "encrypted Linux", SigSwap: "swap",
	SigNTFS: "NTFS", SigFAT: "FAT", SigExFAT: "exFAT", SigReFS: "ReFS", SigExt: "ext", SigAPFS: "APFS", SigLVM: "LVM",
}

func sigName(s Signature) string {
	if n, ok := sigNames[s]; ok {
		return n
	}
	return "unknown"
}

// What the box may keep on a given disk (HW-8a): only data it can rebuild.
const (
	UseModels         = "models"
	UseCaches         = "caches"
	UseSwap           = "swap"
	UseOlderSnapshots = "older-snapshots"
)

// MayPlace reports whether data of kind use may go on the given disk. The
// boot path, the vault, the journal, recall, keys and the newest snapshot
// each agent machine needs (REV-1) never do.
func MayPlace(use string) bool {
	switch use {
	case UseModels, UseCaches, UseSwap, UseOlderSnapshots:
		return true
	}
	return false
}
