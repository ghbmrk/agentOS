package hostdisk

// REQ: HW-8a, HW-8

import (
	"errors"
	"strings"
	"testing"
)

func windowsDisk() Disk {
	return Disk{
		Name: "nvme0n1", Model: "Example NVMe 1TB", Size: 1_000_204_886_016, Bus: BusNVMe, Table: TableGPT,
		Partitions: []Partition{
			{Number: 1, Start: 1 << 20, Size: 100_000_000, Kind: KindESP, Signature: SigFAT},
			{Number: 2, Start: 101 << 20, Size: 16 << 20, Kind: KindMSR},
			{Number: 3, Start: 117 << 20, Size: 999_000_000_000, Kind: KindBasicData, Signature: SigBitLocker},
		},
		HoldsWindows: true, HasBitLocker: true, HasBootLoader: true,
	}
}

func dataDisk() Disk {
	return Disk{
		Name: "sda", Model: "Example SATA 2TB", Size: 2_000_398_934_016, Bus: BusSATA, Table: TableGPT,
		Partitions: []Partition{{Number: 1, Start: 1 << 20, Size: 2_000_000_000_000, Kind: KindBasicData, Signature: SigNTFS}},
	}
}

func listing(ds ...Disk) Listing { return Listing{Disks: ds} }

// HW-8a: the page shows the disk's model, size and partition list from the
// table, and says plainly that everything on it will be erased. A plain
// data disk needs no second confirmation; kernel names never show (H13).
func TestOfferShowsModelSizePartitionsAndErase(t *testing.T) {
	o, err := OfferDisk(listing(dataDisk(), windowsDisk()), "sda", "")
	if err != nil {
		t.Fatal(err)
	}
	page := strings.Join(o.Lines, "\n")
	for _, want := range []string{"Example SATA 2TB", "2.0 TB", "SATA", "Partition 1: 2.0 TB, Windows or data volume (NTFS)"} {
		if !strings.Contains(page, want) {
			t.Fatalf("offer lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, "sda") {
		t.Fatalf("offer shows the kernel name:\n%s", page)
	}
	if o.Erase != EraseText || !strings.Contains(o.Erase, "Everything on this disk will be erased") {
		t.Fatalf("erase text %q", o.Erase)
	}
	if o.Second != "" {
		t.Fatalf("a plain data disk asked for a second confirmation: %q", o.Second)
	}
	if !strings.Contains(o.Moves, "only what was on this disk is lost") {
		t.Fatalf("moves text %q", o.Moves)
	}
}

// HW-8a: a disk holding BitLocker or the host's boot loader needs a second,
// separate confirmation, worded for what it holds; so does a disk that
// could not be read whole.
func TestOfferAsksSecondConfirmationForWindowsBootOrUnreadable(t *testing.T) {
	o, err := OfferDisk(listing(windowsDisk()), "nvme0n1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Second, "encrypted Windows volume") || !strings.Contains(o.Second, "may start from this disk") {
		t.Fatalf("second confirmation %q", o.Second)
	}
	page := strings.Join(o.Lines, "\n")
	for _, want := range []string{"Partition 1: 100 MB, boot partition", "Partition 2: 17 MB, Windows reserved", "Partition 3: 999 GB, Windows or data volume (encrypted)"} {
		if !strings.Contains(page, want) {
			t.Fatalf("offer lacks %q:\n%s", want, page)
		}
	}
	bad := dataDisk()
	bad.Problem = ProblemPartial
	o, err = OfferDisk(listing(bad), "sda", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(o.Second, "couldn't read all of this disk") {
		t.Fatalf("unreadable disk: %q", o.Second)
	}
}

// HW-8: only a listed host disk is offered, never while the drive could not
// be told apart (H13), never removable media (H12), and only one disk.
func TestOfferRefusals(t *testing.T) {
	usb := dataDisk()
	usb.Name, usb.Bus, usb.Removable = "sdb", BusUSB, true
	l := listing(dataDisk(), usb)
	for name, c := range map[string]struct {
		l     Listing
		disk  string
		given string
		want  error
	}{
		"health":   {Listing{Disks: l.Disks, Health: HealthNoRoot}, "sda", "", ErrDriveUnknown},
		"unlisted": {l, "nvme9n1", "", ErrNotListed},
		"empty":    {l, "", "", ErrNotListed},
		"usb":      {l, "sdb", "", ErrRemovable},
		"second":   {l, "sda", "nvme0n1", ErrAlreadyGiven},
	} {
		if _, err := OfferDisk(c.l, c.disk, c.given); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

// The owner's yes counts only for the disk as the page showed it, with the
// local confirmation and the approval code (CH-3 tier 4), and with the
// second confirmation where the offer asked for one.
func TestAcceptNeedsEveryConfirmationForTheDiskShown(t *testing.T) {
	l := listing(windowsDisk())
	o, err := OfferDisk(l, "nvme0n1", "")
	if err != nil {
		t.Fatal(err)
	}
	full := Consent{Token: o.Token, Local: true, Code: true, Second: true}
	if d, err := Accept(l, "nvme0n1", "", full); err != nil || d.Name != "nvme0n1" {
		t.Fatalf("accept: %+v %v", d, err)
	}
	for name, c := range map[string]struct {
		c    Consent
		want error
	}{
		"no local":  {Consent{Token: o.Token, Code: true, Second: true}, ErrNeedLocal},
		"no code":   {Consent{Token: o.Token, Local: true, Second: true}, ErrNeedCode},
		"no second": {Consent{Token: o.Token, Local: true, Code: true}, ErrNeedSecond},
		"no token":  {Consent{Local: true, Code: true, Second: true}, ErrChanged},
	} {
		if _, err := Accept(l, "nvme0n1", "", c.c); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	// The disk changed after the page showed it (another partition, a
	// moved one, a new signature): the yes is stale.
	for name, mod := range map[string]func(*Disk){
		"partition added": func(d *Disk) {
			d.Partitions = append(d.Partitions, Partition{Number: 4, Start: 1 << 40, Size: 1 << 20, Kind: KindLinux})
		},
		"partition moved": func(d *Disk) { d.Partitions[2].Start += 4096 },
		"signature":       func(d *Disk) { d.Partitions[2].Signature = SigNTFS },
		"model":           func(d *Disk) { d.Model = "Other" },
	} {
		d := windowsDisk()
		mod(&d)
		if _, err := Accept(listing(d), "nvme0n1", "", full); !errors.Is(err, ErrChanged) {
			t.Errorf("%s: %v, want ErrChanged", name, err)
		}
	}
	// A refusal at offer time is a refusal at accept time.
	if _, err := Accept(Listing{Disks: l.Disks, Health: HealthMismatch}, "nvme0n1", "", full); !errors.Is(err, ErrDriveUnknown) {
		t.Fatalf("accept with unknown drive: %v", err)
	}
}

// HW-8a: only data the box can rebuild goes on the given disk; the boot
// path, vault, journal and anything rollback needs stay on the drive.
func TestOnlyRebuildableDataIsPlacedOnTheDisk(t *testing.T) {
	for _, u := range []string{UseModels, UseCaches, UseSwap, UseOlderSnapshots} {
		if !MayPlace(u) {
			t.Errorf("%s refused", u)
		}
	}
	for _, u := range []string{"vault", "journal", "boot", "latest-snapshot", "recall", "keys", "", "Models"} {
		if MayPlace(u) {
			t.Errorf("%q allowed on a host disk", u)
		}
	}
}
