package hostdisk

import (
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// REQ: HW-8

// udevProbe is what the stock rules would find on a device: blkid's file
// system result, cdrom_id's answer and a device-mapper UUID.
type udevProbe struct {
	fsType, fsUsage, label string
	cdrom                  bool
	dmUUID                 string
	scsiType               string
}

// udevDev is a device as the rules see it: its properties and the result
// of rule processing.
type udevDev struct {
	kernel, subsystem, action string
	probe                     udevProbe
	env                       map[string]string
	owner, group, mode        string
	locked                    map[string]bool
	tags                      map[string]bool
	links                     []string
	written                   []string // what a stock rule would write: md, LVM, bcache
}

type udevKV struct{ key, op, val string }

func parseRules(t *testing.T, file string) [][]udevKV {
	t.Helper()
	b, err := os.ReadFile("udev/" + file)
	if err != nil {
		t.Fatal(err)
	}
	pair := regexp.MustCompile(`^([A-Z]+(?:\{[A-Za-z_]+\})?)(==|!=|=|\+=|-=|:=)"([^"]*)"$`)
	var rules [][]udevKV
	for n, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		var r []udevKV
		for _, kv := range strings.Split(l, ", ") {
			m := pair.FindStringSubmatch(kv)
			if m == nil {
				t.Fatalf("%s line %d: cannot parse %q", file, n+1, kv)
			}
			r = append(r, udevKV{m[1], m[2], m[3]})
		}
		rules = append(rules, r)
	}
	return rules
}

// globMatch is udev's pattern match: "|" separates alternatives.
func globMatch(pat, s string) bool {
	for _, p := range strings.Split(pat, "|") {
		if ok, _ := path.Match(p, s); ok {
			return true
		}
	}
	return false
}

// runRules evaluates one rule file on d the way udev does for the keys it
// uses. classify stands in for the helper (its stdout); parent is the
// parent disk's properties after its own event.
func runRules(t *testing.T, rules [][]udevKV, d *udevDev, classify func(string) string, parent map[string]string) {
	t.Helper()
	skipTo := ""
	for _, r := range rules {
		if skipTo != "" {
			if r[0].key == "LABEL" && r[0].val == skipTo {
				skipTo = ""
			}
			continue
		}
		matched := true
		for _, kv := range r {
			if kv.op != "==" && kv.op != "!=" {
				continue
			}
			var v string
			switch {
			case kv.key == "ACTION":
				v = d.action
			case kv.key == "SUBSYSTEM":
				v = d.subsystem
			case kv.key == "KERNEL":
				v = d.kernel
			case strings.HasPrefix(kv.key, "ENV{"):
				v = d.env[kv.key[4:len(kv.key)-1]]
			default:
				t.Fatalf("unhandled match key %s", kv.key)
			}
			if globMatch(kv.val, v) != (kv.op == "==") {
				matched = false
			}
		}
		if !matched {
			continue
		}
		for _, kv := range r {
			switch {
			case kv.op == "==" || kv.op == "!=" || kv.key == "LABEL":
			case kv.key == "GOTO":
				skipTo = kv.val
			case kv.key == "IMPORT{program}":
				out := classify(strings.ReplaceAll(kv.val, "%k", d.kernel))
				for _, l := range strings.Split(out, "\n") {
					if k, v, ok := strings.Cut(l, "="); ok {
						d.env[k] = v
					}
				}
			case kv.key == "IMPORT{parent}":
				if v, ok := parent[kv.val]; ok {
					d.env[kv.val] = v
				}
			case strings.HasPrefix(kv.key, "ENV{") && kv.op == "=":
				d.env[kv.key[4:len(kv.key)-1]] = kv.val
			case kv.key == "TAG" && kv.op == "-=":
				delete(d.tags, kv.val)
			case kv.key == "TAG" && kv.op == "+=":
				d.tags[kv.val] = true
			case kv.key == "OWNER" || kv.key == "GROUP" || kv.key == "MODE":
				if d.locked[kv.key] {
					continue
				}
				if kv.op == ":=" {
					d.locked[kv.key] = true
				}
				switch kv.key {
				case "OWNER":
					d.owner = kv.val
				case "GROUP":
					d.group = kv.val
				case "MODE":
					d.mode = kv.val
				}
			default:
				t.Fatalf("unhandled assignment %s%s", kv.key, kv.op)
			}
		}
	}
}

// The stock rules the AgentOS files sit between, modelled for the keys
// that matter here: systemd's 60-persistent-storage, 70-uaccess and
// 99-systemd; dmsetup's 60-persistent-storage-dm (Debian and Ubuntu);
// mdadm's 64-md-raid-assembly, lvm2's 69-lvm and bcache-tools' 69-bcache.
// cdrom_id's ID_CDROM is taken as already set. The real files' behaviour
// is a P2-1 VM-test carry (ASSUMPTIONS H8).

func (d *udevDev) blkid() {
	if d.probe.fsType == "" {
		return
	}
	d.env["ID_FS_TYPE"], d.env["ID_FS_USAGE"] = d.probe.fsType, d.probe.fsUsage
	if d.probe.label != "" {
		d.env["ID_FS_LABEL"] = d.probe.label
		d.links = append(d.links, "disk/by-label/"+d.probe.label)
	}
}

// persistentStorage: skipped when the flag is set, and for dm and md
// devices, which it does not list; otherwise blkid records the file
// system and its label, and by-label links appear.
func persistentStorage(d *udevDev) {
	if d.action == "remove" || d.subsystem != "block" || d.env["UDEV_DISABLE_PERSISTENT_STORAGE_RULES_FLAG"] == "1" ||
		strings.HasPrefix(d.kernel, "dm-") || strings.HasPrefix(d.kernel, "md") {
		return
	}
	d.blkid()
}

// persistentStorageDM: dm devices are probed here, whatever the flag says.
func persistentStorageDM(d *udevDev) {
	if d.action != "remove" && d.subsystem == "block" && strings.HasPrefix(d.kernel, "dm-") {
		d.blkid()
	}
}

// assembly: md assembles a RAID member and LVM scans a PV; bcache-tools
// probes any device with no type and registers a bcache one. Each is a
// write to the device.
func assembly(d *udevDev) {
	if d.action == "remove" || d.subsystem != "block" {
		return
	}
	switch t := d.env["ID_FS_TYPE"]; {
	case t == "linux_raid_member" || t == "LVM2_member":
		d.written = append(d.written, t)
	case t == "" && d.probe.fsType == "bcache", t == "bcache":
		d.written = append(d.written, "bcache")
	}
}

// uaccess: optical drives (block or SCSI generic) get the seat user's tag.
func uaccess(d *udevDev) {
	if d.subsystem == "block" && d.env["ID_CDROM"] == "1" ||
		d.subsystem == "scsi_generic" && globMatch("4|5", d.probe.scsiType) {
		d.tags["uaccess"] = true
	}
}

// systemdReady: a dm-crypt or dm-verity device with no file system result
// is not ready, so nothing waiting on it (the root) starts.
func systemdReady(d *udevDev) {
	if d.subsystem == "block" && strings.HasPrefix(d.env["DM_UUID"], "CRYPT-") && d.env["ID_FS_USAGE"] == "" {
		d.env["SYSTEMD_READY"] = "0"
	}
}

// udevStack runs an event through every rule file in udev's order.
type udevStack struct {
	t        *testing.T
	ours     map[string][][]udevKV
	classify func(string) string
}

func newUdevStack(t *testing.T, classify func(string) string) *udevStack {
	s := &udevStack{t: t, ours: map[string][][]udevKV{}, classify: classify}
	for _, f := range []string{"59-agentos-host-disks.rules", "61-agentos-host-disks-assembly.rules", "72-agentos-host-disks-late.rules"} {
		s.ours[f[:2]] = parseRules(t, f)
	}
	return s
}

func (s *udevStack) run(d *udevDev, parent map[string]string) {
	d.locked, d.tags = map[string]bool{}, map[string]bool{}
	if d.probe.cdrom {
		d.env["ID_CDROM"] = "1"
	}
	if d.probe.dmUUID != "" {
		d.env["DM_UUID"] = d.probe.dmUUID
	}
	runRules(s.t, s.ours["59"], d, s.classify, parent)
	persistentStorage(d)
	persistentStorageDM(d)
	runRules(s.t, s.ours["61"], d, s.classify, parent)
	assembly(d)
	uaccess(d)
	runRules(s.t, s.ours["72"], d, s.classify, parent)
	systemdReady(d)
}

// hidden: the host-disk outcome. A dm device keeps the links
// 60-persistent-storage-dm made (ASSUMPTIONS H8); nothing else does.
func hidden(d *udevDev) bool {
	return d.env["SYSTEMD_READY"] == "0" && d.env["UDISKS_IGNORE"] == "1" && d.env["UDISKS_AUTO"] == "0" &&
		d.env["ID_FS_TYPE"] == "agentos_held" && d.env["ID_FS_USAGE"] == "" && d.env["ID_FS_LABEL"] == "" &&
		(len(d.links) == 0 || strings.HasPrefix(d.kernel, "dm-")) && len(d.written) == 0 &&
		d.owner == "root" && d.group == "root" && d.mode == "0600" &&
		d.locked["OWNER"] && d.locked["GROUP"] && d.locked["MODE"] && !d.tags["uaccess"]
}

func blockDev(kernel, devtype string) *udevDev {
	return &udevDev{kernel: kernel, subsystem: "block", action: "add", group: "disk", mode: "0660",
		probe: udevProbe{fsType: "ntfs", fsUsage: "filesystem", label: "OWNERDATA"},
		env:   map[string]string{"DEVTYPE": devtype}}
}

// outcome is what the rules did to a device.
type outcome int

const (
	untouched outcome = iota
	keptFromUdisks
	hiddenFully
)

func (o outcome) String() string { return [...]string{"untouched", "kept from udisks", "hidden"}[o] }

func outcomeOf(d *udevDev) outcome {
	switch {
	case hidden(d):
		return hiddenFully
	case d.env["UDISKS_IGNORE"] == "1" && d.env["UDISKS_AUTO"] == "0" && d.env["SYSTEMD_READY"] == "" && d.group == "disk" &&
		len(d.written) == 0 && !d.tags["uaccess"]:
		return keptFromUdisks
	case d.env["UDISKS_IGNORE"] == "" && d.env["SYSTEMD_READY"] == "" && d.group == "disk" && d.env["ID_FS_TYPE"] == d.probe.fsType:
		return untouched
	}
	return -1
}

const hostdiskHelper = "/usr/lib/agentos/agentos-hostdisk classify "

func testClassify(t *testing.T) func(string) string {
	return func(cmd string) string {
		if !strings.HasPrefix(cmd, hostdiskHelper) {
			t.Fatalf("helper %q", cmd)
		}
		switch strings.TrimPrefix(cmd, hostdiskHelper) {
		case "sda", "dm-0":
			return "AGENTOS_DISK=drive\n"
		case "sdc":
			return "" // the helper failed
		case "sdd":
			return "AGENTOS_DISK=Host\n"
		case "sde", "dm-2":
			return "AGENTOS_DISK=unknown\n"
		}
		return "AGENTOS_DISK=host\n"
	}
}

// Security H2 on HOST-1a: host disks and their partitions are hidden from
// systemd units, udisks, blkid, LVM/MD assembly and every other uid; the
// drive and the box's virtual devices are left alone; a device the helper
// calls unknown, or for which it fails or prints anything else, is only
// kept from udisks and assembly, so the box still boots.
func TestUdevRuleHidesHostDisks(t *testing.T) {
	s := newUdevStack(t, testClassify(t))
	sr0 := blockDev("sr0", "disk")
	sr0.probe = udevProbe{fsType: "iso9660", fsUsage: "filesystem", label: "OWNERDISC", cdrom: true}
	cases := []struct {
		dev    *udevDev
		parent string
		want   outcome
	}{
		{blockDev("sda", "disk"), "", untouched},
		{blockDev("sda2", "partition"), "sda", untouched},
		{blockDev("dm-0", "disk"), "", untouched},
		{blockDev("nvme0n1", "disk"), "", hiddenFully},
		{blockDev("nvme0n1p3", "partition"), "nvme0n1", hiddenFully},
		{blockDev("sdb", "disk"), "", hiddenFully},
		{blockDev("sdb1", "partition"), "sdb", hiddenFully},
		{blockDev("mmcblk0", "disk"), "", hiddenFully},
		{sr0, "", hiddenFully},
		{blockDev("dm-1", "disk"), "", hiddenFully},
		{blockDev("md0", "disk"), "", hiddenFully},
		{blockDev("sdc", "disk"), "", keptFromUdisks},
		{blockDev("sdc1", "partition"), "sdc", keptFromUdisks},
		{blockDev("sdd", "disk"), "", keptFromUdisks},
		{blockDev("sde", "disk"), "", keptFromUdisks},
		{blockDev("sde1", "partition"), "sde", keptFromUdisks},
		{blockDev("loop0", "disk"), "", untouched},
		{blockDev("zram0", "disk"), "", untouched},
		{blockDev("nbd0", "disk"), "", untouched},
	}
	parents := map[string]map[string]string{}
	for _, c := range cases {
		s.run(c.dev, parents[c.parent])
		if c.dev.env["DEVTYPE"] == "disk" {
			parents[c.dev.kernel] = c.dev.env
		}
		if got := outcomeOf(c.dev); got != c.want {
			t.Errorf("%s: %v, want %v (%+v)", c.dev.kernel, got, c.want, c.dev)
		}
	}

	// Security F1 and L3 on #172: a RAID, LVM or bcache member on an unknown
	// or host disk is neither assembled nor registered (a resync, an
	// activation or a journal replay would write it); the type is held,
	// never left empty, since bcache-tools probes and registers a device
	// with no type. An unknown disk's .device unit stays so the box still
	// boots.
	for _, typ := range []string{"linux_raid_member", "LVM2_member", "isw_raid_member", "ddf_raid_member", "bcache", "zfs_member"} {
		for _, c := range []struct {
			kernel string
			want   outcome
		}{{"sde", keptFromUdisks}, {"sdb", hiddenFully}, {"dm-2", keptFromUdisks}, {"dm-1", hiddenFully}} {
			d := blockDev(c.kernel, "disk")
			d.probe.fsType, d.probe.fsUsage = typ, "raid"
			s.run(d, nil)
			if d.env["ID_FS_TYPE"] != "agentos_held" || len(d.written) != 0 || outcomeOf(d) != c.want {
				t.Errorf("%s %s member: %v %+v", c.kernel, typ, outcomeOf(d), d)
			}
		}
	}
	// The drive's own members are left for the stock rules.
	d := blockDev("sda", "disk")
	d.probe.fsType, d.probe.fsUsage = "LVM2_member", "raid"
	s.run(d, nil)
	if d.env["ID_FS_TYPE"] != "LVM2_member" || len(d.written) != 1 {
		t.Errorf("drive LVM member: %+v", d)
	}
	// The model itself: with no type, bcache-tools finds and registers a
	// bcache device.
	ctl := blockDev("loop0", "disk")
	ctl.probe.fsType = "bcache"
	ctl.env["ID_FS_TYPE"] = ""
	assembly(ctl)
	if len(ctl.written) != 1 {
		t.Errorf("bcache control: %+v", ctl)
	}

	// A remove event and a non-block device are untouched.
	rm := blockDev("sdb", "disk")
	rm.action = "remove"
	s.run(rm, nil)
	if rm.env["AGENTOS_DISK"] != "" || rm.env["UDISKS_IGNORE"] != "" || rm.group != "disk" {
		t.Errorf("remove event processed: %+v", rm)
	}
	tty := blockDev("ttyS0", "")
	tty.subsystem = "tty"
	s.run(tty, nil)
	if tty.env["AGENTOS_DISK"] != "" || tty.group != "disk" || tty.env["ID_FS_TYPE"] != "" {
		t.Errorf("tty processed: %+v", tty)
	}
}

// L3 MUST on #172: when the helper cannot place the box's own dm-verity or
// dm-crypt device (unknown), its file system result stays, so 99-systemd
// does not mark it not ready and the root still mounts.
func TestUdevRuleUnknownVerityStaysReady(t *testing.T) {
	s := newUdevStack(t, testClassify(t))
	for _, uuid := range []string{"CRYPT-VERITY-0123456789abcdef-root", "CRYPT-LUKS2-0123456789abcdef-home"} {
		for _, fs := range [][2]string{{"erofs", "filesystem"}, {"LVM2_member", "raid"}, {"linux_raid_member", "raid"}} {
			d := blockDev("dm-2", "disk")
			d.probe = udevProbe{fsType: fs[0], fsUsage: fs[1], dmUUID: uuid}
			s.run(d, nil)
			if d.env["ID_FS_USAGE"] != fs[1] || d.env["SYSTEMD_READY"] != "" || outcomeOf(d) != keptFromUdisks {
				t.Errorf("unknown %s holding %s: %+v", uuid, fs[0], d)
			}
		}
	}
	// The model itself: a CRYPT device with no file system result is not ready.
	d := blockDev("dm-2", "disk")
	d.probe = udevProbe{dmUUID: "CRYPT-VERITY-x"}
	s.run(d, nil)
	if d.env["SYSTEMD_READY"] != "0" {
		t.Errorf("control: %+v", d)
	}
}

// L3 on #172: the uaccess tag 70-uaccess gives optical drives is taken back
// from a host disc, and the SCSI and NVMe generic nodes, which reach any
// disk with commands that write, are root-only for every disk.
func TestUdevRuleClosesGenericNodes(t *testing.T) {
	s := newUdevStack(t, testClassify(t))
	for _, c := range []struct{ kernel, subsystem, scsiType string }{
		{"sg0", "scsi_generic", "0"},
		{"sg1", "scsi_generic", "5"},
		{"ng0n1", "nvme-generic", ""},
	} {
		d := &udevDev{kernel: c.kernel, subsystem: c.subsystem, action: "add", owner: "root", group: "disk", mode: "0660",
			probe: udevProbe{scsiType: c.scsiType}, env: map[string]string{}}
		s.run(d, nil)
		if d.owner != "root" || d.group != "root" || d.mode != "0600" || !d.locked["MODE"] || !d.locked["GROUP"] || d.tags["uaccess"] {
			t.Errorf("%s: %+v", c.kernel, d)
		}
	}
	// Only the drive's own optical drive (none ships, but the rule must
	// not reach past host and unknown) keeps the stock tag.
	for kernel, cls := range map[string]string{"sr0": "host", "sr1": "drive", "sr2": "unknown", "sr3": ""} {
		d := blockDev(kernel, "disk")
		d.probe.cdrom = true
		classify := func(string) string { return "AGENTOS_DISK=" + cls + "\n" }
		newUdevStack(t, classify).run(d, nil)
		if d.tags["uaccess"] != (cls == "drive") {
			t.Errorf("%s (%q) uaccess %v", kernel, cls, d.tags["uaccess"])
		}
	}
}
