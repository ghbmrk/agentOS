package hostdisk

import (
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
)

// REQ: HW-8

// udevDev is a device as the rule sees it: its properties and the result
// of rule processing.
type udevDev struct {
	kernel, subsystem, action string
	env                       map[string]string
	owner, group, mode        string
	locked                    map[string]bool
	tags                      map[string]bool
}

type udevKV struct{ key, op, val string }

func parseRules(t *testing.T) [][]udevKV {
	t.Helper()
	b, err := os.ReadFile("udev/61-agentos-host-disks.rules")
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
				t.Fatalf("line %d: cannot parse %q", n+1, kv)
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

// runRules evaluates the rule file on d the way udev does for the keys it
// uses. classify stands in for the helper (its stdout); parent is the
// parent disk's properties after its own event.
func runRules(t *testing.T, rules [][]udevKV, d *udevDev, classify func(string) string, parent map[string]string) {
	t.Helper()
	d.locked, d.tags = map[string]bool{}, map[string]bool{"uaccess": true}
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
			case strings.HasPrefix(kv.key, "ENV{"):
				d.env[kv.key[4:len(kv.key)-1]] = kv.val
			case kv.key == "TAG" && kv.op == "-=":
				delete(d.tags, kv.val)
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

func hidden(d *udevDev) bool {
	return d.env["SYSTEMD_READY"] == "0" && d.env["UDISKS_IGNORE"] == "1" && d.env["UDISKS_AUTO"] == "0" &&
		d.env["ID_FS_TYPE"] == "" && d.env["ID_FS_USAGE"] == "" &&
		d.owner == "root" && d.group == "root" && d.mode == "0600" &&
		d.locked["OWNER"] && d.locked["GROUP"] && d.locked["MODE"] && !d.tags["uaccess"]
}

func blockDev(kernel, devtype string) *udevDev {
	return &udevDev{kernel: kernel, subsystem: "block", action: "add", group: "disk", mode: "0660",
		env: map[string]string{"DEVTYPE": devtype, "ID_FS_TYPE": "ntfs", "ID_FS_USAGE": "filesystem"}}
}

// outcome is what the rule did to a device.
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
	case d.env["UDISKS_IGNORE"] == "1" && d.env["UDISKS_AUTO"] == "0" && d.env["SYSTEMD_READY"] == "" &&
		d.group == "disk" && d.env["ID_FS_TYPE"] == "" && d.env["ID_FS_USAGE"] == "":
		return keptFromUdisks
	case d.env["UDISKS_IGNORE"] == "" && d.env["SYSTEMD_READY"] == "" && d.group == "disk" && d.env["ID_FS_TYPE"] == "ntfs":
		return untouched
	}
	return -1
}

// Security H2 on HOST-1a: host disks and their partitions are hidden from
// systemd units, udisks, LVM/MD assembly and every other uid; the drive
// and the box's virtual devices are left alone; a device the helper calls
// unknown, or for which it fails or prints anything else, is only kept
// from udisks, so the box still boots.
func TestUdevRuleHidesHostDisks(t *testing.T) {
	rules := parseRules(t)
	const helper = "/usr/lib/agentos/agentos-hostdisk classify "
	classify := func(cmd string) string {
		if !strings.HasPrefix(cmd, helper) {
			t.Fatalf("helper %q", cmd)
		}
		switch strings.TrimPrefix(cmd, helper) {
		case "sda", "dm-0":
			return "AGENTOS_DISK=drive\n"
		case "sdc":
			return "" // the helper failed
		case "sdd":
			return "AGENTOS_DISK=Host\n"
		case "sde":
			return "AGENTOS_DISK=unknown\n"
		}
		return "AGENTOS_DISK=host\n"
	}
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
		{blockDev("sr0", "disk"), "", hiddenFully},
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
		runRules(t, rules, c.dev, classify, parents[c.parent])
		if c.dev.env["DEVTYPE"] == "disk" {
			parents[c.dev.kernel] = c.dev.env
		}
		if got := outcomeOf(c.dev); got != c.want {
			t.Errorf("%s: %v, want %v (%+v)", c.dev.kernel, got, c.want, c.dev)
		}
	}

	// Security F1 on #172: an unknown disk holding a RAID or LVM member
	// is not assembled (a degraded array's resync would write it), and its
	// .device unit stays so the box still boots.
	for _, typ := range []string{"linux_raid_member", "LVM2_member", "isw_raid_member"} {
		d := blockDev("sde", "disk")
		d.env["ID_FS_TYPE"], d.env["ID_FS_USAGE"] = typ, "raid"
		runRules(t, rules, d, classify, nil)
		if d.env["ID_FS_TYPE"] != "" || d.env["ID_FS_USAGE"] != "" || d.env["SYSTEMD_READY"] != "" || outcomeOf(d) != keptFromUdisks {
			t.Errorf("unknown %s member: %+v", typ, d)
		}
	}

	// A remove event and a non-block device are untouched.
	rm := blockDev("sdb", "disk")
	rm.action = "remove"
	runRules(t, rules, rm, classify, nil)
	if outcomeOf(rm) != untouched {
		t.Error("remove event processed")
	}
	tty := blockDev("ttyS0", "")
	tty.subsystem = "tty"
	runRules(t, rules, tty, classify, nil)
	if outcomeOf(tty) != untouched {
		t.Error("tty processed")
	}
}
