package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// REQ: ARC-1, DEV-net-h, CH-7, CRED-1

// The loader runs as root, so its unit bounds what root keeps: the
// network, firewall and child capabilities only (no CAP_DAC_OVERRIDE), a
// read-only system but for agentosd's state (the burn) with the vault and
// agentosd's other secrets hidden, no devices but the radio's rfkill, no
// kernel tunables (core_pattern would escape every sandbox), no core
// dumps (the setup network's password), and the inbound drop in place
// before it starts. hostapd parses frames from anyone in radio range.
func TestTheUnitIsBounded(t *testing.T) {
	b, err := os.ReadFile("agentos-ap.service")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "[") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		set[k] = append(set[k], v)
	}
	for k, want := range map[string][]string{
		"Requires": {"agentos-inbound.service"},
		// The secrets it hides exist before it starts (#1426).
		"After":                  {"agentos-inbound.service agentos-egress.service agentosd.service"},
		"CapabilityBoundingSet":  {"CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_READ_SEARCH CAP_SETPCAP"},
		"NoNewPrivileges":        {"yes"},
		"ProtectSystem":          {"strict"},
		"ReadWritePaths":         {"/var/lib/agentos"},
		"DevicePolicy":           {"closed"},
		"DeviceAllow":            {"/dev/rfkill rw"},
		"ProtectKernelTunables":  {"yes"},
		"RestrictNamespaces":     {"yes"},
		"ProtectProc":            {"invisible"},
		"PrivateIPC":             {"yes"},
		"MemoryDenyWriteExecute": {"yes"},
		"SystemCallFilter":       {"@system-service"},
		"RuntimeDirectoryMode":   {"0700"},
		"LimitCORE":              {"0"},
		"UMask":                  {"0077"},
		// hostapd runs as its own user (#1426): the loader, still root,
		// shares that user's group only to hand it hostapd.conf.
		"SupplementaryGroups": {"agentos-hostapd"},
	} {
		if strings.Join(set[k], "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, set[k], want)
		}
	}
	hidden := strings.Fields(strings.Join(set["InaccessiblePaths"], " "))
	// The vault's sockets check only uid == broker uid, which is root in
	// the shipped unit, so the loader must not reach them (#1628).
	for _, p := range []string{"-/var/lib/agentos-egress", "-/var/lib/agentos/vault", "-/run/agentos-egress"} {
		if !slices.Contains(hidden, p) {
			t.Errorf("InaccessiblePaths %q lacks %s", hidden, p)
		}
	}
	for _, p := range hidden {
		if strings.Contains(p, "owner.json") || strings.Contains(p, "setup-net") || strings.Contains(p, "ap-net") {
			t.Errorf("hides %s, which the loader reads or burns", p)
		}
	}
	if _, ok := set["User"]; ok {
		t.Error("the loader needs root for nft, systemctl and ip")
	}
	// The image creates hostapd's user (#1426); newHostapd fails closed
	// without it.
	su, err := os.ReadFile("../../../image/mkosi/mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(strings.Split(string(su), "\n"), func(l string) bool {
		return strings.HasPrefix(l, "u "+hostapdUser+" - ")
	}) {
		t.Errorf("sysusers.d declares no %s user", hostapdUser)
	}
}

// The mask on /run/agentos-egress is a mount over that directory; if egress's
// stop removed it, the kernel would detach the mask and the recreated
// directory, with fresh sockets, would show through until the loader
// restarts. A compromised loader can force that restart (CAP_KILL), so
// egress keeps the directory (#1628).
func TestEgressKeepsTheMaskedDirectory(t *testing.T) {
	b, err := os.ReadFile("../../../image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-egress.service")
	if err != nil {
		t.Fatal(err)
	}
	var dir, keep []string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), "=")
		switch k {
		case "RuntimeDirectory":
			dir = append(dir, v)
		case "RuntimeDirectoryPreserve":
			keep = append(keep, v)
		}
	}
	if !slices.Equal(dir, []string{"agentos-egress"}) || !slices.Equal(keep, []string{"yes"}) {
		t.Errorf("RuntimeDirectory = %q, RuntimeDirectoryPreserve = %q; want agentos-egress, yes", dir, keep)
	}
}

// loaderState is what the loader reaches under /var/lib/agentos: the setup
// network it reads and burns, the card's network it serves, and the owner
// state whose presence ends setup.
var loaderState = []string{"setup-net.json", "ap-net.json", "owner.json"}

// maskedDirs are agentosd's state directories under /var/lib/agentos. A
// mask on a directory survives agentosd's renames inside it, but only if
// the directory existed at loader start: the "-" skips a missing one, and
// agentosd makes most of them later (#2626). loop7 is no longer made
// (#2787 deleted it), but an upgraded box keeps its tree, so it stays masked.
// drill is not agentosd's: it holds the restore drill's record (#2932).
var maskedDirs = []string{"vault", "machines", "slots", "journal", "change", "recall", "learn", "skills", "modem", "digest", "loop7", "drill"}

// lapsingFiles are agentosd's state files at the top of /var/lib/agentos.
// The unit masks them, but a mask on a file lapses at agentosd's first
// rewrite (temp file and rename detaches the mount on the old dentry), so
// the loader reaches each one from then on. They stay exposed until
// #2626 moves the loader's files into their own directory.
var lapsingFiles = []string{"journal.log", "claim.json", "drive-id", "meter.json", "spare-meter.json", "kept-replies.json", "guest-inbox.json", "clock.json", "questions.json", "setup.json", "card-latch.json"}

// joinedState is agentosd state under /var/lib/agentos whose name is
// joined to the directory at run time (cmd/agentosd/questions.go), so a
// literal path may not name it.
var joinedState = []string{"questions.json", "clock.json"}

var statePath = regexp.MustCompile(`/var/lib/agentos/([A-Za-z0-9._-]+)`)

// Every state path under /var/lib/agentos that the broker's code or the
// image names is either one of the three the loader needs, a directory in
// maskedDirs (masked only if it existed at loader start), or a file in
// lapsingFiles, whose mask holds only until agentosd first rewrites it
// (#2626). This test does not show anything is hidden; it keeps a new
// path from going unclassed, and
// keeps the unit's masks and these lists the same.
func TestAgentosdStateIsHidden(t *testing.T) {
	b, err := os.ReadFile("agentos-ap.service")
	if err != nil {
		t.Fatal(err)
	}
	var masked []string
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "InaccessiblePaths="); ok {
			for _, p := range strings.Fields(v) {
				if n, ok := strings.CutPrefix(p, "-/var/lib/agentos/"); ok {
					masked = append(masked, n)
				}
			}
		}
	}
	slices.Sort(masked)
	want := slices.Concat(maskedDirs, lapsingFiles)
	slices.Sort(want)
	if !slices.Equal(masked, want) {
		t.Errorf("the unit masks %q under /var/lib/agentos; maskedDirs and lapsingFiles list %q", masked, want)
	}
	named := map[string]string{}
	for _, n := range joinedState {
		named[n] = "joinedState"
	}
	for _, root := range []string{"../..", "../../../image/mkosi/mkosi.extra"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "vendor" || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, "_test.go") || (root == "../.." && !strings.HasSuffix(p, ".go")) {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range statePath.FindAllSubmatch(src, -1) {
				named[string(m[1])] = p
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(named) < len(joinedState)+len(loaderState) {
		t.Fatalf("found only %d state paths; the walk is broken", len(named))
	}
	for n, where := range named {
		if !slices.Contains(loaderState, n) && !slices.Contains(want, n) {
			t.Errorf("/var/lib/agentos/%s (named in %s) is in none of loaderState, maskedDirs or lapsingFiles", n, where)
		}
	}
	for _, n := range loaderState {
		if _, ok := named[n]; !ok {
			t.Errorf("loaderState lists %s, which nothing names", n)
		}
	}
}
