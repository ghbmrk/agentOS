package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/claim"
)

// REQ: ARC-1, DEV-net-h, CH-7, CRED-1

// The loader runs as root, so its unit bounds what root keeps: the
// network, firewall and child capabilities only (no CAP_DAC_OVERRIDE), a
// read-only system with agentosd's state absent but for the loader's own
// directory (the burn) and the vault hidden, no devices but the radio's rfkill, no
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
		"After":                 {"agentos-inbound.service agentos-egress.service agentosd.service"},
		"CapabilityBoundingSet": {"CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_READ_SEARCH CAP_SETPCAP"},
		"NoNewPrivileges":       {"yes"},
		"ProtectSystem":         {"strict"},
		// agentosd's state is absent but for the loader's own
		// directory (#2626; TestOnlyTheLoadersDirectoryIsBound).
		"TemporaryFileSystem":    {"/var/lib/agentos:ro"},
		"BindPaths":              {apnet.Dir},
		"ReadWritePaths":         nil,
		"BindReadOnlyPaths":      nil,
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
	// the shipped unit, so the loader must not reach them (#1628). The
	// vault under /var/lib/agentos is absent with the rest (#2626).
	for _, p := range []string{"-/var/lib/agentos-egress", "-/run/agentos-egress"} {
		if !slices.Contains(hidden, p) {
			t.Errorf("InaccessiblePaths %q lacks %s", hidden, p)
		}
	}
	if _, ok := set["User"]; ok {
		t.Error("the loader needs root for nft, systemctl and ip")
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

// loaderState is what the loader reaches under /var/lib/agentos, all in
// its own directory (apnet.Dir): the setup network it reads and burns,
// the card's network it serves, and agentosd's owned marker, whose
// presence ends setup.
var loaderState = []string{claim.SetupNetPath, apnet.Path, apnet.Owned}

var statePath = regexp.MustCompile(`/var/lib/agentos(/[A-Za-z0-9._/-]*[A-Za-z0-9._-])?`)

// The loader's namespace holds /var/lib/agentos as an empty read-only
// tmpfs with only apnet.Dir bound in (#2626), so nothing agentosd keeps
// there is reachable unless it is inside that directory. Every state
// path under /var/lib/agentos that the broker's code or the image names
// is outside apnet.Dir or one of the loader's three files: a new path
// agentosd adds is hidden by default, and one put in the loader's
// directory fails here. The unit's flags name the same three files.
func TestOnlyTheLoadersDirectoryIsBound(t *testing.T) {
	b, err := os.ReadFile("agentos-ap.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, "=")
		for _, f := range strings.Fields(v) {
			f = strings.TrimLeft(f, "-+")
			if !strings.HasPrefix(f, "/var/lib/agentos/") && f != "/var/lib/agentos" {
				continue
			}
			ok := k == "TemporaryFileSystem" && f == "/var/lib/agentos:ro" ||
				k == "BindPaths" && f == apnet.Dir
			if !ok {
				t.Errorf("%s names %s; only apnet.Dir is bound in under /var/lib/agentos", k, f)
			}
		}
	}
	for _, flag := range []string{"-ap-net " + apnet.Path} {
		if !strings.Contains(string(b), flag) {
			t.Errorf("ExecStart lacks %s", flag)
		}
	}
	for _, p := range loaderState {
		if filepath.Dir(p) != apnet.Dir {
			t.Errorf("%s is not in the loader's directory %s", p, apnet.Dir)
		}
	}
	named := map[string]string{}
	for _, root := range []string{"../..", "../../../image"} {
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
			if strings.HasSuffix(p, "_test.go") || strings.HasSuffix(p, ".md") || (root == "../.." && !strings.HasSuffix(p, ".go")) {
				return nil
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range statePath.FindAll(src, -1) {
				named[string(m)] = p
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := named[claim.SetupNetPath]; !ok {
		t.Fatalf("the walk found no %s; it is broken", claim.SetupNetPath)
	}
	for n, where := range named {
		if strings.HasPrefix(n, apnet.Dir+"/") && !slices.Contains(loaderState, n) {
			t.Errorf("%s (named in %s) is in the loader's directory but is none of its files", n, where)
		}
	}
}
