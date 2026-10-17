package main

import (
	"os"
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
