package main

import (
	"os"
	"strings"
	"testing"
)

// REQ: DEV-net-h, CH-7

// The loader runs as root, so its unit bounds what root keeps: the
// network, firewall and child capabilities only, a read-only system but
// for agentosd's state (the burn), no core dumps (the setup network's
// password), and the inbound drop in place before it starts.
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
		"Requires":               {"agentos-inbound.service"},
		"After":                  {"agentos-inbound.service"},
		"CapabilityBoundingSet":  {"CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_KILL CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE"},
		"NoNewPrivileges":        {"yes"},
		"ProtectSystem":          {"strict"},
		"ReadWritePaths":         {"/var/lib/agentos"},
		"MemoryDenyWriteExecute": {"yes"},
		"SystemCallFilter":       {"@system-service"},
		"RuntimeDirectoryMode":   {"0700"},
		"LimitCORE":              {"0"},
		"UMask":                  {"0077"},
	} {
		if strings.Join(set[k], "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, set[k], want)
		}
	}
	if _, ok := set["User"]; ok {
		t.Error("the loader needs root for nft, systemctl and ip")
	}
}
