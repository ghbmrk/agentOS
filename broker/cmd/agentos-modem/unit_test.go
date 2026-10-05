package main

import (
	"os"
	"strings"
	"testing"
)

// REQ: CH-1

// Security S-B7 on the P2-3w design read: the bridge's unit runs as its
// own user with no privileges, a read-only system, a seccomp allow-list,
// no writable executable memory, the modems' device classes only, and no
// IP networking.
func TestTheUnitIsHardened(t *testing.T) {
	b, err := os.ReadFile("agentos-modem.service")
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
		"User":                    {"agentos-modem"},
		"NoNewPrivileges":         {"yes"},
		"CapabilityBoundingSet":   {""},
		"ProtectSystem":           {"strict"},
		"MemoryDenyWriteExecute":  {"yes"},
		"SystemCallFilter":        {"@system-service", "~@privileged @resources"},
		"DevicePolicy":            {"closed"},
		"DeviceAllow":             {"char-ttyUSB rw", "char-alsa rw"},
		"IPAddressDeny":           {"any"},
		"RestrictAddressFamilies": {"AF_UNIX"},
		"ProtectProc":             {"invisible"},
		"PrivateIPC":              {"yes"},
		"RemoveIPC":               {"yes"},
		"TemporaryFileSystem":     {"/var/lib/agentos:ro"},
		"BindReadOnlyPaths":       {"/var/lib/agentos/modem-roles.json"},
	} {
		if strings.Join(set[k], "|") != strings.Join(want, "|") {
			t.Errorf("%s = %q, want %q", k, set[k], want)
		}
	}
	// The socket agentosd serves (its -sockets default plus owner.sock),
	// not a path nothing listens on (security F2 on #170).
	exec := strings.Join(set["ExecStart"], "")
	if want := "-owner-sock /run/agentos/owner.sock "; !strings.Contains(exec, want) {
		t.Errorf("ExecStart %q lacks %q", exec, want)
	}
	// No number on the command line, where any process could read it.
	if strings.Contains(exec, "NUMBER") || strings.Contains(exec, "-owner-number") {
		t.Errorf("ExecStart %q carries a number", exec)
	}
}

func TestRolesAreReadAtEachOpen(t *testing.T) {
	p := t.TempDir() + "/roles.json"
	if got := ownerICCID(p); got != "" {
		t.Fatalf("no file: %q", got)
	}
	os.WriteFile(p, []byte(`{"owner_iccid":"8901555000010000000F"}`), 0o600)
	if got := ownerICCID(p); got != "8901555000010000000F" {
		t.Fatalf("got %q", got)
	}
	os.WriteFile(p, []byte(`not json`), 0o600)
	if got := ownerICCID(p); got != "" {
		t.Fatalf("bad file: %q", got)
	}
}
