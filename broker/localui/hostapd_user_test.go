package localui

// REQ: ARC-1, CRED-1, CH-7, DEV-net-h

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// probeUID is a uid and gid no image user holds; the probe runs hostapd
// as it.
const probeUID = 61426

// hostapd runs as its own user with NET_ADMIN and NET_RAW and nothing
// else (#1426): as root it would pass egress's uid-0 broker check and
// reach verify.sock's /recall-key. The stub hostapd records what it runs
// as and what it can read. Root only; CI's machines job runs it under the
// unit's capability bounding set, without CAP_CHOWN, with
// AGENTOS_REQUIRE_APUSER=1 so it cannot skip.
func TestHostapdChildRunsAsItsOwnUser(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("AGENTOS_REQUIRE_APUSER") == "1" {
			t.Fatal("AGENTOS_REQUIRE_APUSER=1 but not root")
		}
		t.Skip("needs root to start hostapd as another user")
	}
	// The stub's directory: hostapd's user runs the stub and writes its
	// report there.
	bin := t.TempDir()
	for _, d := range []string{filepath.Dir(bin), bin} {
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	report := filepath.Join(bin, "report")
	script := `#!/bin/sh
{
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapAmb):' /proc/self/status
cat "$1" >/dev/null 2>&1 && echo "conf readable" || echo "conf unreadable"
cat "$(dirname "$1")/dnsmasq.conf" >/dev/null 2>&1 && echo "dnsmasq.conf readable" || echo "dnsmasq.conf unreadable"
touch "$(dirname "$1")/planted" 2>/dev/null && echo "dir writable" || echo "dir unwritable"
} >` + report + `.tmp
mv ` + report + `.tmp ` + report + `
echo AP-ENABLED
exec sleep 30
`
	hp := filepath.Join(bin, "hostapd")
	if err := os.WriteFile(hp, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	dp, _ := stub(t, "dnsmasq", dnsmasqRuns)
	ip, _ := stub(t, "ip", "")
	run := t.TempDir()
	if err := os.Chmod(filepath.Dir(run), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, 0o711); err != nil {
		t.Fatal(err)
	}
	h := &Hostapd{HostapdPath: hp, DnsmasqPath: dp, IPPath: ip, Dir: filepath.Join(run, "ap"),
		User:  &APUser{UID: probeUID, GID: probeUID},
		Ready: 5 * time.Second, Settle: 100 * time.Millisecond, StopWait: 2 * time.Second}
	if err := h.Start(context.Background(), testAPConfig()); err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			k, v = l, ""
		}
		got[k] = strings.Join(strings.Fields(v), " ")
	}
	t.Logf("hostapd ran with %q", got)
	for k, want := range map[string]string{
		"Uid":    "61426 61426 61426 61426",
		"Gid":    "61426 61426 61426 61426",
		"Groups": "",
		"CapInh": "0000000000003000",
		"CapPrm": "0000000000003000",
		"CapEff": "0000000000003000",
		"CapAmb": "0000000000003000",
	} {
		if v, ok := got[k]; !ok || v != want {
			t.Errorf("hostapd's %s = %q, want %q (NET_ADMIN and NET_RAW only)", k, v, want)
		}
	}
	for _, want := range []string{"conf readable", "dnsmasq.conf unreadable", "dir unwritable"} {
		if _, ok := got[want]; !ok {
			t.Errorf("hostapd: want %q, got %q", want, got)
		}
	}
	// The password stays out of every other user's reach (CH-7).
	fi, err := os.Stat(filepath.Join(h.Dir, "hostapd.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("hostapd.conf mode %v, want 0640", fi.Mode().Perm())
	}
	if fi, err := os.Stat(h.Dir); err != nil {
		t.Error(err)
	} else if fi.Mode().Perm() != 0o710 {
		t.Errorf("%s mode %v, want 0710", h.Dir, fi.Mode().Perm())
	}
}

// A Hostapd never starts hostapd as root by name: a zero uid or gid is
// refused before anything runs.
func TestHostapdRefusesARootUser(t *testing.T) {
	for _, u := range []APUser{{UID: 0, GID: probeUID}, {UID: probeUID, GID: 0}} {
		h, ipLog := hostapdRig(t, hostapdUp, dnsmasqRuns)
		h.User = &u
		if err := h.Start(context.Background(), testAPConfig()); err == nil {
			h.Stop()
			t.Fatalf("Start with user %+v returned nil", u)
		}
		if _, err := os.Stat(ipLog); err == nil {
			t.Fatalf("user %+v: ran ip", u)
		}
	}
}
