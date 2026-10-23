package localui

// REQ: ARC-1, CRED-1, CH-7

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
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
grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/self/status
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
		// Nothing it execs can regain more: the bounding set holds the
		// two alone and no_new_privs stops setuid and file capabilities.
		"CapBnd":     "0000000000003000",
		"NoNewPrivs": "1",
	} {
		if v, ok := got[k]; !ok || v != want {
			t.Errorf("hostapd's %s = %q, want %q (NET_ADMIN and NET_RAW only, no_new_privs)", k, v, want)
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

// capStatus reads the CapBnd and NoNewPrivs lines of a status file's text.
func capStatus(status string) (capBnd, nnp string) {
	for _, l := range strings.Split(status, "\n") {
		if k, v, found := strings.Cut(l, ":"); found {
			switch k {
			case "CapBnd":
				capBnd = strings.TrimSpace(v)
			case "NoNewPrivs":
				nnp = strings.TrimSpace(v)
			}
		}
	}
	return capBnd, nnp
}

// threadStatus is capStatus of a status file; ok is false once the
// thread has gone.
func threadStatus(path string) (capBnd, nnp string, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	capBnd, nnp = capStatus(string(b))
	return capBnd, nnp, true
}

// The confinement is per thread, and startConfined's thread is never
// returned to the runtime (#1426): no thread that runs Go code afterwards
// carries hostapd's bounding set or no_new_privs, and children the loader
// starts afterwards from other goroutines (dnsmasq, ip) keep the loader's
// own. The process's main thread is the one exception the runtime makes:
// a locked goroutine that exits there wedges it for good (runtime.mexit)
// and no goroutine runs on it again, so it is left out of the scan.
// Root only: the bounding-set drop needs CAP_SETPCAP.
func TestConfinementStaysOffTheLoadersOtherThreads(t *testing.T) {
	if os.Geteuid() != 0 {
		if os.Getenv("AGENTOS_REQUIRE_APUSER") == "1" {
			t.Fatal("AGENTOS_REQUIRE_APUSER=1 but not root")
		}
		t.Skip("needs root to drop from the bounding set")
	}
	parent := fmt.Sprintf("/proc/%d/status", os.Getppid())
	baseBnd, baseNNP, ok := threadStatus(parent)
	if !ok || baseBnd == "" {
		t.Fatalf("cannot read %s", parent)
	}
	if baseBnd == "0000000000003000" {
		t.Skip("the test process already has hostapd's bounding set")
	}
	// Confined starts from fresh threads, with goroutines blocking in
	// syscalls meanwhile so the runtime makes more threads.
	for range 10 {
		var wg sync.WaitGroup
		for range 10 {
			wg.Add(1)
			go func() { defer wg.Done(); exec.Command("true").Run() }()
		}
		cmd := childproc.Command(context.Background(), hostEnv, childproc.Options{}, "true")
		if err := startConfined(cmd); err != nil {
			t.Fatal(err)
		}
		cmd.Wait()
		wg.Wait()
	}
	confined := func(bnd, nnp string) bool {
		return bnd != baseBnd || (baseNNP == "0" && nnp == "1")
	}
	main := fmt.Sprintf("/proc/self/task/%d/status", os.Getpid())
	// A confined thread may still be exiting: wait for it to go.
	deadline := time.Now().Add(5 * time.Second)
	for {
		tasks, err := filepath.Glob("/proc/self/task/*/status")
		if err != nil || len(tasks) == 0 {
			t.Fatalf("no threads listed: %v", err)
		}
		var flagged []string
		for _, st := range tasks {
			if bnd, nnp, ok := threadStatus(st); ok && st != main && confined(bnd, nnp) {
				flagged = append(flagged, st+" CapBnd "+bnd+" NoNewPrivs "+nnp)
			}
		}
		if len(flagged) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("loader threads still confined (base CapBnd %s NoNewPrivs %s): %v", baseBnd, baseNNP, flagged)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Children from many goroutines, so they start on many threads.
	const n = 20
	out := make(chan string, n)
	for range n {
		go func() {
			b, err := exec.Command("cat", "/proc/self/status").Output()
			if err != nil {
				out <- "error: " + err.Error()
				return
			}
			out <- string(b)
		}()
	}
	for range n {
		said := <-out
		if bnd, nnp := capStatus(said); bnd == "" || confined(bnd, nnp) {
			t.Fatalf("a child started outside startConfined has CapBnd %q NoNewPrivs %q, want the loader's %s and %s:\n%s",
				bnd, nnp, baseBnd, baseNNP, said)
		}
	}
}
