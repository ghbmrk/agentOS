package clock

// REQ: TIM-1, HW-8

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// TIM-1-interval-fu-l (#6058): the state file is read under the rule it is
// written by. A file another uid could have written, or one in a directory
// another uid can write, loads as lost (the fail-closed disagreement), and
// BootEstimate gives no estimate from it.
func TestTIM1StateFileOthersCouldWriteLoadsAsLost(t *testing.T) {
	type place struct{ file, dir os.FileMode }
	cases := map[string]place{
		"own": {0o600, 0o700}, "dir others read": {0o600, 0o755},
		"file group-readable": {0o640, 0o700}, "file other-writable": {0o602, 0o700},
		"dir group-writable": {0o600, 0o770}, "dir other-writable": {0o600, 0o703},
	}
	for name, c := range cases {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "clock.json")
		b, err := json.Marshal(saved{Offset: time.Hour, HaveOffset: true, OffsetHost: HostKey(testHost), Restricted: true, Skew: 2 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, c.file); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, c.dir); err != nil {
			t.Fatal(err)
		}
		want := name == "own" || name == "dir others read"
		g := newRig().guard(t, func(c *Config) { c.StatePath = path })
		if s := g.Status(); g.lost == want || s.State != Disagree || (s.Skew == 2*time.Hour) != want {
			t.Errorf("%s: lost %v, status %+v; want read %v", name, g.lost, s, want)
		}
		if _, ok := BootEstimate(path, time.Unix(1e9, 0), testHost); ok != want {
			t.Errorf("%s: BootEstimate ok %v, want %v", name, ok, want)
		}
	}
	// A device or a directory at the path is not a state file.
	for _, p := range []string{"/dev/null", t.TempDir()} {
		g := newRig().guard(t, func(c *Config) { c.StatePath = p })
		if !g.lost {
			t.Errorf("%s loaded as a state file", p)
		}
		if _, ok := BootEstimate(p, time.Unix(1e9, 0), testHost); ok {
			t.Errorf("BootEstimate read %s", p)
		}
	}
}

// readState leaves no descriptor open, for the directory, its root or the
// file, whether it reads the file or refuses it (garbage collection off,
// so no finalizer closes one for it).
func TestTIM1ReadStateClosesWhatItOpens(t *testing.T) {
	fds := func() int {
		es, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("no /proc/self/fd:", err)
		}
		return len(es)
	}
	dir := t.TempDir()
	own, open := filepath.Join(dir, "own"), filepath.Join(dir, "open")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(open, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	before := fds()
	for range 20 {
		if b, err := readState(own); err != nil || string(b) != "x" {
			t.Fatalf("readState(own) = %q, %v", b, err)
		}
		if _, err := readState(open); err == nil {
			t.Fatal("readState read a file open to other uids")
		}
	}
	if after := fds(); after != before {
		t.Fatalf("%d descriptors open after 40 reads, want %d", after, before)
	}
}

// Owners need root to set: a file or directory owned by another uid (not
// root, for the directory) is refused.
func TestTIM1StateFileOfAnotherOwnerLoadsAsLost(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown needs root")
	}
	for _, other := range []string{"file", "dir"} {
		dir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "clock.json")
		restrictedSave(t, path, nil)
		target := map[string]string{"file": path, "dir": dir}[other]
		if err := os.Chown(target, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if g := newRig().guard(t, func(c *Config) { c.StatePath = path }); !g.lost {
			t.Errorf("%s owned by uid 4242 loaded", other)
		}
	}
}

// sameBootAlerts fills the cap within boot "boot-a" and saves; edit then
// rewrites the saved file before a restart in the same boot. It returns the
// rig, the restarted guard, an alarm, and what the load logged.
func sameBootAlerts(t *testing.T, edit func(v map[string]any)) (*rig, *Guard, func(), []string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	var logged []string
	mod := func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return "boot-a" }
		c.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	}
	g := r.guard(t, mod)
	g.Check(bg)
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	alarm()
	alarm()
	g.Flush()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	if b, err = json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	logged = nil
	g = r.guard(t, mod)
	g.Check(bg)
	return r, g, func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}, logged
}

// A same-boot saved alert time before the save by more than a day, after
// the save, or a saved boot clock before the boot or past now, is corrupt:
// the alert counts as just sent, so the cap is not freed, and it ages out a
// day later (#6058).
func TestTIM1ImplausibleSameBootAlertTimesKeepTheCap(t *testing.T) {
	setAlerts := func(mono func(m float64) float64) func(map[string]any) {
		return func(v map[string]any) {
			for _, a := range v["alerts"].([]any) {
				a.(map[string]any)["mono"] = mono(a.(map[string]any)["mono"].(float64))
			}
		}
	}
	cases := map[string]func(map[string]any){
		"alert long before the save": setAlerts(func(float64) float64 { return float64(-1000 * time.Hour) }),
		"alert after the save":       setAlerts(func(m float64) float64 { return m + float64(1000*time.Hour) }),
		"save before the boot": func(v map[string]any) {
			v["saved_mono"] = float64(-1000 * time.Hour)
			setAlerts(func(float64) float64 { return float64(-1000*time.Hour - time.Hour) })(v)
		},
		"save not reached yet": func(v map[string]any) {
			v["saved_mono"] = v["saved_mono"].(float64) + float64(1000*time.Hour)
			setAlerts(func(m float64) float64 { return m + float64(1000*time.Hour) })(v)
		},
	}
	for name, edit := range cases {
		r, g, alarm, logged := sameBootAlerts(t, edit)
		if len(logged) != 2 || !strings.Contains(logged[0], "implausible") {
			t.Errorf("%s: load logged %q, want each alert implausible", name, logged)
		}
		n := len(r.sent())
		alarm()
		if len(r.sent()) != n {
			t.Errorf("%s: cap freed: %q", name, r.sent()[n:])
		}
		r.advance(alertWindow + time.Minute)
		g.Check(bg)
		alarm()
		if len(r.sent()) == n {
			t.Errorf("%s: cap still full a day after the load", name)
		}
	}
}

// An honest restart within a boot keeps each alert's time: one sent before
// a reboot, carried onto this boot's clock (a negative boot-clock time),
// still ages out a day after it was sent, not a day after the restart.
func TestTIM1RestartKeepsCarriedAlertTimes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	boot := "boot-a"
	var logged []string
	mod := func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return boot }
		c.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	}
	g := r.guard(t, mod)
	g.Check(bg)
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	alarm()
	alarm()
	r.advance(10 * time.Hour)
	g.Check(bg)
	g.Flush()
	boot = "boot-b"
	r.reboot(r.wall.Add(time.Minute))
	r.setCarrier(r.wall)
	g = r.guard(t, mod)
	g.Check(bg)
	r.advance(time.Hour)
	g.Check(bg)
	g.Flush()
	g = r.guard(t, mod) // a restart within boot-b
	g.Check(bg)
	for _, l := range logged {
		if strings.Contains(l, "implausible") {
			t.Fatalf("honest restart logged %q", l)
		}
	}
	n := len(r.sent())
	alarm()
	if len(r.sent()) != n {
		t.Fatalf("cap freed early: %q", r.sent()[n:])
	}
	r.advance(12 * time.Hour) // a day since the alerts
	g.Check(bg)
	alarm()
	if len(r.sent()) == n {
		t.Fatal("restart kept the cap full past a day")
	}
}
