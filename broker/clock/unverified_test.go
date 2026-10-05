package clock

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: HW-8, TIM-1

// rtcRig is a box whose hardware clock reads rtc (as the kernel reads it,
// as if UTC): a Windows PC keeps it in local time.
// testHost is a synthetic firmware system UUID.
const testHost = "4a1b2c3d-0000-4000-8000-0000000c10c6"

func rtcGuard(t *testing.T, r *rig, path string, rtc *time.Time, edit ...func(*Config)) *Guard {
	return r.guard(t, func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.boot }
		c.RTC = func() (time.Time, error) { r.mu.Lock(); defer r.mu.Unlock(); return *rtc, nil }
		c.HostID = func() string { return testHost }
		// The rig's sync is NTS-authenticated unless a test says otherwise.
		c.Sync = func() (SyncKind, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if !r.synced || r.syncErr != nil {
				return NotSynced, r.syncErr
			}
			return SyncedNTS, nil
		}
		for _, e := range edit {
			e(c)
		}
	})
}

// reboot starts a new boot: the monotonic clock restarts and the box clock
// is whatever the hardware clock (or the boot estimate) gave.
func (r *rig) reboot(wall time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.boot += "x"
	r.mono = 0
	r.wall = wall
}

// HW-8: the hardware clock is unverified until network or carrier time. A
// box that has never been verified this boot bounds Latest and Earliest by
// the floor, the last verified time, which only advances: a clock behind
// (a UTC-minus Windows local time) cannot keep a grant alive, and a clock
// ahead (UTC-plus) cannot end a wait early.
func TestHW8UnverifiedClockIsBoundedByTheFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	t0 := r.wall
	rtc := t0
	g := rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if s := g.Status(); !s.Verified {
		t.Fatalf("synced and agreeing: %+v", s)
	}
	r.advance(time.Hour)
	g.Check(bg)
	floor := r.wall

	// Reboot offline with the RTC five hours behind (US local time).
	r.reboot(floor.Add(-5 * time.Hour))
	r.synced, r.carrier = false, time.Time{}
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	s := g.Status()
	if s.Verified {
		t.Fatalf("offline boot verified: %+v", s)
	}
	if lt, _ := g.Latest(bg); !lt.Equal(floor) {
		t.Errorf("Latest = %v, want the floor %v", lt, floor)
	}
	if et, _ := g.Earliest(bg); !et.Equal(floor.Add(-5 * time.Hour)) {
		t.Errorf("Earliest = %v, want the box clock", et)
	}
	if now, err := g.Now(bg); err != nil || !now.Equal(floor.Add(-5*time.Hour)) {
		t.Errorf("Now = %v, %v: the floor never steps or restricts the clock", now, err)
	}

	// Reboot offline with the RTC five hours ahead (European local time).
	r.reboot(floor.Add(5 * time.Hour))
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if et, _ := g.Earliest(bg); !et.Equal(floor) {
		t.Errorf("Earliest = %v, want the floor %v", et, floor)
	}
	if lt, _ := g.Latest(bg); !lt.Equal(floor.Add(5 * time.Hour)) {
		t.Errorf("Latest = %v, want the box clock", lt)
	}

	// A verified sync lifts both bounds and advances the floor.
	r.mu.Lock()
	r.wall, r.synced = floor.Add(30*time.Minute), true
	r.mu.Unlock()
	g.Check(bg)
	if !g.Status().Verified {
		t.Fatal("verified sync not recorded")
	}
	if et, _ := g.Earliest(bg); !et.Equal(floor.Add(30 * time.Minute)) {
		t.Errorf("verified Earliest = %v", et)
	}
	if got := readSaved(t, path).Floor; !got.Equal(floor.Add(30 * time.Minute)) {
		t.Errorf("floor saved %v", got)
	}
}

func readSaved(t *testing.T, path string) saved {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v saved
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Security T3, T4: the floor advances only from verified time. Carrier time
// alone verifies only as a tie-break: when it agrees with a box clock at or
// after the floor. A carrier reading before the floor does not verify, and
// unverified time never moves the floor.
func TestHW8FloorAdvancesOnlyFromVerifiedTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	g := rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	floor := r.wall

	// Offline, no carrier: the box clock moves on, the floor does not.
	r.reboot(floor.Add(48 * time.Hour))
	r.synced, r.carrier = false, time.Time{}
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if got := readSaved(t, path).Floor; !got.Equal(floor) {
		t.Fatalf("unverified check moved the floor to %v", got)
	}

	// A fake cell agreeing with a box clock behind the floor: not verified.
	r.reboot(floor.Add(-10 * time.Hour))
	r.carrier = floor.Add(-10 * time.Hour)
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if s := g.Status(); s.Verified || s.State != CarrierOnly {
		t.Fatalf("carrier before the floor verified: %+v", s)
	}
	if got := readSaved(t, path).Floor; !got.Equal(floor) {
		t.Fatalf("floor moved to %v", got)
	}

	// Carrier agreeing with a box clock after the floor: verified, and the
	// floor advances.
	r.reboot(floor.Add(2 * time.Hour))
	r.carrier = floor.Add(2 * time.Hour)
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if !g.Status().Verified {
		t.Fatal("agreeing carrier after the floor not verified")
	}
	if got := readSaved(t, path).Floor; !got.Equal(floor.Add(2 * time.Hour)) {
		t.Fatalf("floor %v", got)
	}

	// A restricted check never verifies.
	r.reboot(floor.Add(3 * time.Hour))
	r.carrier = floor.Add(9 * time.Hour)
	r.synced = true
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if s := g.Status(); s.Verified || s.State != Disagree {
		t.Fatalf("disagreeing check verified: %+v", s)
	}
}

// Verified holds for the rest of the boot, across a broker restart, and
// not into the next boot.
func TestHW8VerifiedIsPerBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	g := rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	r.synced, r.carrier = false, time.Time{}
	g = rtcGuard(t, r, path, &rtc) // broker restart, same boot
	g.Check(bg)
	if !g.Status().Verified {
		t.Fatal("restart in the same boot lost Verified")
	}
	r.reboot(r.wall)
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if g.Status().Verified {
		t.Fatal("Verified carried into a new boot")
	}
}

// A floor beyond authenticated time is impossible, so an NTS-verified
// check replaces it (a corrupt or tampered file), and it is logged. Plain
// NTP or carrier time, which an on-path attacker can forge, never rolls
// the floor back for later boots (security R1 on #177); that is logged
// once.
func TestHW8FloorAheadOfVerifiedTimeIsReplaced(t *testing.T) {
	for _, kind := range []SyncKind{SyncedPlain, SyncedNTS} {
		path := filepath.Join(t.TempDir(), "clock.json")
		r := newRig()
		rtc := r.wall
		g := rtcGuard(t, r, path, &rtc)
		g.Check(bg)
		v := readSaved(t, path)
		ahead := r.wall.Add(400 * 24 * time.Hour)
		v.Floor = ahead
		if err := writeAtomic(path, v); err != nil {
			t.Fatal(err)
		}
		var logs []string
		r.reboot(r.wall)
		g = r.guard(t, func(c *Config) {
			c.StatePath = path
			c.BootID = func() string { return r.boot }
			c.Logf = func(f string, a ...any) { logs = append(logs, f) }
			c.Sync = func() (SyncKind, error) { return kind, nil }
		})
		g.Check(bg)
		g.Check(bg)
		want := ahead
		if kind == SyncedNTS {
			want = r.wall
		}
		if got := readSaved(t, path).Floor; !got.Equal(want) {
			t.Errorf("kind %d: floor %v, want %v", kind, got, want)
		}
		if len(logs) != 1 {
			t.Errorf("kind %d: logged %d times", kind, len(logs))
		}
	}
}

// L3 MUST on #177 (security T3): a plain NTP sync, which an on-path
// attacker can forge, verifies only a box clock at or after the floor, like
// carrier time; below it the clock stays unverified and bounded by the
// floor for the rest of the boot. An NTS sync verifies either way.
func TestHW8PlainSyncBelowTheFloorDoesNotVerify(t *testing.T) {
	for _, kind := range []SyncKind{SyncedPlain, SyncedNTS} {
		path := filepath.Join(t.TempDir(), "clock.json")
		r := newRig()
		r.carrier = time.Time{}
		rtc := r.wall
		rtcGuard(t, r, path, &rtc).Check(bg)
		floor := r.wall
		r.reboot(floor.Add(-10 * time.Hour))
		var logs []string
		g := rtcGuard(t, r, path, &rtc, func(c *Config) {
			c.Sync = func() (SyncKind, error) { return kind, nil }
			c.Logf = func(f string, a ...any) { logs = append(logs, f) }
		})
		g.Check(bg)
		g.Check(bg)
		s := g.Status()
		latest, _ := g.Latest(bg)
		if kind == SyncedPlain {
			if s.Verified || latest.Before(floor) || len(logs) != 1 {
				t.Errorf("plain below floor: verified %v, latest %v, logs %d", s.Verified, latest, len(logs))
			}
			// Within tolerance of the floor, plain time verifies.
			r.reboot(floor.Add(-DefaultTolerance / 2))
			g = rtcGuard(t, r, path, &rtc, func(c *Config) {
				c.Sync = func() (SyncKind, error) { return kind, nil }
			})
			g.Check(bg)
			if !g.Status().Verified {
				t.Error("plain sync at the floor not verified")
			}
		} else if !s.Verified || !latest.Before(floor) {
			t.Errorf("NTS below floor: verified %v, latest %v", s.Verified, latest)
		}
	}
}

// L3 MUST on #177: a step held within a boot neither verifies nor moves
// the floor, even with a sync.
func TestHW8HeldStepDoesNotAdvanceTheFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	r.carrier = time.Time{}
	rtc := r.wall
	g := rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	floor := readSaved(t, path).Floor
	r.step(10 * 24 * time.Hour)
	g.Check(bg)
	if s := g.Status(); s.State != Held {
		t.Fatalf("not held: %+v", s)
	}
	if got := readSaved(t, path).Floor; !got.Equal(floor) {
		t.Fatalf("held step moved the floor to %v from %v", got, floor)
	}
}

// Potency C1, security T7: the offset between the hardware clock and UTC
// is learned at a verified NTP sync, rounded to 15 minutes, only within
// ±14 hours, and kept; BootEstimate turns a later boot's RTC reading into
// the estimate a one-shot sets before the time service starts.
func TestHW8LearnsTheRTCOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall.Add(2*time.Hour + 3*time.Minute) // Windows at UTC+2, drifted 3 min
	r.carrier = time.Time{}
	g := rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	v := readSaved(t, path)
	if !v.HaveOffset || v.Offset != 2*time.Hour {
		t.Fatalf("offset %v %v", v.HaveOffset, v.Offset)
	}
	later := time.Date(2026, 10, 9, 20, 0, 0, 0, time.UTC)
	est, ok := BootEstimate(path, later, testHost)
	if !ok || !est.Equal(later.Add(-2*time.Hour)) {
		t.Fatalf("estimate %v %v", est, ok)
	}
	// L3 on #177: the offset belongs to the PC it was learned on; on
	// another PC, or one with no or a placeholder UUID, there is none. The
	// UUID itself is not kept.
	for _, other := range []string{"4a1b2c3d-0000-4000-8000-0000000c10c7", "", "00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "not-a-uuid"} {
		if _, ok := BootEstimate(path, later, other); ok {
			t.Errorf("estimate on host %q", other)
		}
	}
	if _, ok := BootEstimate(path, later, strings.ToUpper(testHost)); !ok {
		t.Error("upper-case UUID not the same PC")
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "0000000c10c6") {
		t.Error("state file keeps the system UUID")
	}

	// A plain NTP sync, which can be forged on path, teaches no offset;
	// nor does a PC with no UUID.
	for name, edit := range map[string]func(*Config){
		"plain":     func(c *Config) { c.Sync = func() (SyncKind, error) { return SyncedPlain, nil } },
		"no host":   func(c *Config) { c.HostID = func() string { return "" } },
		"zero UUID": func(c *Config) { c.HostID = func() string { return "00000000-0000-0000-0000-000000000000" } },
		"F UUID":    func(c *Config) { c.HostID = func() string { return "ffffffff-ffff-ffff-ffff-ffffffffffff" } },
	} {
		p := filepath.Join(t.TempDir(), "clock.json")
		rp := newRig()
		rtcp := rp.wall.Add(2 * time.Hour)
		rp.carrier = time.Time{}
		rtcGuard(t, rp, p, &rtcp, edit).Check(bg)
		if readSaved(t, p).HaveOffset {
			t.Errorf("%s taught an offset", name)
		}
	}

	// Carrier-only verification does not teach an offset; an offset past
	// ±14 hours is not learned and the old one stays.
	path2 := filepath.Join(t.TempDir(), "clock.json")
	r2 := newRig()
	r2.synced = false
	rtc2 := r2.wall.Add(-5 * time.Hour)
	g = rtcGuard(t, r2, path2, &rtc2)
	g.Check(bg)
	if readSaved(t, path2).HaveOffset {
		t.Fatal("carrier time taught an offset")
	}
	rtc = r.wall.Add(15 * time.Hour)
	g = rtcGuard(t, r, path, &rtc)
	g.Check(bg)
	if v := readSaved(t, path); v.Offset != 2*time.Hour {
		t.Fatalf("15-hour offset replaced the old: %v", v.Offset)
	}

	// No offset known, or a file that cannot be read: no estimate.
	if _, ok := BootEstimate(path2, later, testHost); ok {
		t.Fatal("estimate without an offset")
	}
	if _, ok := BootEstimate(filepath.Join(t.TempDir(), "none"), later, testHost); ok {
		t.Fatal("estimate without a file")
	}
	bad := filepath.Join(t.TempDir(), "bad")
	os.WriteFile(bad, []byte(`{"have_offset":true,"offset":3600000000001}`), 0o600)
	if _, ok := BootEstimate(bad, later, testHost); ok {
		t.Fatal("estimate from an offset not on a 15-minute step")
	}
}

// UX-H1b-1: STATUS says the clock is not confirmed yet, in the Time check
// family, until verified; a restriction keeps its own wording.
func TestHW8StatusLineWhileUnverified(t *testing.T) {
	r := newRig()
	r.synced, r.carrier = false, time.Time{}
	r.mono = 90 * time.Minute // booted at 02:30 UTC
	g := r.guard(t, nil)
	want := "Time check: not confirmed since start at 04:30 (waiting for network or phone-network time). Nothing to do."
	if got := g.Status().Line(time.FixedZone("x", 2*3600)); got != want {
		t.Fatalf("before a check: %q", got)
	}
	g.Check(bg)
	if got := g.Status().Line(time.FixedZone("x", 2*3600)); got != want {
		t.Fatalf("after a check: %q", got)
	}
	r.carrier = r.wall.Add(3 * time.Hour)
	g.Check(bg)
	if got := g.Status().Line(time.UTC); !strings.HasPrefix(got, "Time check: restricted since") {
		t.Fatalf("restricted: %q", got)
	}
}
