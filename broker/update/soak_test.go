package update

// REQ: UPD-7, UPD-5, UPD-4, UPD-8

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

const day = 24 * time.Hour

// ordinary is a checked ordinary release 2 on a stable box with the
// fixture's allow-list, or o's.
func ordinary(t *testing.T, o Options) (*fixture, *Verified) {
	t.Helper()
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	res, err := f.check(o)
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	return f, res.Release
}

func ready(t *testing.T, name string, w Wait, err error) {
	t.Helper()
	if err != nil || !w.Ready {
		t.Fatalf("%s: not ready: %+v, %v", name, w, err)
	}
}

func waits(t *testing.T, name string, w Wait, err error, reason string) {
	t.Helper()
	if err != nil || w.Ready || w.Reason != reason {
		t.Fatalf("%s: got %+v, %v; want waiting for %q", name, w, err, reason)
	}
}

func TestStableWaitsForSoakAndPasses(t *testing.T) {
	f, v := ordinary(t, Options{})
	one := [][]byte{pass(t, f.att[0], v)}
	for _, c := range []struct {
		elapsed time.Duration
		atts    [][]byte
		reason  string // "" is ready
	}{
		{7*day - time.Hour, nil, WaitSoak},
		{7*day - time.Hour, one, WaitSoak},
		{7 * day, nil, WaitAttestations},
		{7 * day, one, ""},
	} {
		w, err := v.StableReady(c.atts, nil, ChannelStable, t0, t0.Add(c.elapsed), 7, 1)
		name := c.elapsed.String()
		if c.reason == "" {
			ready(t, name, w, err)
			continue
		}
		waits(t, name, w, err, c.reason)
		if c.reason == WaitSoak && !w.Until.Equal(t0.Add(7*day)) {
			t.Fatalf("%s: until %v", name, w.Until)
		}
		if c.reason == WaitAttestations && w.Need != 1 {
			t.Fatalf("%s: need %d", name, w.Need)
		}
	}
}

func TestSoakDaysAreFloored(t *testing.T) {
	f, v := ordinary(t, Options{})
	one := [][]byte{pass(t, f.att[0], v)}
	for _, c := range []struct{ soak, want int }{{0, 7}, {-1, 7}, {3, 7}, {7, 7}, {30, 30}, {60, 60}, {61, 60}} {
		end := t0.Add(time.Duration(c.want) * day)
		w, err := v.StableReady(one, nil, ChannelStable, t0, end.Add(-time.Second), c.soak, 1)
		waits(t, "before", w, err, WaitSoak)
		if !w.Until.Equal(end) {
			t.Fatalf("soak %d: until %v, want %v", c.soak, w.Until, end)
		}
		w, err = v.StableReady(one, nil, ChannelStable, t0, end, c.soak, 1)
		ready(t, "at end", w, err)
	}
}

func TestOnlyIndependentFastPassesCount(t *testing.T) {
	own := newKey(t)
	ownPub := own.Public().(ed25519.PublicKey)
	f := newFixture(t)
	f.release(2, nil)
	f.publish(0, 1)
	// The box's own key and a root key are listed too: neither counts.
	res, err := f.check(Options{Attestors: f.attestors(own, f.root[0])})
	if err != nil || res.Release == nil {
		t.Fatal(res.Release, err)
	}
	v := res.Release
	stable, _ := Attest(f.att[0], v, Statement{Result: ResultPass, Channel: ChannelStable, Hardware: floorPC})
	failed, _ := Attest(f.att[1], v, Statement{Result: ResultFail, Channel: ChannelFast, Hardware: floorPC})
	late := t0.Add(30 * day)
	for name, a := range map[string][]byte{
		"stable channel": stable,
		"failed":         failed,
		"own key":        pass(t, own, v),
		"root key":       pass(t, f.root[0], v),
		"unlisted":       pass(t, newKey(t), v),
	} {
		w, err := v.StableReady([][]byte{a}, ownPub, ChannelStable, t0, late, 7, 1)
		waits(t, name, w, err, WaitAttestations)
	}
	ok := pass(t, f.att[0], v)
	w, err := v.StableReady([][]byte{ok}, ownPub, ChannelStable, t0, late, 7, 1)
	ready(t, "one listed fast pass", w, err)
	w, err = v.StableReady([][]byte{ok, ok}, ownPub, ChannelStable, t0, late, 7, 2)
	waits(t, "one attestor twice", w, err, WaitAttestations)
	if w.Need != 1 {
		t.Fatalf("need %d", w.Need)
	}
	w, err = v.StableReady([][]byte{ok, pass(t, f.att[1], v)}, ownPub, ChannelStable, t0, late, 7, 2)
	ready(t, "two attestors", w, err)
	// minPasses below 1 is 1.
	for _, n := range []int{0, -1} {
		w, err = v.StableReady(nil, ownPub, ChannelStable, t0, late, 7, n)
		waits(t, "minPasses floor", w, err, WaitAttestations)
	}
}

func TestEmptyAllowListNeverReady(t *testing.T) {
	_, v := ordinary(t, Options{Attestors: []ed25519.PublicKey{}})
	w, err := v.StableReady([][]byte{pass(t, newKey(t), v)}, nil, ChannelStable, t0, t0.Add(365*day), 7, 1)
	waits(t, "empty list", w, err, WaitNoAttestor)
	// A list holding only the project's test box is not empty.
	box := newKey(t)
	only := []ed25519.PublicKey{box.Public().(ed25519.PublicKey)}
	_, v = ordinary(t, Options{Attestors: only, InterimAttestors: only})
	w, err = v.StableReady(nil, nil, ChannelStable, t0, t0.Add(365*day), 7, 1)
	waits(t, "interim list, no pass", w, err, WaitAttestations)
	w, err = v.StableReady([][]byte{pass(t, box, v)}, nil, ChannelStable, t0, t0.Add(365*day), 7, 1)
	ready(t, "interim list", w, err)
}

func TestFastBoxTakesReleaseUnsoaked(t *testing.T) {
	_, v := ordinary(t, Options{Channel: ChannelFast})
	w, err := v.StableReady(nil, nil, ChannelFast, t0, t0, 7, 1)
	ready(t, "ordinary on fast", w, err)
	_, sec := securityFix(t)
	if w, err := sec.StableReady(nil, nil, ChannelFast, t0, t0, 7, 1); w.Ready || !errors.Is(err, ErrNeedsAttestation) {
		t.Fatalf("security fix on fast: %+v, %v", w, err)
	}
}

func TestPinnedAndUnknownChannelNeverReady(t *testing.T) {
	f, v := ordinary(t, Options{})
	one := [][]byte{pass(t, f.att[0], v)}
	for _, ch := range []string{"pinned", "", "beta", "Stable"} {
		w, err := v.StableReady(one, nil, ch, t0, t0.Add(365*day), 7, 1)
		waits(t, ch, w, err, WaitPinned)
	}
}

func TestSecurityFixFollowsSecurityAutoStage(t *testing.T) {
	f, sec := securityFix(t)
	// The newest release only covers a fix (coversFix): release 3 above
	// the security release 2.
	g := newFixture(t)
	g.release(2, func(r *Manifest) { r.Security = true })
	g.release(3, nil)
	g.publish(0, 1)
	res, err := g.check(Options{})
	if err != nil || res.Release == nil || res.SecurityFix != 2 {
		t.Fatal(res, err)
	}
	for _, c := range []struct {
		name string
		att  ed25519.PrivateKey
		v    *Verified
	}{{"security", f.att[0], sec}, {"covers a fix", g.att[0], res.Release}} {
		if c.v.Security() {
			t.Fatal("fixture: Security() is already true")
		}
		w, err := c.v.StableReady(nil, nil, ChannelStable, t0, t0, 7, 1)
		if w.Ready || !errors.Is(err, ErrNeedsAttestation) {
			t.Fatalf("%s, no pass: %+v, %v", c.name, w, err)
		}
		w, err = c.v.StableReady([][]byte{pass(t, c.att, c.v)}, nil, ChannelStable, t0, t0, 7, 1)
		ready(t, c.name, w, err)
	}
}

func TestClockBackAndZeroTimesFailClosed(t *testing.T) {
	f, v := ordinary(t, Options{})
	one := [][]byte{pass(t, f.att[0], v)}
	late := t0.Add(365 * day)
	w, err := v.StableReady(one, nil, ChannelStable, time.Time{}, late, 7, 1)
	waits(t, "zero firstSeen", w, err, WaitSoak)
	w, err = v.StableReady(one, nil, ChannelStable, t0, time.Time{}, 7, 1)
	waits(t, "zero now", w, err, WaitSoak)
	w, err = v.StableReady(one, nil, ChannelStable, late, t0, 7, 1)
	waits(t, "clock back", w, err, WaitSoak)
	if !w.Until.Equal(late.Add(7 * day)) {
		t.Fatalf("clock back: until %v", w.Until)
	}
	var nilV *Verified
	if w, err := nilV.StableReady(one, nil, ChannelFast, t0, late, 7, 1); w.Ready || !errors.Is(err, ErrNotChecked) {
		t.Fatalf("nil: %+v, %v", w, err)
	}
	if w, err := (&Verified{}).StableReady(one, nil, ChannelFast, t0, late, 7, 1); w.Ready || !errors.Is(err, ErrNotChecked) {
		t.Fatalf("unsealed: %+v, %v", w, err)
	}
}
