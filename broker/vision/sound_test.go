package vision

// REQ: DEV-7, DEV-8

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

func soundReply(t *testing.T, ss ...Sound) []byte {
	b, err := json.Marshal(Reply{Sounds: ss})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func clip(fill byte) []byte { return bytes.Repeat([]byte{fill}, 320) }

func zero(b []byte) bool { return !bytes.ContainsFunc(b, func(r rune) bool { return r != 0 }) }

// DEV-8: a label repeats from one source at most once per Quiet, each
// source's events are rate-limited per minute, and what is dropped is
// counted and carried by the source's next event.
func TestSoundEventsQuietAndRateLimited(t *testing.T) {
	labels := []Sound{{Label: "glass-break", Conf: 90}}
	path := serve(t, func(Request) []byte { return soundReply(t, labels...) })
	now := time.Unix(1_800_000_000, 0)
	s := NewSounds(Client{Path: path})
	s.Now = func() time.Time { return now }
	hear := func(src string) []SoundEvent {
		t.Helper()
		es, err := s.Hear(context.Background(), src, clip(1))
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	if es := hear("porch"); len(es) != 1 || es[0] != (SoundEvent{Source: "porch", Label: "glass-break", Conf: 90}) {
		t.Fatalf("first: %+v", es)
	}
	now = now.Add(DefaultSoundQuiet / 2)
	if es := hear("porch"); len(es) != 0 {
		t.Fatalf("within Quiet: %+v", es)
	}
	if es := hear("yard"); len(es) != 1 {
		t.Fatalf("another source shares Quiet: %+v", es)
	}
	now = now.Add(DefaultSoundQuiet)
	if es := hear("porch"); len(es) != 1 || es[0].Coalesced != 1 {
		t.Fatalf("after Quiet: %+v", es)
	}
	// The count went with the event that carried it.
	now = now.Add(DefaultSoundQuiet / 2)
	hear("porch")
	now = now.Add(DefaultSoundQuiet)
	if es := hear("porch"); len(es) != 1 || es[0].Coalesced != 1 {
		t.Fatalf("a carried count came back: %+v", es)
	}

	// Repeats past the per-minute limit are held and counted per label.
	routine := []Sound{{Label: "vehicle", Conf: 50}, {Label: "dog-bark", Conf: 50}, {Label: "knock", Conf: 50}, {Label: "doorbell", Conf: 50}}
	labels = routine
	now = now.Add(time.Hour)
	if es := hear("shed"); len(es) != 4 {
		t.Fatalf("first routine labels: %+v", es)
	}
	now = now.Add(DefaultSoundQuiet)
	es := hear("shed")
	if len(es) != DefaultSoundsPerMinute-4 || s.Coalesced("shed", "doorbell") != 1 || s.Coalesced("shed", "knock") != 1 {
		t.Fatalf("repeats: %+v; held knock %d, doorbell %d", es, s.Coalesced("shed", "knock"), s.Coalesced("shed", "doorbell"))
	}
	// A rare label is never starved by the routine ones (combined review
	// of #3632, point 2): its first event in the minute passes the limit.
	now = now.Add(10 * time.Second)
	labels = append(routine, Sound{Label: "glass-break", Conf: 95})
	es = hear("shed")
	if len(es) != 1 || es[0].Label != "glass-break" || es[0].Coalesced != 0 {
		t.Fatalf("glass-break after routine labels: %+v", es)
	}
	// Each held label's count rides on that label's own next event.
	now = now.Add(time.Minute)
	labels = routine
	for _, e := range hear("shed") {
		if want := map[string]int{"vehicle": 1, "dog-bark": 1, "knock": 2, "doorbell": 2}[e.Label]; e.Coalesced != want {
			t.Fatalf("%s carried %d, want %d", e.Label, e.Coalesced, want)
		}
	}
}

// DEV-7: Hear zeroes the clip on every path: a heard clip, a service
// error, a malformed reply, an unreachable service and a bad source.
func TestHearZeroesTheClip(t *testing.T) {
	ok := serve(t, func(Request) []byte { return soundReply(t, Sound{Label: "knock", Conf: 50}) })
	cases := map[string]struct {
		path, source string
	}{
		"heard":       {ok, "porch"},
		"error reply": {serve(t, fixed(`{"error":"missing"}`)), "porch"},
		"malformed":   {serve(t, fixed(`{"sounds":[{"label":"speech","conf":50}]}`)), "porch"},
		"no service":  {"/nonexistent/vision.sock", "porch"},
		"bad source":  {ok, "Porch!"},
	}
	for name, c := range cases {
		pcm := clip('Q')
		_, err := NewSounds(Client{Path: c.path, Timeout: time.Second}).Hear(context.Background(), c.source, pcm)
		if (name == "heard") != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
		if !zero(pcm) {
			t.Errorf("%s: clip left unzeroed", name)
		}
	}
}

// #3728: the first-in-minute pass is one minute wide. With the limit full,
// a label's repeat at 59 s after its last event is held, and at 60 s it
// passes as the label's first event in a minute.
func TestSoundFirstInMinuteWindowEdge(t *testing.T) {
	var labels []Sound
	path := serve(t, func(Request) []byte { return soundReply(t, labels...) })
	now := time.Unix(1_800_000_000, 0)
	s := NewSounds(Client{Path: path})
	s.Now = func() time.Time { return now }
	s.PerMinute = 1
	hear := func(l string) []SoundEvent {
		t.Helper()
		labels = []Sound{{Label: l, Conf: 70}}
		es, err := s.Hear(context.Background(), "porch", clip(1))
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	start := now
	if es := hear("knock"); len(es) != 1 {
		t.Fatalf("first knock: %+v", es)
	}
	now = start.Add(30 * time.Second)
	if es := hear("doorbell"); len(es) != 1 {
		t.Fatalf("first doorbell: %+v", es)
	}
	now = start.Add(59 * time.Second)
	if es := hear("knock"); len(es) != 0 {
		t.Fatalf("a repeat at 59 s with the limit full: %+v", es)
	}
	now = start.Add(60 * time.Second)
	if es := hear("knock"); len(es) != 1 || es[0].Coalesced != 1 {
		t.Fatalf("at 60 s: %+v", es)
	}
}

// #3728: a hostile service, hearing a random set of labels in each clip,
// one clip a second for half an hour, gets at most PerMinute+MaxSounds
// events in any minute from one source (VIS-A20: 14).
func TestSoundCeilingPerSource(t *testing.T) {
	r := rand.New(rand.NewPCG(3728, 1))
	var mu sync.Mutex
	path := serve(t, func(Request) []byte {
		mu.Lock()
		defer mu.Unlock()
		var ss []Sound
		for _, l := range SoundLabels() {
			if r.IntN(3) == 0 {
				ss = append(ss, Sound{Label: l, Conf: 99})
			}
		}
		return soundReply(t, ss...)
	})
	now := time.Unix(1_800_000_000, 0)
	s := NewSounds(Client{Path: path})
	s.Now = func() time.Time { return now }
	var at []time.Time
	for range 1800 {
		es, err := s.Hear(context.Background(), "porch", clip(1))
		if err != nil {
			t.Fatal(err)
		}
		for range es {
			at = append(at, now)
		}
		now = now.Add(time.Second)
	}
	most := 0
	for i := range at {
		n := 0
		for _, b := range at[i:] {
			if b.Sub(at[i]) < time.Minute {
				n++
			}
		}
		most = max(most, n)
	}
	if most > DefaultSoundsPerMinute+MaxSounds || most < MaxSounds {
		t.Fatalf("at most %d events in a minute, want %d to %d", most, MaxSounds, DefaultSoundsPerMinute+MaxSounds)
	}
}

// #3728, later: a stale source is dropped when a new one comes only if
// it holds no coalesced count, so a held count is never lost.
func TestSoundStaleSourceKeepsItsCount(t *testing.T) {
	labels := []Sound{{Label: "knock", Conf: 70}}
	path := serve(t, func(Request) []byte { return soundReply(t, labels...) })
	now := time.Unix(1_800_000_000, 0)
	s := NewSounds(Client{Path: path})
	s.Now = func() time.Time { return now }
	hear := func(src string) {
		t.Helper()
		if _, err := s.Hear(context.Background(), src, clip(1)); err != nil {
			t.Fatal(err)
		}
	}
	hear("held")
	hear("held") // within Quiet: held and counted
	hear("clean")
	now = now.Add(2 * time.Hour)
	hear("new")
	if s.Coalesced("held", "knock") != 1 {
		t.Fatal("a stale source's held count was dropped")
	}
	s.mu.Lock()
	_, clean := s.sources["clean"]
	s.mu.Unlock()
	if clean {
		t.Fatal("a stale source with nothing held was kept")
	}
}
