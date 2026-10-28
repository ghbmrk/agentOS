package vision

// REQ: DEV-7, DEV-8

import (
	"bytes"
	"context"
	"encoding/json"
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
