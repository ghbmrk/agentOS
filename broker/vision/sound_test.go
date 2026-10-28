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

	// Every label at once: the per-minute limit holds the rest.
	labels = nil
	for i, l := range SoundLabels() {
		labels = append(labels, Sound{Label: l, Conf: 10 + i})
	}
	now = now.Add(time.Hour)
	es := hear("shed")
	if len(es) != DefaultSoundsPerMinute || s.Coalesced("shed") != len(labels)-DefaultSoundsPerMinute {
		t.Fatalf("burst: %d events, %d coalesced", len(es), s.Coalesced("shed"))
	}
	now = now.Add(time.Minute)
	es = hear("shed")
	if len(es) == 0 || es[0].Coalesced != len(labels)-DefaultSoundsPerMinute {
		t.Fatalf("after a minute: %+v", es)
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
