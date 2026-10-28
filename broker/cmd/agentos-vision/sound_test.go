package main

// REQ: DEV-7, DEV-8

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// TestSoundLabelsOnlyNoAudioStored (brief, part d; point 7): clips holding
// a marker pattern go through the service and vision.Sounds. Afterwards no
// marker byte is on disk (the socket's folder and the process's TMPDIR),
// in the service's log or in any event, the events carry only labels from
// the list, and both the caller's clip and the service's copy are zeroed.
func TestSoundLabelsOnlyNoAudioStored(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	marker := []byte("AUDIO-MARKER-3515")
	var log lockedBuffer
	f := newFake()
	c := start(t, newService(Config{}, f, &log))
	s := vision.NewSounds(c)
	var events []vision.SoundEvent
	for i := 0; i < 20; i++ {
		pcm := bytes.Repeat(marker, 1000)[:16000]
		if i%5 == 4 {
			f.failNext("off-list", 1) // a reply off the list is refused
		}
		es, err := s.Hear(context.Background(), "porch", pcm)
		if i%5 == 4 {
			if vision.CauseOf(err) != vision.Unavailable {
				t.Fatalf("clip %d: an off-list label got %v", i, err)
			}
		} else if err != nil {
			t.Fatalf("clip %d: %v", i, err)
		}
		if bytes.ContainsFunc(pcm, func(r rune) bool { return r != 0 }) {
			t.Fatalf("clip %d: the caller's clip was left unzeroed", i)
		}
		f.mu.Lock()
		lent := f.clip
		f.mu.Unlock()
		if len(lent) != 16000 || bytes.ContainsFunc(lent, func(r rune) bool { return r != 0 }) {
			t.Fatalf("clip %d: the service's copy was left unzeroed", i)
		}
		events = append(events, es...)
	}
	if len(events) == 0 {
		t.Fatal("no events at all")
	}
	for _, e := range events {
		if !vision.KnownSound(e.Label) || e.Source != "porch" {
			t.Fatalf("event off the list: %+v", e)
		}
	}
	ev, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	// Any 4 bytes of the marker would show a piece of a clip.
	check := func(where string, b []byte) {
		t.Helper()
		for i := 0; i+4 <= len(marker); i++ {
			if bytes.Contains(b, marker[i:i+4]) {
				t.Fatalf("%s holds %q from the clip", where, marker[i:i+4])
			}
		}
	}
	check("the events", ev)
	check("the log", []byte(log.String()))
	for _, dir := range []string{tmp, filepath.Dir(c.Path)} {
		filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			check(p, b)
			return nil
		})
	}
}
