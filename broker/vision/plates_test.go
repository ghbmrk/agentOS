package vision

// REQ: DEV-8

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The synthetic plate set's thresholds (VIS-A21): of the plates on tracks
// of at least plateMinFrames frames, at least plateReadRate are reported
// right, and at most plateWrongRate of all reports are wrong. Part (e)
// holds the real runtime's reads of rendered plates to the same figures.
const (
	plateSet       = 1000
	plateMinFrames = 6
	plateReadRate  = 0.95
	plateWrongRate = 0.005
)

// confusions are the OCR swaps a plate reader makes most.
var confusions = map[byte]string{'0': "OD", 'O': "0D", 'D': "0O", '1': "I7", 'I': "1", '8': "B", 'B': "8", '5': "S", 'S': "5", '2': "Z", 'Z': "2", '6': "G", 'G': "6"}

// syntheticPlate is a plate in one of the common North American layouts.
func syntheticPlate(r *rand.Rand) string {
	letter := func() byte { return byte('A' + r.IntN(26)) }
	digit := func() byte { return byte('0' + r.IntN(10)) }
	var b []byte
	switch r.IntN(4) {
	case 0: // ABC 1234
		b = []byte{letter(), letter(), letter(), ' ', digit(), digit(), digit(), digit()}
	case 1: // 1ABC234
		b = []byte{digit(), letter(), letter(), letter(), digit(), digit(), digit()}
	case 2: // AB-12345
		b = []byte{letter(), letter(), '-', digit(), digit(), digit(), digit(), digit()}
	default: // 123 ABC
		b = []byte{digit(), digit(), digit(), ' ', letter(), letter(), letter()}
	}
	return string(b)
}

// misread is one frame's read of p by a noisy reader: no read 25% of the
// time; otherwise each character is dropped 1% of the time and, when it
// has a look-alike, swapped for one 2% of the time, so roughly one read in
// eight is wrong.
func misread(r *rand.Rand, p string) string {
	if r.Float64() < 0.25 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch x := r.Float64(); {
		case x < 0.01:
			continue
		case x < 0.03 && confusions[c] != "":
			alt := confusions[c]
			c = alt[r.IntN(len(alt))]
		}
		b.WriteByte(c)
	}
	s := strings.TrimSpace(b.String())
	if !ValidPlate(s) {
		return ""
	}
	return s
}

func vehicle(plate string) Detection {
	return Detection{Class: Vehicle, Box: Box{0, 0, 10, 10}, Conf: 70, Plate: plate}
}

// TestPlateReadOnSyntheticSet (brief, part d): over a synthetic set of
// plates seen by a noisy reader, the per-track rule reports the right
// plate for nearly all of them and almost never a wrong one.
func TestPlateReadOnSyntheticSet(t *testing.T) {
	r := rand.New(rand.NewPCG(3515, 4))
	p := NewPlates()
	p.PerMinute = plateSet // the rate limit is tested on its own
	var long, right, wrong, reports int
	for i := 0; i < plateSet; i++ {
		truth := syntheticPlate(r)
		frames := 3 + r.IntN(18)
		if frames >= plateMinFrames {
			long++
		}
		k := TrackKey{Camera: "drive", Track: uint64(i)}
		for f := 0; f < frames; f++ {
			e, ok := p.Read(k, vehicle(misread(r, truth)))
			if !ok {
				continue
			}
			reports++
			if e.Plate == strconv.Quote(truth) {
				if frames >= plateMinFrames {
					right++
				}
			} else {
				wrong++
			}
		}
		p.End(k)
	}
	read := float64(right) / float64(long)
	bad := float64(wrong) / float64(reports)
	t.Logf("%d plates, %d on tracks of %d+ frames: %.3f read right; %d reports, %.4f wrong", plateSet, long, plateMinFrames, read, reports, bad)
	if read < plateReadRate {
		t.Errorf("read rate %.3f, want at least %.3f", read, plateReadRate)
	}
	if bad > plateWrongRate {
		t.Errorf("wrong-report rate %.4f, want at most %.4f", bad, plateWrongRate)
	}
}

// A track reports its plate once, only after the read has held Hold frames
// and leads the other reads two to one, and the event carries it quoted.
func TestPlateReportedOnceAfterHold(t *testing.T) {
	p := NewPlates()
	k := TrackKey{Camera: "drive", Track: 1}
	for i, read := range []string{"ABC 1234", "ABC 1Z34", "ABC 1234", "", "ABC I234", "ABC 1234"} {
		if e, ok := p.Read(k, vehicle(read)); ok {
			t.Fatalf("read %d settled early: %+v", i, e)
		}
	}
	e, ok := p.Read(k, vehicle("ABC 1234"))
	if !ok || e != (PlateEvent{Camera: "drive", Track: 1, Plate: `"ABC 1234"`, Frames: 4}) {
		t.Fatalf("settle: %+v, %v", e, ok)
	}
	for i := 0; i < 10; i++ {
		if e, ok := p.Read(k, vehicle("ABC 1234")); ok {
			t.Fatalf("a second report for one track: %+v", e)
		}
	}
	// A plate on anything but a vehicle, or outside its alphabet, is no
	// read at all.
	k2 := TrackKey{Camera: "drive", Track: 2}
	for i := 0; i < 5; i++ {
		d := vehicle("XYZ 999")
		d.Class = Person
		if _, ok := p.Read(k2, d); ok {
			t.Fatal("a person's plate was reported")
		}
		if _, ok := p.Read(k2, vehicle("xyz 999")); ok {
			t.Fatal("lower-case plate text was reported")
		}
	}
	if _, ok := p.Read(TrackKey{Camera: "Drive!", Track: 3}, vehicle("XYZ 999")); ok {
		t.Fatal("a camera id outside its alphabet was taken")
	}
}

// VIS-A9, from the #3576 Security review: a service cycling plate text to
// push bits out gets nothing for the track, however long it goes on.
func TestCyclingPlateReadsNeverReport(t *testing.T) {
	p := NewPlates()
	k := TrackKey{Camera: "drive", Track: 7}
	for i := 0; i < 500; i++ {
		read := "A" + strconv.Itoa(i%(MaxPlateReads+1))
		if e, ok := p.Read(k, vehicle(read)); ok {
			t.Fatalf("read %d (%s) reported %+v", i, read, e)
		}
	}
	// Two reads in turn never lead two to one either.
	k = TrackKey{Camera: "drive", Track: 8}
	for i := 0; i < 500; i++ {
		if e, ok := p.Read(k, vehicle([]string{"AAA 111", "BBB 222"}[i%2])); ok {
			t.Fatalf("alternating reads reported %+v", e)
		}
	}
}

// DEV-8: one camera's plate events are rate-limited per minute; the excess
// is coalesced and counted, and the next event carries the count.
func TestPlateEventsRateLimited(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	p := NewPlates()
	p.Now = func() time.Time { return now }
	settle := func(cam string, track uint64) (PlateEvent, bool) {
		k := TrackKey{Camera: cam, Track: track}
		var e PlateEvent
		var ok bool
		for i := 0; i < DefaultPlateHold; i++ {
			e, ok = p.Read(k, vehicle("PLT "+strconv.FormatUint(track, 10)))
		}
		return e, ok
	}
	for i := 0; i < DefaultPlatesPerMinute; i++ {
		if _, ok := settle("drive", uint64(i)); !ok {
			t.Fatalf("event %d within the limit was dropped", i)
		}
	}
	for i := 0; i < 4; i++ {
		if e, ok := settle("drive", uint64(100+i)); ok {
			t.Fatalf("event past the limit: %+v", e)
		}
	}
	if n := p.Coalesced("drive"); n != 4 {
		t.Fatalf("coalesced %d, want 4", n)
	}
	// Another camera has its own limit.
	if _, ok := settle("gate", 1); !ok {
		t.Fatal("a second camera shares the first's limit")
	}
	now = now.Add(time.Minute)
	e, ok := settle("drive", 200)
	if !ok || e.Coalesced != 4 {
		t.Fatalf("after a minute: %+v, %v", e, ok)
	}
	if p.Coalesced("drive") != 0 {
		t.Fatal("the count was not cleared by the event that carried it")
	}
}

// The tracks held are bounded: past MaxPlateTracks the one read least
// recently is forgotten, so a flood of tracks cannot grow memory.
func TestPlateTracksBounded(t *testing.T) {
	p := NewPlates()
	for i := 0; i < 3*MaxPlateTracks; i++ {
		p.Read(TrackKey{Camera: "drive", Track: uint64(i)}, vehicle("AAA 111"))
	}
	p.mu.Lock()
	n := len(p.tracks)
	_, first := p.tracks[TrackKey{Camera: "drive", Track: 0}]
	p.mu.Unlock()
	if n != MaxPlateTracks || first {
		t.Fatalf("%d tracks held (oldest kept: %v), want %d", n, first, MaxPlateTracks)
	}
}
