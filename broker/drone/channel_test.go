package drone

import (
	"bytes"
	"io"
	"log"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// REQ: NET-2, A18
// TestChannelRefusesAllButReturn: on the core-side channel only the exact
// return_to_dock line is a command; near-misses, other commands, MAVLink
// bytes and random input are refused (a well-formed camera fix is a report,
// not a command); every refusal is logged and answered; and a burst past
// the rate pauses the reader.
func TestChannelRefusesAllButReturn(t *testing.T) {
	if k, _, _ := parseCore(returnToDock); k != coreReturn {
		t.Fatal("return_to_dock is not the return command")
	}
	refused := []string{"", " return_to_dock", "return_to_dock ", "return_to_dock\x00", "RETURN_TO_DOCK",
		"return_to_dock\r", "return-to-dock", "return_to_dock;arm", "return_to_dock\nreturn_to_dock",
		"arm", "mode GUIDED", "waypoint -35.36 149.16 30", "param FENCE_ENABLE 0", "set_mode 4",
		"\xfd\x09\x01\x00\x00\xff\xbe\x00\x00\x00", // a MAVLink 2 frame header
		"camera_fix", "camera_fix -35.36", "camera_fix -35.36 149.16 30", "camera_fix  -35.36 149.16",
		"camera_fix 1e1 149.16", "camera_fix 0x10 149.16", "camera_fix +35.36 149.16", "camera_fix NaN 149.16",
		"camera_fix Inf 149.16", "camera_fix 91 149.16", "camera_fix -35.36 181", "camera_fix -35.36 149.16\x00"}
	for _, line := range refused {
		if k, _, err := parseCore(line); k != coreRefused || err == nil {
			t.Errorf("%q parsed as %v", line, k)
		}
	}
	if k, p, err := parseCore("camera_fix -35.363261 149.165230"); k != coreCameraFix || err != nil ||
		p != (Point{Lat: -35.363261, Lon: 149.165230}) {
		t.Errorf("a camera fix parsed as %v %+v %v", k, p, err)
	}
	// Random lines, and every one-byte change of the command: none is it.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(24))
		rng.Read(b)
		if k, _, _ := parseCore(string(b)); k == coreReturn && string(b) != returnToDock {
			t.Fatalf("%q is a return", b)
		}
	}
	for i := range returnToDock {
		for c := 0; c < 256; c++ {
			b := []byte(returnToDock)
			if b[i] == byte(c) {
				continue
			}
			b[i] = byte(c)
			if k, _, _ := parseCore(string(b)); k == coreReturn {
				t.Fatalf("%q is a return", b)
			}
		}
	}

	// Served: each refused line is logged and answered, and nothing else.
	var logs bytes.Buffer
	h := &Holder{log: log.New(&logs, "", 0)}
	var out bytes.Buffer
	clock := time.Unix(0, 0)
	var paused []time.Duration
	lim := &limiter{tokens: coreBurst, now: func() time.Time { return clock },
		sleep: func(d time.Duration) { paused = append(paused, d); clock = clock.Add(d) }}
	in := strings.Repeat("waypoint 1 2\n", coreBurst+3)
	if err := h.serveCore(struct {
		io.Reader
		io.Writer
	}{strings.NewReader(in), &out}, lim); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "refused\n"); got != coreBurst+3 || strings.Contains(out.String(), "ok") {
		t.Errorf("answers = %q", out.String())
	}
	if got := strings.Count(logs.String(), "core side refused"); got != coreBurst+3 {
		t.Errorf("%d refusals logged, want %d:\n%s", got, coreBurst+3, logs.String())
	}
	if len(paused) != 3 || !strings.Contains(logs.String(), "over its rate") {
		t.Errorf("a burst of %d lines paused %d times (%v), want 3", coreBurst+3, len(paused), paused)
	}
	for _, d := range paused {
		if d < coreInterval-time.Millisecond {
			t.Errorf("paused %v, less than the rate's interval", d)
		}
	}
	// After a quiet spell the burst is back.
	clock = clock.Add(coreBurst * coreInterval)
	paused = nil
	for i := 0; i < coreBurst; i++ {
		lim.wait()
	}
	if len(paused) != 0 {
		t.Errorf("a burst after a quiet spell paused %d times", len(paused))
	}
	// The rate is the holder's: a reconnect does not refill it.
	clock = clock.Add(coreBurst * coreInterval)
	paused = nil
	h.core = lim
	for _, n := range []int{coreBurst, 3} {
		h.ServeCore(struct {
			io.Reader
			io.Writer
		}{strings.NewReader(strings.Repeat("arm\n", n)), io.Discard})
	}
	if len(paused) != 3 {
		t.Errorf("a burst split over two connections paused %d times, want 3", len(paused))
	}

	// A line over the limit ends the connection.
	out.Reset()
	if err := h.serveCore(struct {
		io.Reader
		io.Writer
	}{strings.NewReader(strings.Repeat("x", maxCoreLine+1) + "\n"), &out}, newLimiter()); err == nil {
		t.Error("an over-long line did not end the connection")
	}
	// A refused line is logged quoted and cut short, so the core cannot
	// write the log.
	logs.Reset()
	h.serveCore(struct {
		io.Reader
		io.Writer
	}{strings.NewReader("x\x1b[2J" + strings.Repeat("y", 100) + "\n"), io.Discard}, newLimiter())
	if strings.Contains(logs.String(), "\x1b") || strings.Contains(logs.String(), strings.Repeat("y", 50)) {
		t.Errorf("a refused line was logged raw: %q", logs.String())
	}
}
