package drone

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The core-side channel is a line protocol, not MAVLink (brief decision 7).
// Exactly one line is a command: returnToDock. A camera fix is a report the
// GPS/camera check weighs, never a command (brief decision 10). Every other
// line is refused and logged, and nothing reaches the aircraft for it (P5).
const (
	returnToDock  = "return_to_dock"
	cameraFixWord = "camera_fix"
	maxCoreLine   = 128

	coreBurst    = 5           // lines the channel takes at once
	coreInterval = time.Second // then one line per interval
)

type coreKind int

const (
	coreRefused coreKind = iota
	coreReturn
	coreCameraFix
)

// parseCore reads one core-side line. It is pure, so the fuzz test can show
// that only the exact returnToDock line yields a command.
func parseCore(line string) (coreKind, Point, error) {
	if line == returnToDock {
		return coreReturn, Point{}, nil
	}
	f := strings.Split(line, " ")
	if len(f) == 3 && f[0] == cameraFixWord {
		lat, err1 := parseCoord(f[1])
		lon, err2 := parseCoord(f[2])
		if err1 == nil && err2 == nil {
			p := Point{Lat: lat, Lon: lon}
			if checkPoint(p) == nil {
				return coreCameraFix, p, nil
			}
		}
		return coreRefused, Point{}, errors.New("a camera fix must be two decimal degrees in range")
	}
	return coreRefused, Point{}, errors.New("the core side may send only return_to_dock or a camera fix")
}

// parseCoord takes only plain decimal degrees: no exponent, hex, sign
// prefix '+', infinity or NaN, so a near-miss is not read as a number.
func parseCoord(s string) (float64, error) {
	if s == "" || len(s) > 16 || strings.Trim(s, "-.0123456789") != "" {
		return 0, errors.New("not decimal degrees")
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, errors.New("not decimal degrees")
	}
	return v, nil
}

// limiter is a token bucket: coreBurst lines at once, then one per
// coreInterval. An empty bucket pauses the reader, so a flood waits rather
// than reaching the aircraft at line rate.
type limiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	now    func() time.Time
	sleep  func(time.Duration)
}

func newLimiter() *limiter {
	return &limiter{tokens: coreBurst, now: time.Now, sleep: time.Sleep}
}

// wait takes one token, pausing first if there is none. It reports whether
// it paused.
func (l *limiter) wait() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if !l.last.IsZero() {
		l.tokens = math.Min(coreBurst, l.tokens+t.Sub(l.last).Seconds()/coreInterval.Seconds())
	}
	l.last = t
	if l.tokens >= 1 {
		l.tokens--
		return false
	}
	d := time.Duration((1 - l.tokens) * float64(coreInterval))
	l.sleep(d)
	l.last = l.last.Add(d)
	l.tokens = 0
	return true
}

// ServeCore serves one core-side connection until it closes: each line is
// rate-limited, parsed and answered with "ok" or "refused". A line longer
// than maxCoreLine ends the connection. The rate is the holder's, across
// connections, so reconnecting does not refill it.
func (h *Holder) ServeCore(rw io.ReadWriter) error {
	return h.serveCore(rw, h.core)
}

func (h *Holder) serveCore(rw io.ReadWriter, lim *limiter) error {
	sc := bufio.NewScanner(rw)
	sc.Buffer(make([]byte, maxCoreLine+1), maxCoreLine+1)
	for sc.Scan() {
		if lim.wait() {
			h.log.Printf("drone: core side over its rate, paused")
		}
		line := sc.Text()
		kind, fix, err := parseCore(line)
		switch kind {
		case coreReturn:
			err = h.Return("the core side asked")
		case coreCameraFix:
			_, err = h.CameraFix(fix)
		default:
			h.log.Printf("drone: core side refused: %q: %v", truncate(line, 40), err)
		}
		answer := "ok\n"
		if err != nil {
			answer = "refused\n"
		}
		if _, werr := io.WriteString(rw, answer); werr != nil {
			return werr
		}
	}
	if err := sc.Err(); err != nil {
		h.log.Printf("drone: core side connection ended: %v", err)
		return fmt.Errorf("drone: core side: %w", err)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
