package plan

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Metering a model call (MIG-4-plan-login-b, LOG-7, RES-5). The model clerk
// admits each call before it is sent and settles it once it has ended, from
// what the provider's answer carried on this clerk's own connection: the
// usage the stream reports and the pool's reading in its headers. Nothing
// the guest writes is read for either.

// Meter is the model clerk's check and record of one model call. Do calls
// it with the checked body once nothing is left to refuse but the spend,
// before any byte is sent; a non-empty detail refuses the call. The settle
// it returns is called exactly once, when the call has ended.
type Meter func(body []byte) (settle func(Used), detail string)

// Used is how a model call ended.
type Used struct {
	// Sent is false only when no byte of the request left (the dial was
	// refused by the home-network policy).
	Sent bool
	// Done is a 2xx answer read to its end.
	Done bool
	// Reported is set when the stream's last event carried the usage.
	Reported bool
	In, Out  int64
	// Bytes is the answer's length as read, for the clerk's own count.
	Bytes int64
	// Pool is the plan's usage pool as the answer's headers state it.
	Pool *Reading
}

// Reading is a usage pool's state: per mille used, and when it resets
// (unix ms; 0 when the answer did not say).
type Reading struct{ Used, ResetAt int64 }

// Pool is how a provider's answer states the plan's usage pool (RES-5).
type Pool struct {
	// Windows are the header prefixes of the pool's rate windows. Each
	// window carries <prefix>Used-Percent and <prefix>Reset-At (unix s).
	Windows []string
	// Reached names a header whose presence reads as a full pool.
	Reached string
}

// DUnmetered is Do's answer for a model call with no meter: nothing sent.
const DUnmetered = "plan-unmetered"

// DBody is a model call whose body is out of its declared shape; then the
// rule it broke. Nothing was sent.
const DBody = "plan-body"

// maxEvent bounds one stream event read for its usage. A longer one is
// passed on unread, and the call is metered as if it reported nothing.
const maxEvent = 4 << 20

// reading is the pool's state from h: the window nearest its limit, and a
// reached limit as a full pool. A window whose use is unreadable is no
// reading of it, since 0% would read as an open pool.
func (p Pool) reading(h http.Header) *Reading {
	var r *Reading
	var latest int64
	for _, pre := range p.Windows {
		pct, err := strconv.ParseFloat(strings.TrimSpace(h.Get(pre+"Used-Percent")), 64)
		if err != nil || math.IsNaN(pct) || pct < 0 {
			continue
		}
		used := int64(math.Min(math.Ceil(pct*10), 1000))
		var reset int64
		if s, err := strconv.ParseInt(strings.TrimSpace(h.Get(pre+"Reset-At")), 10, 64); err == nil && s > 0 && s <= math.MaxInt64/1000 {
			reset = s * 1000
		}
		latest = max(latest, reset)
		if r == nil || used > r.Used || used == r.Used && reset > r.ResetAt {
			r = &Reading{Used: used, ResetAt: reset}
		}
	}
	if p.Reached != "" && h.Get(p.Reached) != "" {
		r = &Reading{Used: 1000, ResetAt: latest}
	}
	return r
}

// meterReader reads a model call's answer for its usage as it passes, and
// settles the call once: at its end, at a read error, or when it is closed.
type meterReader struct {
	r      io.ReadCloser
	settle func(Used)
	u      Used
	ok     bool // a 2xx answer
	stream bool // an event stream, read line by line
	line   []byte
	skip   bool // the current line passed maxEvent
	once   sync.Once
}

func newMeterReader(resp *http.Response, settle func(Used), pool *Reading) *meterReader {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return &meterReader{r: resp.Body, settle: settle, ok: resp.StatusCode/100 == 2, stream: strings.HasPrefix(ct, "text/event-stream"),
		u: Used{Sent: true, Pool: pool}}
}

func (m *meterReader) Read(b []byte) (int, error) {
	n, err := m.r.Read(b)
	m.u.Bytes += int64(n)
	if m.stream {
		m.observe(b[:n])
	}
	if err != nil {
		if err == io.EOF && m.stream && !m.skip && len(m.line) > 0 {
			m.event(m.line) // a last line with no newline
		}
		m.end(err == io.EOF)
	}
	return n, err
}

func (m *meterReader) Close() error {
	m.end(false)
	return m.r.Close()
}

func (m *meterReader) end(eof bool) {
	m.once.Do(func() {
		m.u.Done = eof && m.ok
		m.settle(m.u)
	})
}

func (m *meterReader) observe(b []byte) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		part := b
		if i >= 0 {
			part = b[:i]
		}
		if !m.skip {
			if len(m.line)+len(part) > maxEvent {
				m.skip, m.line = true, nil
			} else {
				m.line = append(m.line, part...)
			}
		}
		if i < 0 {
			return
		}
		if !m.skip {
			m.event(m.line)
		}
		m.line, m.skip = m.line[:0], false
		b = b[i+1:]
	}
}

// event reads one stream line. A Responses stream reports its usage on its
// last event (response.completed, .incomplete or .failed).
func (m *meterReader) event(l []byte) {
	d, ok := bytes.CutPrefix(bytes.TrimSuffix(l, []byte("\r")), []byte("data:"))
	if !ok {
		return
	}
	var ev struct {
		Type     string `json:"type"`
		Response struct {
			Usage *struct {
				In  *float64 `json:"input_tokens"`
				Out *float64 `json:"output_tokens"`
			} `json:"usage"`
		} `json:"response"`
	}
	if json.Unmarshal(bytes.TrimSpace(d), &ev) != nil {
		return
	}
	switch ev.Type {
	case "response.completed", "response.incomplete", "response.failed":
	default:
		return
	}
	u := ev.Response.Usage
	if u == nil || !count(u.In) || !count(u.Out) {
		return
	}
	m.u.Reported, m.u.In, m.u.Out = true, int64(*u.In), int64(*u.Out)
}

// count is a token figure the clerk takes: a whole number, at most 1e12.
func count(f *float64) bool {
	return f != nil && *f >= 0 && *f <= 1e12 && *f == math.Trunc(*f)
}
