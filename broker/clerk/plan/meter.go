package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	// Done is a 2xx event stream read to its end.
	Done bool
	// Reported is set when the stream's last event carried the usage.
	Reported bool
	In, Out  int64
	// Bytes is the answer's length as read, for the clerk's own count.
	Bytes int64
	// Pool is the plan's usage pool as the answer's headers state it.
	Pool *Reading
}

// Reading is a usage pool's state, window by window: only the windows the
// answer stated.
type Reading struct{ Windows []WindowUse }

// WindowUse is one window's state: its ID, per mille used, when it resets
// (unix ms; 0 when the answer did not say), and its declared length.
type WindowUse struct {
	Window               string
	Used, ResetAt, Every int64
}

// Pool is the plan's usage pool as the provider names it and as its answers
// state it (RES-5). Names and labels stay in the image's declaration: the
// log carries the pool's and windows' IDs only.
type Pool struct {
	// ID is the pool's kernel name, which model.Price.Pool carries.
	ID string
	// Name is the pool as the provider names it: "ChatGPT Codex".
	Name string
	// Windows are the pool's rate windows, in the provider's order.
	Windows []Window
	// Reached names a header whose presence reads as every window full.
	Reached string
}

// Window is one rate window of a pool. Its answer carries
// <Prefix>Used-Percent and <Prefix>Reset-At (unix s).
type Window struct {
	// ID is the window's kernel name: "5h".
	ID     string
	Prefix string
	// Label is the window as the provider names it: "5-hour limit".
	Label string
	// Every is the window's length in ms, the reset a full window with no
	// reset time falls back to.
	Every int64
}

// DUnmetered is Do's answer for a model call with no meter: nothing sent.
const DUnmetered = "plan-unmetered"

// DBody is a model call whose body is out of its declared shape; then the
// rule it broke. Nothing was sent.
const DBody = "plan-body"

// maxEvent bounds one stream event read for its usage. A longer one is
// passed on unread, and the call is metered as if it reported nothing.
const maxEvent = 4 << 20

// reading is the pool's state from h, each window read on its own, and a
// reached limit as every window full at the latest reset time. A window
// whose use is unreadable is no reading of it, since 0% would read as an
// open window.
func (p Pool) reading(h http.Header) *Reading {
	var ws []WindowUse
	var latest int64
	for _, w := range p.Windows {
		var reset int64
		if s, err := strconv.ParseInt(strings.TrimSpace(h.Get(w.Prefix+"Reset-At")), 10, 64); err == nil && s >= 1 && s <= math.MaxInt64/1000 {
			reset = s * 1000
		}
		latest = max(latest, reset)
		pct, err := strconv.ParseFloat(strings.TrimSpace(h.Get(w.Prefix+"Used-Percent")), 64)
		if err != nil || math.IsNaN(pct) || pct < 0 {
			continue
		}
		ws = append(ws, WindowUse{w.ID, int64(math.Min(math.Ceil(pct*10), 1000)), reset, w.Every})
	}
	if p.Reached != "" && h.Get(p.Reached) != "" {
		ws = ws[:0]
		for _, w := range p.Windows {
			ws = append(ws, WindowUse{w.ID, 1000, latest, w.Every})
		}
	}
	if len(ws) == 0 {
		return nil
	}
	return &Reading{ws}
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
		// Only a stream is read for its usage, so only a stream read to its
		// end is done; any other answer is metered at its worst case.
		m.u.Done = eof && m.ok && m.stream
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

// valid reports whether a pool declaration can be read and named: a pool
// with windows has an ID and a name, and each window its own ID, a prefix,
// a label and a length.
func (p Pool) valid() error {
	if len(p.Windows) == 0 {
		return nil
	}
	if p.ID == "" || p.Name == "" {
		return errors.New("a pool needs its ID and name")
	}
	seen := map[string]bool{}
	for _, w := range p.Windows {
		if w.ID == "" || seen[w.ID] || w.Prefix == "" || w.Label == "" || w.Every <= 0 {
			return fmt.Errorf("pool %s: window %q needs its own ID, a prefix, a label and a length", p.ID, w.ID)
		}
		seen[w.ID] = true
	}
	return nil
}
