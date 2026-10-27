package homekit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bounds on /accessories (a HAP bridge holds at most 150 accessories).
const (
	maxAccessories = 150
	maxServices    = 64
	maxChars       = 64
	maxEventsWait  = 1024
)

// ID names one characteristic instance on the accessory.
type ID struct{ AID, IID uint64 }

// Characteristic is one resolved characteristic: its service and type
// (short HAP form for Apple-defined UUIDs), permissions, format and the
// declared range or enumeration a write must keep to (DEV-4).
type Characteristic struct {
	ID
	Service, Type string
	Perms         []string
	Format        string
	Min, Max      *float64
	Step          *float64
	ValidValues   []float64
}

func (c *Characteristic) can(perm string) bool { return slices.Contains(c.Perms, perm) }

// Value is one value read or received in an event. V is a bool, a float64
// or a string, as the accessory's JSON gave it.
type Value struct {
	ID
	V any
}

// Session is one encrypted session with a verified accessory. Its first
// error ends it; open another with Verify. Events that arrive while a call
// waits for its response go to Options.OnEvent once the call has released
// the session, so a callback may call back into it.
type Session struct {
	mu      sync.Mutex
	closing atomic.Bool
	events  [][]Value // held for OnEvent until the lock is released
	raw     io.ReadWriter
	host    string
	w       io.Writer
	br      *bufio.Reader
	err     error
	opt     Options
	chars   map[ID]*Characteristic
	config  int
}

func newSession(conn io.ReadWriter, host string, shared []byte, opt Options) (*Session, error) {
	wc, err := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Write-Encryption-Key"))
	if err != nil {
		return nil, err
	}
	rc, err := newFrameCipher(hkdfKey(shared, "Control-Salt", "Control-Read-Encryption-Key"))
	if err != nil {
		return nil, err
	}
	return &Session{
		raw:  conn,
		host: host,
		w:    &frameWriter{w: conn, c: wc},
		br:   bufio.NewReaderSize(&frameReader{r: conn, c: rc}, readBufSize),
		opt:  opt,
	}, nil
}

// lock and unlock guard the session; unlock hands the events held during
// the call to OnEvent after releasing the lock (#3325 item 1).
func (s *Session) lock() { s.mu.Lock() }

func (s *Session) unlock() {
	evs := s.events
	s.events = nil
	s.mu.Unlock()
	for _, e := range evs {
		s.opt.OnEvent(e)
	}
}

type deadliner interface{ SetDeadline(time.Time) error }

// Close ends the session. It closes the connection before taking the lock,
// so a call blocked reading from the accessory ends at once with ErrClosed
// instead of holding Close (#3325 item 3).
func (s *Session) Close() error {
	s.closing.Store(true)
	if c, ok := s.raw.(io.Closer); ok {
		c.Close()
	} else if d, ok := s.raw.(deadliner); ok {
		d.SetDeadline(time.Unix(1, 0))
	}
	s.lock()
	defer s.unlock()
	s.fail(ErrClosed)
	return nil
}

// end fails the session with err and returns what the caller sees: the
// error, or ErrClosed when Close cut the call short.
func (s *Session) end(err error) error {
	s.fail(err)
	if s.closing.Load() {
		return ErrClosed
	}
	return err
}

func (s *Session) fail(err error) {
	if s.closing.Load() {
		err = ErrClosed
	}
	if s.err == nil {
		s.err = err
		s.opt.logf("homekit: session with %s ended: %v", s.host, err)
		if c, ok := s.raw.(io.Closer); ok {
			c.Close()
		}
	}
}

// do sends one request and returns its response, holding any events that
// arrive first for OnEvent. Any transport or framing error ends the
// session; with Options.Timeout, so does an accessory that does not answer
// in time.
func (s *Session) do(method, path string, body []byte) (*response, error) {
	if s.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClosed, s.err)
	}
	if d, ok := s.raw.(deadliner); ok && s.opt.Timeout > 0 {
		d.SetDeadline(time.Now().Add(s.opt.Timeout))
		defer d.SetDeadline(time.Time{})
	}
	ct := ""
	if body != nil {
		ct = "application/hap+json"
	}
	if err := writeRequest(s.w, method, path, s.host, ct, body); err != nil {
		return nil, s.end(err)
	}
	for i := 0; i < maxEventsWait; i++ {
		r, err := readResponse(s.br)
		if err != nil {
			return nil, s.end(err)
		}
		if !r.event {
			if r.status >= 300 && r.status < 400 {
				return nil, s.end(fmt.Errorf("%w: redirect refused", ErrProtocol))
			}
			return r, nil
		}
		s.hold(r.body)
	}
	return nil, s.end(fmt.Errorf("%w: over %d events before a response", ErrProtocol, maxEventsWait))
}

// hold keeps an event's values for resolved characteristics that offer
// events, for unlock to pass on.
func (s *Session) hold(body []byte) {
	vals, err := parseValues(body)
	if err != nil || s.opt.OnEvent == nil {
		return
	}
	var out []Value
	for _, v := range vals {
		if c := s.chars[v.ID]; c != nil && c.can("ev") {
			out = append(out, v)
		}
	}
	if len(out) > 0 {
		s.events = append(s.events, out)
	}
}

// Resolve reads /accessories and replaces the resolved characteristics.
func (s *Session) Resolve() error {
	s.lock()
	defer s.unlock()
	return s.resolve()
}

func (s *Session) resolve() error {
	r, err := s.do("GET", "/accessories", nil)
	if err != nil {
		return err
	}
	if r.status != 200 {
		return fmt.Errorf("%w: /accessories status %d", ErrProtocol, r.status)
	}
	chars, err := parseAccessories(r.body)
	if err != nil {
		return err
	}
	s.chars = chars
	return nil
}

// ConfigNumber takes the TXT record's c# and re-resolves when it changed.
func (s *Session) ConfigNumber(c int) error {
	s.lock()
	defer s.unlock()
	if s.chars != nil && c == s.config {
		return nil
	}
	if err := s.resolve(); err != nil {
		return err
	}
	s.config = c
	return nil
}

// Characteristic returns the resolved characteristic, if any.
func (s *Session) Characteristic(id ID) (Characteristic, bool) {
	s.lock()
	defer s.unlock()
	c := s.chars[id]
	if c == nil {
		return Characteristic{}, false
	}
	return *c, true
}

// Find returns the resolved characteristic of type typ in service svc on
// accessory aid. A bridge exposes one accessory per device, so the aid names
// the device; an aid with two matches is ambiguous and finds nothing
// (#3325 item 2).
func (s *Session) Find(aid uint64, svc, typ string) (Characteristic, bool) {
	s.lock()
	defer s.unlock()
	var found *Characteristic
	for _, c := range s.chars {
		if c.AID == aid && c.Service == svc && c.Type == typ {
			if found != nil {
				return Characteristic{}, false
			}
			found = c
		}
	}
	if found == nil {
		return Characteristic{}, false
	}
	return *found, true
}

// Read reads resolved, readable characteristics.
func (s *Session) Read(ids ...ID) ([]Value, error) {
	s.lock()
	defer s.unlock()
	if len(ids) == 0 || len(ids) > maxChars {
		return nil, fmt.Errorf("%w: read of %d characteristics", ErrRefused, len(ids))
	}
	q := make([]string, len(ids))
	for i, id := range ids {
		c := s.chars[id]
		if c == nil || !c.can("pr") {
			return nil, fmt.Errorf("%w: %d.%d is not a readable resolved characteristic", ErrRefused, id.AID, id.IID)
		}
		q[i] = fmt.Sprintf("%d.%d", id.AID, id.IID)
	}
	r, err := s.do("GET", "/characteristics?id="+strings.Join(q, ","), nil)
	if err != nil {
		return nil, err
	}
	if r.status != 200 && r.status != 207 {
		return nil, fmt.Errorf("%w: read status %d", ErrProtocol, r.status)
	}
	vals, err := parseValues(r.body)
	if err != nil {
		return nil, err
	}
	var out []Value
	for _, v := range vals {
		if slices.Contains(ids, v.ID) {
			out = append(out, v)
		}
	}
	return out, nil
}

// Write checks value against the resolved characteristic's permissions,
// format and declared range or enumeration, and only then frames it.
func (s *Session) Write(id ID, value any) error {
	s.lock()
	defer s.unlock()
	c := s.chars[id]
	if c == nil {
		return fmt.Errorf("%w: %d.%d is not a resolved characteristic", ErrRefused, id.AID, id.IID)
	}
	if !c.can("pw") {
		return fmt.Errorf("%w: %d.%d is not writable", ErrRefused, id.AID, id.IID)
	}
	v, err := checkValue(c, value)
	if err != nil {
		return err
	}
	return s.put(map[string]any{"aid": id.AID, "iid": id.IID, "value": v})
}

// Subscribe asks for events on a resolved characteristic that offers them.
func (s *Session) Subscribe(id ID) error {
	s.lock()
	defer s.unlock()
	c := s.chars[id]
	if c == nil || !c.can("ev") {
		return fmt.Errorf("%w: %d.%d offers no events", ErrRefused, id.AID, id.IID)
	}
	return s.put(map[string]any{"aid": id.AID, "iid": id.IID, "ev": true})
}

func (s *Session) put(item map[string]any) error {
	body, err := json.Marshal(map[string]any{"characteristics": []any{item}})
	if err != nil {
		return err
	}
	r, err := s.do("PUT", "/characteristics", body)
	if err != nil {
		return err
	}
	switch r.status {
	case 204:
		return nil
	case 207:
		return fmt.Errorf("%w: accessory refused the write", ErrRefused)
	}
	return fmt.Errorf("%w: write status %d", ErrProtocol, r.status)
}

var intRange = map[string][2]float64{
	"uint8": {0, math.MaxUint8}, "uint16": {0, math.MaxUint16},
	"uint32": {0, math.MaxUint32}, "uint64": {0, 1 << 53}, "int": {math.MinInt32, math.MaxInt32},
}

// checkValue returns the JSON value to send, or ErrRefused.
func checkValue(c *Characteristic, value any) (any, error) {
	refuse := func(why string) error {
		return fmt.Errorf("%w: %d.%d %s", ErrRefused, c.AID, c.IID, why)
	}
	var f float64
	switch v := value.(type) {
	case bool:
		if c.Format != "bool" {
			return nil, refuse("takes no bool")
		}
		return v, nil
	case int:
		f = float64(v)
	case float64:
		f = v
	default:
		return nil, refuse("value type not allowed")
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, refuse("value not finite")
	}
	if c.Min != nil && f < *c.Min || c.Max != nil && f > *c.Max {
		return nil, refuse("value outside the declared range")
	}
	if len(c.ValidValues) > 0 && !slices.Contains(c.ValidValues, f) {
		return nil, refuse("value not in the declared values")
	}
	if c.Step != nil && *c.Step > 0 && c.Min != nil {
		k := (f - *c.Min) / *c.Step
		if math.Abs(k-math.Round(k)) > 1e-6 {
			return nil, refuse("value off the declared step")
		}
	}
	switch c.Format {
	case "float":
		return f, nil
	case "bool":
		if f != 0 && f != 1 {
			return nil, refuse("bool is 0 or 1")
		}
		return f == 1, nil
	}
	if r, ok := intRange[c.Format]; ok {
		if f != math.Trunc(f) || f < r[0] || f > r[1] {
			return nil, refuse("value outside the format")
		}
		return int64(f), nil
	}
	return nil, refuse("format " + strconv.Quote(c.Format) + " is not writable here")
}

// hapBase is the Apple base UUID suffix; types under it use the short form.
const hapBase = "-0000-1000-8000-0026BB765291"

// shortType normalizes a HAP type UUID: "0000004A-0000-1000-8000-0026BB765291"
// and "4A" both become "4A"; other UUIDs stay full, upper case.
func shortType(t string) (string, error) {
	t = strings.ToUpper(t)
	if len(t) == 0 || len(t) > 36 {
		return "", fmt.Errorf("%w: bad type", ErrProtocol)
	}
	for _, r := range t {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F' || r == '-') {
			return "", fmt.Errorf("%w: bad type", ErrProtocol)
		}
	}
	if len(t) == 36 && strings.HasSuffix(t, hapBase) {
		t = t[:8]
	}
	if len(t) <= 8 && !strings.Contains(t, "-") {
		t = strings.TrimLeft(t, "0")
		if t == "" {
			t = "0"
		}
		return t, nil
	}
	if len(t) != 36 {
		return "", fmt.Errorf("%w: bad type", ErrProtocol)
	}
	return t, nil
}

type jsonChar struct {
	IID         uint64    `json:"iid"`
	Type        string    `json:"type"`
	Perms       []string  `json:"perms"`
	Format      string    `json:"format"`
	Min         *float64  `json:"minValue"`
	Max         *float64  `json:"maxValue"`
	Step        *float64  `json:"minStep"`
	ValidValues []float64 `json:"valid-values"`
}

type jsonAccessories struct {
	Accessories []struct {
		AID      uint64 `json:"aid"`
		Services []struct {
			Type  string     `json:"type"`
			Chars []jsonChar `json:"characteristics"`
		} `json:"services"`
	} `json:"accessories"`
}

func parseAccessories(body []byte) (map[ID]*Characteristic, error) {
	var doc jsonAccessories
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: /accessories json", ErrProtocol)
	}
	if len(doc.Accessories) == 0 || len(doc.Accessories) > maxAccessories {
		return nil, fmt.Errorf("%w: %d accessories", ErrProtocol, len(doc.Accessories))
	}
	out := map[ID]*Characteristic{}
	for _, a := range doc.Accessories {
		if len(a.Services) > maxServices {
			return nil, fmt.Errorf("%w: %d services", ErrProtocol, len(a.Services))
		}
		for _, sv := range a.Services {
			st, err := shortType(sv.Type)
			if err != nil {
				return nil, err
			}
			if len(sv.Chars) > maxChars {
				return nil, fmt.Errorf("%w: %d characteristics", ErrProtocol, len(sv.Chars))
			}
			for _, jc := range sv.Chars {
				ct, err := shortType(jc.Type)
				if err != nil {
					return nil, err
				}
				id := ID{a.AID, jc.IID}
				if out[id] != nil || len(jc.Perms) > 8 || len(jc.ValidValues) > 64 || len(jc.Format) > 16 {
					return nil, fmt.Errorf("%w: characteristic %d.%d", ErrProtocol, a.AID, jc.IID)
				}
				out[id] = &Characteristic{ID: id, Service: st, Type: ct, Perms: jc.Perms, Format: jc.Format,
					Min: jc.Min, Max: jc.Max, Step: jc.Step, ValidValues: jc.ValidValues}
			}
		}
	}
	return out, nil
}

func parseValues(body []byte) ([]Value, error) {
	var doc struct {
		Chars []struct {
			AID   uint64          `json:"aid"`
			IID   uint64          `json:"iid"`
			Value json.RawMessage `json:"value"`
		} `json:"characteristics"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: characteristics json", ErrProtocol)
	}
	if len(doc.Chars) > maxChars {
		return nil, fmt.Errorf("%w: %d values", ErrProtocol, len(doc.Chars))
	}
	var out []Value
	for _, c := range doc.Chars {
		var v any
		if len(c.Value) == 0 || json.Unmarshal(c.Value, &v) != nil {
			continue
		}
		switch x := v.(type) {
		case bool, float64:
		case string:
			if len(x) > 256 {
				continue
			}
		default:
			continue
		}
		out = append(out, Value{ID{c.AID, c.IID}, v})
	}
	return out, nil
}
