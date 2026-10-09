package modemlink

// LOOP-7 bullet 2 (P3-4b-3): fuzz target for the bridge's inbound-text
// decoder on owner.sock, with a planted-decoder control.
// REQ: LOOP-7

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

type reporter interface {
	Errorf(format string, args ...any)
}

type recorder struct{ msgs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

const fuzzOwner = "+15550000001"

type inboundFunc func(*Link, json.RawMessage) (any, error)

func realInbound(l *Link, args json.RawMessage) (any, error) {
	return l.inbound(context.Background(), sockets.Peer{Kind: "owner"}, args)
}

// checkInbound hands args to a fresh, usable link through inbound and
// checks: no panic; args that do not decode to a valid Inbound are refused
// as bad and change nothing; only a text on the owner line from the
// owner's number, not a sender name, reaches the owner's inbox, and it
// arrives as sent.
func checkInbound(r reporter, inbound inboundFunc, args []byte) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	l := New(Config{Owner: fuzzOwner, Now: func() time.Time { return now }})
	if _, err := l.setState(context.Background(), sockets.Peer{}, json.RawMessage(`{"owner_line":"ok"}`)); err != nil {
		r.Errorf("set state: %v", err)
		return
	}
	var err error
	func() {
		defer func() {
			if p := recover(); p != nil {
				r.Errorf("decoder panicked on %q: %v", args, p)
				err = errors.New("panic")
			}
		}()
		_, err = inbound(l, args)
	}()
	var in bridgeproto.Inbound
	valid := json.Unmarshal(args, &in) == nil && in.Valid()
	var got []string
	for len(l.inbox) > 0 {
		m := <-l.inbox
		got = append(got, fmt.Sprintf("%s|%s|%v", m.From, m.Text, m.Alphanumeric))
	}
	if !valid {
		if !errors.Is(err, errBadInbound) && (err == nil || err.Error() != "panic") {
			r.Errorf("invalid %q: %v, want refused as bad", args, err)
		}
		if len(got) != 0 || l.others != 0 {
			r.Errorf("invalid %q changed the link: inbox %v, others %d", args, got, l.others)
		}
		return
	}
	owners := in.Line == bridgeproto.LineOwner && !in.Named && in.From == fuzzOwner
	want := []string(nil)
	if owners {
		want = []string{fmt.Sprintf("%s|%s|false", fuzzOwner, in.Text)}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		r.Errorf("%q reached the inbox as %v, want %v", args, got, want)
	}
}

func FuzzInbound(f *testing.F) {
	for _, s := range []string{
		`{"line":"owner","from":"+15550000001","text":"YES 1234","id":"a1"}`,
		`{"line":"owner","from":"+15550000002","text":"hi"}`,
		`{"line":"owner","from":"Bank","text":"code 1","named":true}`,
		`{"line":"owner","from":"+15550000001","text":"x","named":true}`,
		`{"line":"second","from":"+15550000001","text":"x"}`,
		`{"line":"owner","from":"+15550000001","text":"\ud800"}`,
		`{"line":"owner","from":"","text":"x"}`, `{"line":"other","from":"1","text":""}`,
		`{"line":"owner","from":"+15550000001","text":"x","line":"second"}`,
		`null`, `[]`, ``, `{"line":0}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, args []byte) { checkInbound(t, realInbound, args) })
}

// The check reports a planted decoder that panics, skips the limits, or
// lets a stranger's text into the owner's inbox; it passes the real one.
func TestInboundCheckReportsAPlantedDecoder(t *testing.T) {
	stranger := []byte(`{"line":"owner","from":"+15550000002","text":"planted"}`)
	long := []byte(`{"line":"owner","from":"+15550000001","text":"planted` + string(bytes.Repeat([]byte("x"), bridgeproto.MaxText)) + `"}`)
	planted := map[string]struct {
		dec  inboundFunc
		args []byte
	}{
		"panics": {func(l *Link, args json.RawMessage) (any, error) {
			if bytes.Contains(args, []byte("planted")) {
				panic("planted")
			}
			return realInbound(l, args)
		}, stranger},
		"no limits": {func(l *Link, args json.RawMessage) (any, error) {
			var in bridgeproto.Inbound
			if json.Unmarshal(args, &in) != nil {
				return nil, errBadInbound
			}
			l.inbox <- smsOf(in)
			return struct{}{}, nil
		}, long},
		"stranger": {func(l *Link, args json.RawMessage) (any, error) {
			var in bridgeproto.Inbound
			if json.Unmarshal(args, &in) != nil || !in.Valid() {
				return nil, errBadInbound
			}
			l.inbox <- smsOf(in)
			return struct{}{}, nil
		}, stranger},
	}
	for name, c := range planted {
		var rec recorder
		checkInbound(&rec, c.dec, c.args)
		if len(rec.msgs) == 0 {
			t.Errorf("%s: the check did not report the planted decoder", name)
		}
		rec = recorder{}
		checkInbound(&rec, realInbound, c.args)
		if len(rec.msgs) != 0 {
			t.Errorf("%s: the real decoder reported: %v", name, rec.msgs)
		}
	}
}

func smsOf(in bridgeproto.Inbound) modem.SMS {
	return modem.SMS{From: in.From, To: fuzzOwner, Text: in.Text, Alphanumeric: in.Named}
}
