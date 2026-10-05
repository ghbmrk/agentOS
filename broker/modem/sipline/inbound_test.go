package sipline_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/modem/sipsim"
	"github.com/ghbmrk/agentos/broker/sipsign"
)

// REQ: ADP-12, CH-1

// clip stands in for the broker-rendered "can't take calls" audio.
func clip(frames int) []byte {
	b := make([]byte, frames*at.FrameBytes)
	for i := range b {
		b[i] = byte(i*5 + 3)
	}
	return b
}

func withClip(p *sipsim.Provider, frames int) sipline.Config {
	cfg := config(p, vault(p))
	cfg.NoCallsClip = clip(frames)
	return cfg
}

// A call to the second line hears, over SRTP, that the number can't take
// calls and should be texted, and is then hung up (potency PL2 on #102):
// a caller learns what to do instead of meeting a silent decline.
func TestACallerHearsTheNumberCannotTakeCallsAndIsHungUp(t *testing.T) {
	p := provider(t)
	l := open(t, p, withClip(p, 3))
	ctx := context.Background()
	c, err := p.RingLine(ctx, shopNum, user, sipsim.Ring{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != 200 {
		t.Fatalf("status %d", c.Status)
	}
	// The answer echoes the caller's crypto tag, with the line's own key,
	// and picks one offered codec.
	if a := string(c.Answer); !strings.Contains(a, "RTP/SAVP 0\r\n") || !strings.Contains(a, "a=crypto:7 "+sipline.Suite+" inline:") {
		t.Fatalf("answer:\n%s", a)
	}
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the line did not hang up after the clip")
	}
	// The last packets may still be in flight when the BYE lands.
	want := sipline.ULaw(clip(3))
	eventually(t, "the whole clip", func() bool { return len(c.Heard()) >= len(want) })
	if h := c.Heard(); !bytes.HasPrefix(h, want) {
		t.Fatalf("heard %d bytes, want the clip's %d", len(h), len(want))
	}
	// The line is free again: an outbound call is not refused as busy.
	out, err := l.Dial(ctx, shopNum)
	if err != nil {
		t.Fatalf("after the clip: %v", err)
	}
	_ = out.Hangup(ctx)
}

// A caller offering only A-law hears the clip in A-law.
func TestTheClipIsPlayedInTheCallersCodec(t *testing.T) {
	p := provider(t)
	open(t, p, withClip(p, 2))
	c, err := p.RingLine(context.Background(), shopNum, user, sipsim.Ring{PTs: []int{sipline.PCMA}})
	if err != nil || c.Status != 200 {
		t.Fatalf("%v %v", c, err)
	}
	<-c.Done()
	want := sipline.ALaw(clip(2))
	eventually(t, "the whole clip", func() bool { return len(c.Heard()) >= len(want) })
	if !bytes.HasPrefix(c.Heard(), want) {
		t.Fatal("not the A-law clip")
	}
	if pts := c.PayloadTypes(); len(pts) != 1 || pts[0] != sipline.PCMA {
		t.Fatalf("payload types %v", pts)
	}
}

// The line declines (603) whenever the clip cannot be played safely: no
// clip configured, a caller without SRTP or without an offered codec, or a
// call already in progress. It never answers in the clear.
func TestCallsTheClipCannotReachAreDeclined(t *testing.T) {
	p := provider(t)
	ctx := context.Background()
	for name, o := range map[string]sipsim.Ring{
		"no SRTP":        {Plain: true},
		"no G.711":       {PTs: []int{18}},
		"broadcast addr": {Addr: "255.255.255.255"},
	} {
		l := open(t, p, withClip(p, 2))
		c, err := p.RingLine(ctx, shopNum, user, o)
		if err != nil || c.Status != 603 || len(c.Heard()) != 0 {
			t.Errorf("%s: %v %v", name, c, err)
		}
		_ = l.Close()
	}

	open(t, p, config(p, vault(p))) // no clip
	if c, err := p.RingLine(ctx, shopNum, user, sipsim.Ring{}); err != nil || c.Status != 603 {
		t.Fatalf("without a clip: %v %v", c, err)
	}
}

func TestACallToTheLineWhileItIsOnACallIsDeclined(t *testing.T) {
	p := provider(t)
	l := open(t, p, withClip(p, 2))
	ctx := context.Background()
	out, err := l.Dial(ctx, shopNum)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Hangup(ctx)
	far := <-p.Calls()
	_ = far.Ring()
	if c, err := p.RingLine(ctx, ownerNum, user, sipsim.Ring{}); err != nil || c.Status != 603 {
		t.Fatalf("while busy: %v %v", c, err)
	}
}

// A caller hanging up mid-clip ends the call at once, and the line is free.
func TestACallerHangingUpMidClipFreesTheLine(t *testing.T) {
	p := provider(t)
	cfg := withClip(p, 2000) // far longer than the test
	cfg.FramePace = 5 * time.Millisecond
	l := open(t, p, cfg)
	ctx := context.Background()
	c, err := p.RingLine(ctx, shopNum, user, sipsim.Ring{})
	if err != nil || c.Status != 200 {
		t.Fatalf("%v %v", c, err)
	}
	eventually(t, "some of the clip", func() bool { return len(c.Heard()) > 0 })
	if err := c.Hangup(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the line free", func() bool {
		out, err := l.Dial(ctx, shopNum)
		if err != nil {
			return false
		}
		_ = out.Hangup(ctx)
		return true
	})
	n := len(c.Heard())
	time.Sleep(50 * time.Millisecond)
	if len(c.Heard()) != n {
		t.Fatal("the clip kept playing after the caller hung up")
	}
}

// The parser for the caller's offer accepts any crypto tag and keeps the
// answer's rules: SRTP, an offered G.711 codec, a public unicast address.
func TestTheCallersOfferIsCheckedLikeAnAnswer(t *testing.T) {
	sdp := func(addr, proto, fmts, crypto string) []byte {
		return []byte(fmt.Sprintf("v=0\r\no=- 0 0 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio 4000 %s %s\r\n%s", addr, addr, proto, fmts, crypto))
	}
	key := "a=crypto:3 " + sipline.Suite + " inline:" + strings.Repeat("A", 40) + "\r\n"
	if tag, err := sipline.ParseOffer(sdp("203.0.113.5", "RTP/SAVP", "8 0", key), false); err != nil || tag != "3" {
		t.Fatalf("good offer: %q %v", tag, err)
	}
	for name, b := range map[string][]byte{
		"plain":   sdp("203.0.113.5", "RTP/AVP", "0", ""),
		"no key":  sdp("203.0.113.5", "RTP/SAVP", "0", ""),
		"codec":   sdp("203.0.113.5", "RTP/SAVP", "18", key),
		"private": sdp("192.168.1.5", "RTP/SAVP", "0", key),
		"loop":    sdp("127.0.0.1", "RTP/SAVP", "0", key),
		"tag":     sdp("203.0.113.5", "RTP/SAVP", "0", strings.Replace(key, "crypto:3", "crypto:3x", 1)),
		"tag 10":  sdp("203.0.113.5", "RTP/SAVP", "0", strings.Replace(key, "crypto:3", "crypto:1234567890", 1)),
	} {
		if _, err := sipline.ParseOffer(b, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Errors reach the owner in plain words that say what to do, never the
// provider's reason text or a status code (UX on #102).
func TestLineErrorsHaveOwnerWording(t *testing.T) {
	for err, want := range map[error]string{
		sipline.ErrNumber:                            "isn't a phone number",
		sipline.ErrBusy:                              "already on a call",
		sipline.ErrClosed:                            "isn't connected right now",
		sipline.ErrConfig:                            "isn't set up. Set it up on the box's local page",
		sipline.ErrInsecure:                          "couldn't connect securely",
		sipline.ErrNoSRTP:                            "Turn on encrypted calls (SRTP)",
		sipline.ErrMediaAddress:                      "isn't on a safe address",
		sipline.ErrTextRefused:                       "provider didn't accept",
		fmt.Errorf("%w: 486", sipline.ErrCallFailed): "doesn't call again on its own",
		fmt.Errorf("x: %w", sipline.ErrUnreachable):  "It will keep trying to reconnect",
		sipsign.ErrLocked:                            "while the box is locked",
		sipsign.ErrNoAccount:                         "isn't set up",
		sipsign.ErrRefused:                           "local page",
		errors.New("anything else 486 Busy"):         "couldn't reach its provider, so that didn't go through",
	} {
		got := sipline.OwnerText(err)
		if !strings.Contains(got, want) {
			t.Errorf("%v: %q lacks %q", err, got, want)
		}
		if strings.ContainsAny(got, "0123456789") || strings.Contains(got, "sipline") {
			t.Errorf("%v: %q carries internals", err, got)
		}
	}
	if sipline.OwnerText(nil) != "" {
		t.Fatal("nil has text")
	}
}

// A sender the provider does not vouch for reaches the agent as a named
// sender, labelled so it never reads as a number (UX on #102).
func TestUnvouchedSendersReachTheAgentAsNamedSenders(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	tl := tool(t, l, time.Second)
	ctx := context.Background()
	if _, err := p.Relay(ctx, sipsim.Incoming{From: "ShopCo", FromHost: "elsewhere.example", User: user, ContentType: "text/plain", Body: "Your table is ready"}); err != nil {
		t.Fatal(err)
	}
	select {
	case u := <-tl.Inbound():
		if !u.Named || u.Sender() != "named sender ShopCo" {
			t.Fatalf("%+v as %q", u, u.Sender())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing delivered")
	}
	if _, err := p.Relay(ctx, sipsim.Incoming{From: shopNum, User: user, ContentType: "text/plain", Body: "hi"}); err != nil {
		t.Fatal(err)
	}
	if u := <-tl.Inbound(); u.Named || u.Sender() != shopNum {
		t.Fatalf("%+v as %q", u, u.Sender())
	}
}

// Security F1 on #132: the clip goes only to a caller that acknowledged
// the answer and sent audio that authenticates under its own key from the
// address it offered. A forged offer naming someone else's address gets
// nothing but a hangup.
func TestTheClipWaitsForTheCallersAckAndAuthenticatedAudio(t *testing.T) {
	defer sipline.SetInbound(300*time.Millisecond, 300*time.Millisecond, time.Now)()
	p := provider(t)
	l := open(t, p, withClip(p, 2))
	ctx := context.Background()

	silent, err := p.RingLine(ctx, shopNum, user, sipsim.Ring{Silent: true})
	if err != nil || silent.Status != 200 {
		t.Fatalf("%v %v", silent, err)
	}
	select {
	case <-silent.Done(): // the line's BYE
	case <-time.After(3 * time.Second):
		t.Fatal("no hangup for a caller that sent no audio")
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(silent.Heard()); n != 0 {
		t.Fatalf("a silent caller heard %d bytes", n)
	}

	elsewhere, err := p.RingLine(ctx, boxNum, user, sipsim.Ring{Elsewhere: true})
	if err != nil || elsewhere.Status != 200 {
		t.Fatalf("%v %v", elsewhere, err)
	}
	select {
	case <-elsewhere.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("no hangup for audio from another address")
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(elsewhere.Heard()); n != 0 {
		t.Fatalf("audio from another address unlocked the clip: %d bytes", n)
	}

	wrongKey, err := p.RingLine(ctx, "+15550000555", user, sipsim.Ring{WrongKey: true})
	if err != nil || wrongKey.Status != 200 {
		t.Fatalf("%v %v", wrongKey, err)
	}
	select {
	case <-wrongKey.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("no hangup for audio under another key")
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(wrongKey.Heard()); n != 0 {
		t.Fatalf("audio under another key unlocked the clip: %d bytes", n)
	}

	unacked, err := p.RingLine(ctx, ownerNum, user, sipsim.Ring{NoAck: true})
	if err != nil || unacked.Status != 200 {
		t.Fatalf("%v %v", unacked, err)
	}
	// The line is free again within the ACK bound, without a word said.
	eventually(t, "the line free", func() bool {
		out, err := l.Dial(ctx, shopNum)
		if err != nil {
			return false
		}
		_ = out.Hangup(ctx)
		return true
	})
	if n := len(unacked.Heard()); n != 0 {
		t.Fatalf("a caller that never acknowledged heard %d bytes", n)
	}
}

// Security F2 on #132: each clip is an answered call, so a caller gets one
// per 10 minutes and the line 20 an hour; past either, 603.
func TestClipsAreCappedPerCallerAndPerHour(t *testing.T) {
	var mu sync.Mutex
	clock := time.Unix(1_800_000_000, 0)
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	defer sipline.SetInbound(time.Second, time.Second, func() time.Time { mu.Lock(); defer mu.Unlock(); return clock })()
	p := provider(t)
	open(t, p, withClip(p, 1))
	ctx := context.Background()
	ring := func(from string) int {
		t.Helper()
		c, err := p.RingLine(ctx, from, user, sipsim.Ring{})
		if err != nil {
			t.Fatal(err)
		}
		<-c.Done()
		return c.Status
	}
	if s := ring(shopNum); s != 200 {
		t.Fatalf("first call: %d", s)
	}
	if s := ring(shopNum); s != 603 {
		t.Fatalf("a repeat caller within 10 minutes: %d", s)
	}
	advance(10 * time.Minute)
	if s := ring(shopNum); s != 200 {
		t.Fatalf("after 10 minutes: %d", s)
	}
	for i := 3; i <= 20; i++ {
		if s := ring(fmt.Sprintf("+1555000%04d", i)); s != 200 {
			t.Fatalf("call %d of the hour: %d", i, s)
		}
	}
	if s := ring("+15550009999"); s != 603 {
		t.Fatalf("the 21st call in an hour: %d", s)
	}
	advance(time.Hour)
	if s := ring("+15550009999"); s != 200 {
		t.Fatalf("an hour later: %d", s)
	}
}

// A call the far end refuses ends with ErrCallFailed, worded for the owner
// as not retried (L3 S4 on #132).
func TestARefusedCallEndsWithCallFailed(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	c, err := l.Dial(context.Background(), shopNum)
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.Calls()
	_ = far.Reject(486)
	<-c.Ended()
	err = c.(interface{ Err() error }).Err()
	if !errors.Is(err, sipline.ErrCallFailed) || !strings.Contains(sipline.OwnerText(err), "doesn't call again") {
		t.Fatalf("%v", err)
	}
}
