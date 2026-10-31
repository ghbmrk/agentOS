package radio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: NET-6, NET-2

// door is a lock on the BLE stack whose one characteristic takes its
// commands.
var door = Device{Name: "door", Stack: StackBLE, Chars: []string{"cmd"}}

// actuator is the action.Actuator slice l wires over the host: every act
// goes through Send with the book's context. Each write carries the tap's
// number, so the test can tell which relock it must precede.
type actuator struct {
	h   *Host
	tap *atomic.Int64
}

func (a actuator) Act(ctx context.Context, device string, act action.Act, _ string) error {
	_, err := a.h.Send(ctx, Request{Op: OpWrite, Device: device, Char: "cmd", Data: fmt.Appendf(nil, "%s %d", act, a.tap.Load())})
	return err
}

// NET-6 ("the lock relocks automatically") on the real host: an unlock
// whose book timed out never reaches the lock after the relock the channel
// sends once Redeem has returned, however short the bound, because Send
// checks the book's context in the same step as the write, under the
// link's write lock. Catches an adapter over Call, whose queued unlock
// goes out after the relock (#4138).
func TestTimedOutUnlockNeverFollowsRelockOnHost(t *testing.T) {
	owner := newOwner(t)
	doc := policy.Document{Version: 1, Devices: []policy.Device{{ID: "door", Network: policy.NetDevices, Class: policy.ClassLock}}}
	for _, bound := range []time.Duration{time.Nanosecond, time.Microsecond} {
		h, err := NewHost(Config{Devices: []Device{door}, Notify: func(Notification) {}, Log: func(string) {}, Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		rec := newRecorder(t, StackBLE)
		if err := h.Attach(StackBLE, rec.host.(Conn)); err != nil {
			t.Fatal(err)
		}
		var tap atomic.Int64
		b, err := action.NewBook(owner.pub, actuator{h, &tap}, bound)
		if err != nil {
			t.Fatal(err)
		}
		timeouts := 0
		for i := range int64(500) {
			tap.Store(i)
			c, err := b.Issue(doc, "door", action.Unlock, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.Redeem(doc, c.ID, owner.sign(t, c.Msg), 1); errors.Is(err, action.ErrTimeout) {
				timeouts++
			}
			if _, err := h.Call(Request{Op: OpWrite, Device: "door", Char: "cmd", Data: fmt.Appendf(nil, "lock %d", i)}); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(50 * time.Millisecond) // let a stray unlock try to land
		relocked := map[string]bool{}
		for _, w := range writes(rec) {
			act, n, _ := strings.Cut(w, " ")
			if act == "lock" {
				relocked[n] = true
			} else if relocked[n] {
				t.Fatalf("bound %v: tap %s's unlock landed after its relock", bound, n)
			}
		}
		if timeouts == 0 {
			t.Fatalf("bound %v: no run timed out, the test proves nothing", bound)
		}
	}
}

// TestSendRefusesAnEndedContext: once the caller's context has ended,
// Send writes nothing and leaves no request outstanding, so the stack
// never sees it and the link stays.
func TestSendRefusesAnEndedContext(t *testing.T) {
	var logs []string
	h, err := NewHost(Config{Devices: []Device{door}, Notify: func(Notification) {}, Log: func(s string) { logs = append(logs, s) }, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder(t, StackBLE)
	h.Attach(StackBLE, rec.host.(Conn))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Send(ctx, Request{Op: OpWrite, Device: "door", Char: "cmd", Data: []byte("unlock")}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ended context: %v", err)
	}
	if _, err := h.Call(Request{Op: OpWrite, Device: "door", Char: "cmd", Data: []byte("lock")}); err != nil {
		t.Fatalf("the link did not stay: %v", err)
	}
	if got := writes(rec); !slices.Equal(got, []string{"lock"}) {
		t.Fatalf("reached the stack: %v", got)
	}
	h.mu.Lock()
	n := len(h.links[StackBLE].pending) + len(h.links[StackBLE].expired)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d requests left outstanding", n)
	}
}

// writes is each write's data that reached the stand-in stack, in order.
func writes(r *recorder) []string {
	var out []string
	for _, q := range r.requests() {
		out = append(out, string(q.Data))
	}
	return out
}

// owner is a passkey on the enforcer's name, signing as a phone would.
type owner struct {
	priv *ecdsa.PrivateKey
	pub  key.PublicKey
}

const rpID = "enforcer.home.arpa"

func newOwner(t *testing.T) *owner {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, _ := priv.PublicKey.Bytes()
	pub, err := key.ES256(rpID, point)
	if err != nil {
		t.Fatal(err)
	}
	return &owner{priv: priv, pub: pub}
}

// sign is the owner's assertion over msg, in key.AssertionSig's form.
func (o *owner) sign(t *testing.T, msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]), "origin": "https://" + rpID, "crossOrigin": false})
	rp := sha256.Sum256([]byte(rpID))
	ad := append(rp[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(slices.Clone(ad), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, o.priv, m[:])
	if err != nil {
		t.Fatal(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
