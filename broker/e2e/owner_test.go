package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-1, CH-14, CH-19, REV-5, ARC-6
//
// TestARC6OwnerChatReachesTheGuestAndBack: the owner texts the box; the
// owner channel (P1-5) checks the code and hands the chat to the agent's
// machine through its guest inbox (ARC-6 (c)), raising its label (REV-5);
// the guest's answer goes back through the channel's CH-19 filter.

// totp is the owner's phone authenticator (RFC 6238, SHA-1, 30 s, 6 digits).
func totp(seed []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// seedVerifier stands in for the vault process's verify operation.
type seedVerifier struct {
	seed []byte
	last atomic.Int64
}

func (v *seedVerifier) VerifyTOTP(code string, after int64, _ bool, _ ...owner.CheckerAct) (int64, bool, error) {
	step, ok := owner.MatchTOTP(v.seed, code, time.Now(), max(after, v.last.Load()))
	if ok {
		v.last.Store(step)
	}
	return step, ok, nil
}

// lateAgent lets the daemon take an Agent before the plane exists.
type lateAgent struct {
	a atomic.Pointer[guest.OwnerAgent]
}

func (l *lateAgent) Deliver(ctx context.Context, text string, public bool) error {
	a := l.a.Load()
	if a == nil {
		return fmt.Errorf("no agent")
	}
	return a.Deliver(ctx, text, public)
}

func recv(t *testing.T, l *modem.Line) string {
	t.Helper()
	select {
	case m := <-l.Inbox():
		return m.Text
	case <-time.After(5 * time.Second):
		t.Fatal("no text arrived")
		return ""
	}
}

func TestARC6OwnerChatReachesTheGuestAndBack(t *testing.T) {
	dir, err := os.MkdirTemp("", "oc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) }) // after checkJournal, which reads the journal here
	carrier := modem.NewCarrier()
	box, phone := carrier.Line("+15550000100"), carrier.Line(ownerNumber)
	seed := []byte("synthetic-totp-seed-for-tests-01")
	agent := &lateAgent{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNumber, ModemUID: os.Getuid(),
		Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		// The seed stays with the vault process, which checks codes for
		// the channel (egress K7); agentosd holds none.
		OwnerState: filepath.Join(dir, "owner.json"), OwnerVerifier: &seedVerifier{seed: seed},
		Modem: box, Agent: agent,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkJournal(t, d.Engine())
	defer func() { cancel(); d.Wait() }()
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(dir, "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	ms := &machines{private: map[string]bool{}}
	plane, err := guest.New(guest.Config{
		Dir: filepath.Join(dir, "run", "guests"), Machines: ms, Meter: mtr,
		OwnerReply: func(_ string, rep guest.Reply) { d.Owner().Notify(rep.Text) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	agent.a.Store(&guest.OwnerAgent{Plane: plane, Machine: "agent"})
	b := &broker{plane: plane}

	defer func() {
		for _, m := range carrier.Log() {
			t.Logf("%s -> %s: %q", m.From, m.To, m.Text)
		}
	}()
	// The agent's machine has open services before the owner texts, as
	// it does once the machine runs. Without them the owner's message is
	// refused with "Your agent is not running" and never queued (#5425).
	if _, err := plane.Open("agent"); err != nil {
		t.Fatal(err)
	}
	// The machine starts public, so the label check below fails unless
	// the owner's message raised it (REV-5).
	if l := ms.label("agent"); l != "public" {
		t.Fatalf("agent starts %s, want public", l)
	}
	// The session opens on the page (CH-14, D-311); task chat then goes
	// by text. A code in unlocked chat is stripped (owner's own tests).
	code := totp(seed, time.Now())
	if _, _, err := d.Owner().LocalSignIn(code); err != nil {
		t.Fatalf("page sign-in: %v", err)
	}
	phone.Send(box.Number(), "plan my week")
	// Each /owner/next is held open until a message arrives (up to the
	// plane's poll wait), so this loops only on a 204 or an error.
	const ownerChatWait = 60 * time.Second
	var msg struct{ ID, Text string }
	var st int
	var body string
	for deadline := time.Now().Add(ownerChatWait); msg.ID == "" && time.Now().Before(deadline); {
		if st, body = guestCall(t, b, "agent", "GET", "/owner/next", ""); st == 200 {
			json.Unmarshal([]byte(body), &msg)
		} else {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !strings.Contains(msg.Text, "plan my week") || strings.Contains(msg.Text, code) {
		t.Fatalf("guest got %q (last /owner/next: %d %q)", msg.Text, st, body)
	}
	if ms.label("agent") != "private" {
		t.Fatal("owner chat reached a machine still labelled public")
	}
	reply := func(text string) {
		b, _ := json.Marshal(map[string]string{"id": msg.ID, "text": text})
		if st, body := guestCall(t, &broker{plane: plane}, "agent", "POST", "/owner/reply", string(b)); st != 204 {
			t.Fatalf("reply: %d %s", st, body)
		}
	}
	// The page sign-in's alert races the guest's answers; skip it.
	next := func() string {
		for {
			got := recv(t, phone)
			if strings.Contains(got, "482913") {
				t.Fatalf("a secret-shaped guest reply went out: %q", got)
			}
			if !strings.Contains(got, "signed in on my Wi-Fi") {
				return got
			}
		}
	}
	reply("Your verification code is 482913, and the plan is ready.")
	if got := next(); !strings.Contains(got, "held back") {
		t.Fatalf("owner got %q, want the held-back pointer", got)
	}
	if _, err := plane.DeliverOwner("agent", "second", false); err != nil {
		t.Fatal(err)
	}
	if st, body := guestCall(t, b, "agent", "GET", "/owner/next", ""); st == 200 {
		json.Unmarshal([]byte(body), &msg)
	}
	reply("Monday: dentist. Tuesday: free.")
	if got := next(); !strings.Contains(got, "dentist") {
		t.Fatalf("owner got %q", got)
	}
}
