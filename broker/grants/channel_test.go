package grants

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-3, CH-10, CH-12, CH-13, ADP-9, ADP-11

// TestOwnerChannelEndToEnd runs the gate with the real owner channel on
// the modem simulator: a grant approved with a code-generator code and
// the local page, a send approved with its texted code, an auto-reply the
// owner undoes, and a pre-allowance paused by text.
// unpaced is owner state with the loosest pacing the owner can set (20
// texts an hour, approval and agent texts urgent), for tests about the
// gate rather than CH-15's pacing (W5-Dc-r1a).
func unpaced() *owner.MemStore {
	st := &owner.MemStore{}
	st.Save(owner.State{Pacing: owner.Pacing{PerHour: owner.MaxTextsPerHour, Urgent: []owner.Class{owner.ClassApproval, owner.ClassAgent}}})
	return st
}

func TestOwnerChannelEndToEnd(t *testing.T) {
	const ownerNum, boxNum = "+15550000001", "+15550000002"
	seed := []byte("synthetic-totp-seed-0001") // synthetic canary, not a credential
	r := newRig(t, func(c *Config) { c.Isolated = func(m string) bool { return m == "reply-1" } })
	carrier := modem.NewCarrier()
	carrier.SetClock(r.now)
	box, phone := carrier.Line(boxNum), carrier.Line(ownerNum)
	ch, err := owner.New(owner.Config{
		Owner: ownerNum, Modem: box, Engine: r.eng, Secrets: owner.Secrets{TOTPSeed: seed}, Store: unpaced(),
		Limits: owner.Limits{AmountLimit: 50000}, Location: time.UTC, Now: r.now,
		Decide: r.g.Decide, Narrow: r.g.Narrow,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.g.Attach(r.eng, ch)
	ctx := context.Background()
	text := func() string {
		t.Helper()
		select {
		case m := <-phone.Inbox():
			return m.Text
		case <-time.After(2 * time.Second):
			t.Fatal("no text to the owner")
		}
		return ""
	}
	say := func(msg string) string { return strings.Join(ch.Handle(ctx, ownerNum, msg), " | ") }
	idRE := regexp.MustCompile(`^([A-Z][0-9]{1,2}):`)

	// 1. A grant: asked on the local page only, where one
	// code-generator code approves and confirms it (Security Q1).
	r.submit(journal.Intent{ID: "local/g1", Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: specParams(mailGrant()), Executor: ExecutorName})
	r.g.Flush()
	req := text()
	if !strings.Contains(req, "grant \"connect mail, 3 acting ops") || !strings.Contains(req, "Wi-Fi page") || strings.Contains(req, "YES") {
		t.Fatalf("grant request %q", req)
	}
	id := idRE.FindStringSubmatch(req)[1]
	if got := say(fmt.Sprintf("YES %s %s", id, totp(seed, r.now()))); strings.HasPrefix(got, "Approved") {
		t.Fatalf("grant approved by text: %q", got)
	}
	r.advance(30 * time.Second)
	pageApprove(t, ch, id, totp(seed, r.now()))
	r.g.Wait()
	pageTexts(text, "Added G1", true)

	// 2. A low-risk send: the texted code from the request.
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	req = text()
	m := regexp.MustCompile(`Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6})`).FindStringSubmatch(req)
	if m == nil || !strings.Contains(req, "send invoice 1042 to sam@example.com, $120.00") {
		t.Fatalf("send request %q", req)
	}
	if got := say("YES " + m[1] + " " + m[2]); !strings.HasPrefix(got, "Approved") {
		t.Fatalf("send approval: %q", got)
	}
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("approved send: %s", st.State)
	}

	// 3. An auto-reply the owner undoes.
	r.grant2(ch, text, say, seed, Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 3, PerDay: 10, Reply: true}}, false)
	r.ver.set("thr-1", Verified{Item: owner.Item{Object: "reply", Recipient: "sam@example.com",
		Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
		Recipients: []string{"sam@example.com"}, Record: "thr-1", ThreadVerified: true})
	r.submit(journal.Intent{ID: "reply-1/r1", Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
		Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	alert := text()
	um := regexp.MustCompile(`UNDO ([A-Z][0-9]{1,2})`).FindStringSubmatch(alert)
	if um == nil {
		t.Fatalf("auto-reply alert %q", alert)
	}
	if got := say("UNDO " + um[1]); !strings.HasPrefix(got, "Cancelled") {
		t.Fatalf("undo: %q", got)
	}
	r.g.Wait()
	r.advance(15 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("reply-1/r1"); st.State != journal.Denied || r.exec.runs("reply-1/r1") != 0 {
		t.Fatalf("undone reply: %s", st.State)
	}

	// 4. PAUSE by text needs no code.
	if got := say("pause g2"); got != "Paused G2. Its actions now need your approval." {
		t.Fatalf("pause: %q", got)
	}
	if got := say("REVOKE G7"); got != "No grant G7." {
		t.Fatalf("revoke unknown: %q", got)
	}
}

// REQ: OP-3, OP-4, CH-10, CH-12, CH-13

// TestRestartReissuesThroughTheChannel (GR10) runs a restart with the real
// owner channel and its saved state: the boot text says the open request
// will be re-sent; its old code no longer works; each intent comes back in
// one text under its own request and code, with the original expiry and
// the time first asked; one code approves one intent only.
func TestRestartReissuesThroughTheChannel(t *testing.T) {
	const ownerNum, boxNum = "+15550000001", "+15550000002"
	seed := []byte("synthetic-totp-seed-0002") // synthetic canary, not a credential
	r := newRig(t, nil)
	carrier := modem.NewCarrier()
	carrier.SetClock(r.now)
	box, phone := carrier.Line(boxNum), carrier.Line(ownerNum)
	state := unpaced()
	var ch *owner.Channel
	open := func() {
		r.openWith(func() Owner {
			var err error
			ch, err = owner.New(owner.Config{
				Owner: ownerNum, Modem: box, Engine: r.eng, Secrets: owner.Secrets{TOTPSeed: seed}, Store: state,
				Limits: owner.Limits{AmountLimit: 50000}, Location: time.UTC, Now: r.now,
				Decide: r.g.Decide, Narrow: r.g.Narrow, Reissue: r.g.Reissue,
			})
			if err != nil {
				t.Fatal(err)
			}
			return ch
		})
		ch.Boot()
	}
	open()
	ctx := context.Background()
	text := func() string {
		t.Helper()
		select {
		case m := <-phone.Inbox():
			return m.Text
		case <-time.After(2 * time.Second):
			t.Fatal("no text to the owner")
		}
		return ""
	}
	say := func(msg string) string { return strings.Join(ch.Handle(ctx, ownerNum, msg), " | ") }
	r.grant2(ch, text, say, seed, mailGrant(), true)

	for _, rec := range []string{"inv-1", "inv-2"} {
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		r.effect("agent/"+rec, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
	}
	r.g.Flush()
	old := regexp.MustCompile(`Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6}) for all`).FindStringSubmatch(text())
	if old == nil {
		t.Fatal("no batch request")
	}

	r.advance(2 * time.Minute)
	open() // restart
	if boot := text(); !strings.Contains(boot, old[1]+" will be re-sent with new codes") {
		t.Fatalf("boot text %q", boot)
	}
	if got := say("YES " + old[1] + " " + old[2]); strings.HasPrefix(got, "Approved") {
		t.Fatalf("an old code worked: %q", got)
	}
	r.advance(time.Minute) // the batch goes quiet
	r.g.Tick()
	again := text()
	m := regexp.MustCompile(`([A-Z][0-9]{1,2}): send invoice .+?, asked 09:0[0-9], re-sent after restart\. Expires 09:1[0-9]\. Reply YES ([A-Z][0-9]{1,2}) ([0-9]{6})`).FindAllStringSubmatch(again, -1)
	if len(m) != 2 || m[0][3] == m[1][3] {
		t.Fatalf("re-sent text %q", again)
	}
	if got := say("YES " + m[1][1] + " " + m[0][3]); strings.HasPrefix(got, "Approved") {
		t.Fatalf("one intent's code approved another: %q", got)
	}
	for _, x := range m {
		if got := say("YES " + x[1] + " " + x[3]); !strings.HasPrefix(got, "Approved") {
			t.Fatalf("re-sent approval %s: %q", x[1], got)
		}
	}
	r.g.Wait()
	for _, id := range []string{"agent/inv-1", "agent/inv-2"} {
		if st := r.state(id); st.State != journal.Succeeded || r.exec.runs(id) != 1 {
			t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
		}
	}
}

// grant2 creates a grant through the real channel.
// note: the page's own note on it is texted now, not coalesced into a
// later one.
func (r *rig) grant2(ch *owner.Channel, text func() string, say func(string) string, seed []byte, s Spec, note bool) {
	r.t.Helper()
	id := fmt.Sprintf("local/grant/%d", len(r.eng.List()))
	r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: specParams(s), Executor: ExecutorName})
	r.g.Flush()
	req := text()
	rid := regexp.MustCompile(`^([A-Z][0-9]{1,2}):`).FindStringSubmatch(req)[1]
	// Codes work once per step: move to the next one.
	r.advance(30 * time.Second)
	pageApprove(r.t, ch, rid, totp(seed, r.now()))
	r.g.Wait()
	pageTexts(text, "Added G", note)
}

// pageTexts reads the texts a page approval of a grant sends, in either
// order: the grant's notice and, when note, the page's own note.
func pageTexts(text func() string, notice string, note bool) {
	gotNotice, gotNote := false, !note
	for !gotNotice || !gotNote {
		m := text()
		gotNotice = gotNotice || strings.Contains(m, notice)
		gotNote = gotNote || strings.Contains(m, "on my Wi-Fi page at")
	}
}

// pageApprove approves request id on the local page with code.
func pageApprove(t *testing.T, ch *owner.Channel, id, code string) {
	t.Helper()
	for _, rq := range ch.LocalRequests() {
		if rq.ID == id {
			if got, err := ch.LocalAnswer(id, rq.Sum, true, code); err != nil || !strings.HasPrefix(got, "Approved") {
				t.Fatalf("page approval: %q %v", got, err)
			}
			return
		}
	}
	t.Fatalf("%s is not on the page", id)
}

// totp is RFC 6238 (SHA-1, 30 s, 6 digits), as a code generator shows it.
func totp(seed []byte, at time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}
