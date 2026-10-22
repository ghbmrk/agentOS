package imapsmtp

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// seenServer is a raw IMAP server for Seen that takes one connection: it logs
// in, selects, answers a UID SEARCH with UIDs 1 and 2, and a UID FETCH with
// fetch ("NO" fails it).
func seenServer(t *testing.T, fetch string) string {
	return seenSearch(t, "* SEARCH 1 2\r\n", fetch)
}

// seenSearch is seenServer with the UID SEARCH's untagged answer ("NO" fails
// it).
func seenSearch(t *testing.T, search, fetch string) string {
	return seenServe(t, func(string, int) string { return search }, each(fetch), 0)
}

// each answers every UID FETCH alike.
func each(fetch string) func(int) string { return func(int) string { return fetch } }

// seenServe is seenSearch answering the nth UID SEARCH, whose command line is
// cmd, with search(cmd, n), and the nth UID FETCH with fetch(n) after delay.
func seenServe(t *testing.T, search func(cmd string, n int) string, fetch func(n int) string, delay time.Duration) string {
	t.Helper()
	l := listenLoopback(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		w := bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s); w.Flush() }
		say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
		r := bufio.NewReader(c)
		n, k := 0, 0
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			tag, cmd := f[0], strings.ToUpper(f[1])
			switch {
			case cmd == "LOGIN":
				say(tag + " OK done\r\n")
			case cmd == "SELECT" || cmd == "EXAMINE":
				say("* 2 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
			case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH"):
				if a := search(strings.ToUpper(line), n); a == "NO" {
					say(tag + " NO failed\r\n")
				} else {
					say(a + tag + " OK done\r\n")
				}
				n++
			case cmd == "UID":
				a := fetch(k)
				if k++; a == "NO" {
					say(tag + " NO failed\r\n")
					continue
				}
				time.Sleep(delay)
				say(a + tag + " OK done\r\n")
			case cmd == "LOGOUT":
				say("* BYE\r\n" + tag + " OK done\r\n")
			default:
				say(tag + " OK done\r\n")
			}
		}
	}()
	return l.Addr().String()
}

// seenFrom collects what Seen hands over.
func seenFrom(s *Store, folder string) ([][]byte, error) {
	var out [][]byte
	err := s.Seen(context.Background(), folder, func(h []byte, _ time.Time) error {
		out = append(out, h)
		return nil
	})
	return out, err
}

func header(uid int, from string) string {
	h := "From: " + from + "\r\n\r\n"
	return "* " + strconv.Itoa(uid) + " FETCH (UID " + strconv.Itoa(uid) + " BODY[HEADER.FIELDS (FROM MESSAGE-ID)]<0> {" + strconv.Itoa(len(h)) + "}\r\n" + h + ")\r\n"
}

// One header per UID the search found: a repeated or invented response adds
// nothing.
func TestSeenKeepsOneHeaderPerSearchedUID(t *testing.T) {
	addr := seenServer(t, header(1, "a@x.test")+header(1, "b@x.test")+header(9, "c@x.test")+header(2, "d@x.test"))
	got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.Contains(string(got[0]), "a@x.test") || !strings.Contains(string(got[1]), "d@x.test") {
		t.Fatalf("headers %q", got)
	}
}

// A fetch the server fails fails the call: the headers it did not send would
// make their senders look never opened.
func TestSeenFailsWhenTheFetchFails(t *testing.T) {
	addr := seenServer(t, "NO")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A search the server fails fails the call: it is not a folder with no read
// mail.
func TestSeenFailsWhenTheSearchFails(t *testing.T) {
	addr := seenSearch(t, "NO", "")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A FETCH that answers OK without a header for a searched message still
// there and read fails the call, and so does a From header longer than
// headMax, which the server cut or would have to: either leaves a sender out.
// A long header's error names its folder, and says when the server gave no
// arrival.
func TestSeenFailsWhenAHeaderIsMissingOrCut(t *testing.T) {
	long := "a@x.test (" + strings.Repeat("x", headMax) + ")"
	for name, c := range map[string]struct {
		fetch string
		want  error
	}{
		"missing": {header(1, "a@x.test"), ErrUnanswered},
		"cut":     {header(1, long) + header(2, "d@x.test"), ErrLongHeader},
	} {
		addr := seenServer(t, c.fetch)
		if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); !errors.Is(err, c.want) || c.want == ErrLongHeader && !strings.Contains(err.Error(), "the mail in INBOX that arrived at an unknown time") {
			t.Fatalf("%s: headers %q, err %v; want %v", name, got, err, c.want)
		}
	}
}

// A searched mail that did not answer because the owner deleted it or marked
// it unread since is let go: searched again for its UID and \Seen, it is not
// there. Only the UIDs that did not answer count, whatever else the search
// names; a second search that asks for anything else finds it still there.
func TestSeenLetsGoOfAMailGoneSinceTheSearch(t *testing.T) {
	addr := seenServe(t, func(cmd string, n int) string {
		if n > 0 && strings.Contains(cmd, " SEEN") && strings.Contains(cmd, "UID 2 ") {
			return "* SEARCH 9\r\n"
		}
		return "* SEARCH 1 2\r\n"
	}, each(header(1, "a@x.test")), 0)
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err != nil || len(got) != 1 {
		t.Fatalf("headers %q, err %v; want the one still there", got, err)
	}
}

// A search or a batch the server stalls fails the call with ErrTimeout once
// it has run for the timeout, not long after.
func TestSeenTimesOutAStalledStep(t *testing.T) {
	stall := func(string, int) string { time.Sleep(5 * time.Second); return "* SEARCH 1 2\r\n" }
	for name, addr := range map[string]string{
		"search": seenServe(t, stall, each(header(1, "a@x.test")+header(2, "d@x.test")), 0),
		"batch":  seenServe(t, func(string, int) string { return "* SEARCH 1 2\r\n" }, each(header(1, "a@x.test")+header(2, "d@x.test")), 5*time.Second),
	} {
		start := time.Now()
		if _, err := seenFrom(hostileStore(t, addr, 500*time.Millisecond), "INBOX"); !errors.Is(err, ErrTimeout) || time.Since(start) > 1400*time.Millisecond {
			t.Fatalf("%s: err %v after %v; want ErrTimeout at the timeout", name, err, time.Since(start))
		}
	}
}

// Every session cut off at its timeout fails with ErrTimeout, a one-step
// session as much as Seen's, whichever runs out first: the store's timeout,
// the caller's deadline, or that deadline passing before the dial.
func TestASessionCutOffAtItsTimeoutSaysSo(t *testing.T) {
	stall := func(string, int) string { time.Sleep(5 * time.Second); return "* SEARCH 1\r\n" }
	for name, c := range map[string]struct {
		timeout, deadline time.Duration
	}{
		"timeout":  {500 * time.Millisecond, time.Minute},
		"deadline": {time.Minute, 500 * time.Millisecond},
		"dial":     {time.Minute, -time.Second},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), c.deadline)
		_, _, err := hostileStore(t, seenServe(t, stall, each(""), 0), c.timeout).UIDs(ctx, "INBOX")
		cancel()
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("%s: err %v, want ErrTimeout", name, err)
		}
	}
}

// guardedStore is a TLS store for mail.example whose dials go through the
// address policy to connect.
func guardedStore(t *testing.T, timeout time.Duration, connect func(ctx context.Context, network string) (net.Conn, error)) *Store {
	t.Helper()
	s, err := New(Config{
		IMAP: "mail.example:993", SMTP: "mail.example:465", IMAPSec: TLS, SMTPSec: TLS,
		Timeout:    timeout,
		Credential: func(context.Context) (Login, error) { return Login{}, nil },
		From:       "owner@example.test",
		Guard: netguard.New(netguard.Config{
			Resolver: answers{"8.8.8.8"},
			Connect:  func(ctx context.Context, network, _ string) (net.Conn, error) { return connect(ctx, network) },
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mailCalls are a session of steps, a one-step session and a submission.
func mailCalls(s *Store) map[string]func() error {
	return map[string]func() error{
		"Seen":   func() error { _, err := seenFrom(s, "INBOX"); return err },
		"UIDs":   func() error { _, _, err := s.UIDs(context.Background(), "INBOX"); return err },
		"Submit": func() error { return s.Submit(context.Background(), []string{"a@example.test"}, []byte("x")) },
	}
}

// A server that takes the connection and never answers the handshake is
// cut off at the timeout counted from the dial, and says so: the dial here
// takes half the timeout, so a cut-off counted from the connection ends a
// quarter of the timeout past the bound, and one that does not mark the
// session late says what the closed connection reports.
func TestAStalledHandshakeTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	const timeout = time.Second
	s := guardedStore(t, timeout, func(ctx context.Context, network string) (net.Conn, error) {
		time.Sleep(timeout / 2)
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	})
	for name, call := range mailCalls(s) {
		start := time.Now()
		if err := call(); !errors.Is(err, ErrTimeout) || time.Since(start) > timeout*5/4 {
			t.Fatalf("%s: err %v after %v, want ErrTimeout within %v", name, err, time.Since(start), timeout*5/4)
		}
	}
}

// A dial that fails, refused or never answered until the timeout, says the
// server could not be reached, not that it stopped answering; a dial the
// address policy refuses says so instead (TestMailDialsRefusePrivateAndReboundAnswers).
func TestADialThatFailsSaysTheServerWasNotReached(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	for name, connect := range map[string]func(ctx context.Context, network string) (net.Conn, error){
		"refused": func(ctx context.Context, network string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, closed)
		},
		"silent": func(ctx context.Context, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	} {
		for call, f := range mailCalls(guardedStore(t, 500*time.Millisecond, connect)) {
			if err := f(); !errors.Is(err, ErrUnreachable) || errors.Is(err, ErrTimeout) {
				t.Fatalf("%s %s: err %v, want ErrUnreachable", name, call, err)
			}
		}
	}
}

// A dial the caller's deadline ends, passed before it or during it, says
// the timeout ran out, not that the server was not reached, reading or
// sending.
func TestADialTheCallersDeadlineEndsTimesOut(t *testing.T) {
	s := guardedStore(t, 5*time.Second, func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	for name, d := range map[string]time.Duration{"before": -time.Second, "during": 200 * time.Millisecond} {
		for call, f := range map[string]func(context.Context) error{
			"UIDs":   func(ctx context.Context) error { _, _, err := s.UIDs(ctx, "INBOX"); return err },
			"Submit": func(ctx context.Context) error { return s.Submit(ctx, []string{"a@example.test"}, []byte("x")) },
		} {
			ctx, cancel := context.WithTimeout(context.Background(), d)
			err := f(ctx)
			cancel()
			if !errors.Is(err, ErrTimeout) {
				t.Fatalf("%s %s: err %v, want ErrTimeout", name, call, err)
			}
		}
	}
}

// A caller that stops a dial is told so, not that the server was not
// reached.
func TestADialTheCallerStopsIsNotUnreachable(t *testing.T) {
	s := guardedStore(t, 5*time.Second, func(ctx context.Context, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if _, _, err := s.UIDs(ctx, "INBOX"); !errors.Is(err, context.Canceled) || errors.Is(err, ErrUnreachable) {
		t.Fatalf("err %v, want the caller's cancel", err)
	}
}

// A submission server that takes the connection and never greets is cut
// off at the timeout and says so.
func TestAStalledSubmissionTimesOut(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	err = hostileStore(t, ln.Addr().String(), 500*time.Millisecond).Submit(context.Background(), []string{"a@example.test"}, []byte("x"))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err %v, want ErrTimeout", err)
	}
}

// A second search the server fails fails the call: the rest of the folder
// is unread.
func TestSeenFailsWhenTheSecondSearchFails(t *testing.T) {
	addr := seenServe(t, func(_ string, n int) string {
		if n > 0 {
			return "NO"
		}
		return "* SEARCH 1 2\r\n"
	}, each(header(1, "a@x.test")), 0)
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// subjectAnswer is a UID FETCH answer of a Subject section for uid.
func subjectAnswer(uid int, h string) string {
	return "* " + strconv.Itoa(uid) + " FETCH (UID " + strconv.Itoa(uid) + " BODY[HEADER.FIELDS (SUBJECT)]<0> {" + strconv.Itoa(len(h)) + "}\r\n" + h + ")\r\n"
}

// A header too long names its mail by the Subject the server sends for that
// UID first, unfolded, decoded, and with control and bidi characters taken
// out, so the sender cannot write a line of the owner's status; a section
// that is not a Subject names nothing.
func TestSeenNamesALongHeaderBySubject(t *testing.T) {
	long := header(1, "a@x.test ("+strings.Repeat("x", headMax)+")")
	for answer, want := range map[string]string{
		subjectAnswer(2, "Subject: wrong\r\n\r\n") + subjectAnswer(1, "Subject: first\r\n part\r\n\r\n") + subjectAnswer(1, "Subject: second\r\n\r\n"): "first part",
		subjectAnswer(1, "Subject: =?UTF-8?Q?ok=0AOPENED_nothing=1B[2J=E2=80=AE?=\r\n\r\n"):                                                            "ok OPENED nothing [2J",
		subjectAnswer(1, "X-Subject: no\r\n\r\n"): "",
		subjectAnswer(1, "Subject: =?UTF-8?Q?Gro=C3=9Fer?= =?UTF-8?Q?"+strings.Repeat("x", subjectMax)+"?=\r\n\r\n"):       "Großer…",
		subjectAnswer(1, "Subject: =?UTF-8?Q?Gro=C3=9Fer?= =?UTF-8?Q?=C3=A9"+strings.Repeat("x", subjectMax)+"?=\r\n\r\n"): "Großer…",
		subjectAnswer(1, "Subject: =?UTF-8?Q?Gro=C3=9Fer?= "+strings.Repeat("x", subjectMax)+"\r\n\r\n"):                   "Großer " + strings.Repeat("x", subjectMax-len("Subject: =?UTF-8?Q?Gro=C3=9Fer?= ")) + "…",
		subjectAnswer(1, "Subject: a =? b\r\n\r\n"):                                                                        "a =? b",
		// cut between an encoded word's closing "?" and "="
		subjectAnswer(1, cutAt("Subject: =?UTF-8?Q?Gro=C3=9Fer?= =?UTF-8?Q?", "?=\r\n\r\n")): "Großer…",
	} {
		addr := seenServe(t, func(string, int) string { return "* SEARCH 1\r\n" }, func(n int) string {
			if n == 0 {
				return long
			}
			return answer
		}, 0)
		_, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
		var lh *LongHeaderError
		if !errors.As(err, &lh) || lh.Subject != want {
			t.Fatalf("err %v (%+v); want a LongHeaderError with subject %q", err, lh, want)
		}
	}
}

// A long header found before the timeout stands when the subject's read is
// cut off: the error is what the server sent, not ErrTimeout.
func TestALongHeaderStandsWhenItsSubjectTimesOut(t *testing.T) {
	long := header(1, "a@x.test ("+strings.Repeat("x", headMax)+")")
	addr := seenServe(t, func(string, int) string { return "* SEARCH 1\r\n" }, func(n int) string {
		if n > 0 {
			time.Sleep(5 * time.Second)
		}
		return long
	}, 0)
	_, err := seenFrom(hostileStore(t, addr, 500*time.Millisecond), "INBOX")
	var lh *LongHeaderError
	if !errors.As(err, &lh) || errors.Is(err, ErrTimeout) || lh.Subject != "" {
		t.Fatalf("err %v; want the LongHeaderError, with no subject", err)
	}
}

// Each batch gets a fresh timeout: batches that together take longer than
// one, each within it, pass. Three delays just past a third of the timeout
// pass it for certain, and leave each batch about two thirds of it, many
// times what a batch of seenBatch headers costs under -race on a busy runner.
func TestSeenRenewsTheTimeoutForEachBatch(t *testing.T) {
	const timeout, delay = 2 * time.Second, 700 * time.Millisecond
	search, fetch := seenUIDs(3 * seenBatch)
	addr := seenServe(t, func(string, int) string { return search }, each(fetch), delay)
	start := time.Now()
	if got, err := seenFrom(hostileStore(t, addr, timeout), "INBOX"); err != nil || len(got) != 3*seenBatch {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 3*seenBatch)
	}
	if took := time.Since(start); took <= timeout {
		t.Fatalf("the batches took %v, within one timeout of %v: nothing was renewed", took, timeout)
	}
}

// Every batch of seenBatch UIDs is fetched in the one session the search ran
// in, signed in once: the server accepts a single connection.
func TestSeenSignsInOnceForEveryBatch(t *testing.T) {
	search, fetch := seenUIDs(2*seenBatch + 1)
	addr := seenSearch(t, search, fetch)
	got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
	if err != nil || len(got) != 2*seenBatch+1 {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 2*seenBatch+1)
	}
}

// Each batch gets a fresh read budget: replies that together pass one
// batch's budget, each within it, pass.
func TestSeenRenewsTheBudgetForEachBatch(t *testing.T) {
	search, fetch := seenUIDs(3 * seenBatch)
	var b strings.Builder
	b.WriteString(fetch)
	for pad := header(1<<30, strings.Repeat("x", headMax-64)+"@x.test"); b.Len() < (seenBase+seenBatch*(headMax+fetchFrame))*2/3; {
		b.WriteString(pad)
	}
	s := hostileStore(t, seenSearch(t, search, b.String()), 5*time.Second)
	s.replyBase = 64 << 10 // a batch must not fit in what sign-in left
	if got, err := seenFrom(s, "INBOX"); err != nil || len(got) != 3*seenBatch {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 3*seenBatch)
	}
}

// The batch, not the search, sizes the read budget (M21): with more UIDs
// found than one batch fetches, a reply just past one batch's budget, padded
// with invented messages, still fails the call.
func TestSeenBudgetsTheBatchNotTheSearch(t *testing.T) {
	search, fetch := seenUIDs(4 * seenBatch)
	var b strings.Builder
	b.WriteString(fetch)
	for pad := header(1<<30, strings.Repeat("x", headMax-64)+"@x.test"); b.Len() < seenBase+seenBatch*(headMax+fetchFrame); {
		b.WriteString(pad)
	}
	s := hostileStore(t, seenSearch(t, search, b.String()), 5*time.Second)
	if _, err := seenFrom(s, "INBOX"); !errors.Is(err, ErrReplyTooLarge) {
		t.Fatalf("a reply past one batch's budget: err %v, want ErrReplyTooLarge", err)
	}
}

// seenUIDs is a search answering UIDs 1 to n and a fetch answering each.
func seenUIDs(n int) (search, fetch string) {
	var sb, fb strings.Builder
	sb.WriteString("* SEARCH")
	for u := 1; u <= n; u++ {
		sb.WriteString(" " + strconv.Itoa(u))
		fb.WriteString(header(u, "a@x.test"))
	}
	return sb.String() + "\r\n", fb.String()
}

// An error from each stops the call with that error.
func TestSeenStopsOnTheCallersError(t *testing.T) {
	stop := errors.New("stop")
	addr := seenServer(t, header(1, "a@x.test")+header(2, "d@x.test"))
	n := 0
	err := hostileStore(t, addr, 5*time.Second).Seen(context.Background(), "INBOX", func([]byte, time.Time) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err %v after %d headers, want stop after 1", err, n)
	}
}

// cutAt is a Subject field of head, x's, and tail, whose first subjectMax
// bytes end at tail's first byte.
func cutAt(head, tail string) string {
	return head + strings.Repeat("x", subjectMax-len(head)-1) + tail
}
