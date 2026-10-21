package imapsmtp

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"bufio"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
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
	return seenServe(t, func(string, int) string { return search }, fetch, 0)
}

// seenServe is seenSearch answering the nth UID SEARCH, whose command line is
// cmd, with search(cmd, n), and each UID FETCH after delay.
func seenServe(t *testing.T, search func(cmd string, n int) string, fetch string, delay time.Duration) string {
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
		n := 0
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
			case cmd == "UID" && fetch == "NO":
				say(tag + " NO failed\r\n")
			case cmd == "UID":
				time.Sleep(delay)
				say(fetch + tag + " OK done\r\n")
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
	}, header(1, "a@x.test"), 0)
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err != nil || len(got) != 1 {
		t.Fatalf("headers %q, err %v; want the one still there", got, err)
	}
}

// A search or a batch the server stalls fails the call once it has run for
// the timeout.
func TestSeenTimesOutAStalledStep(t *testing.T) {
	stall := func(string, int) string { time.Sleep(3 * time.Second); return "* SEARCH 1 2\r\n" }
	for name, addr := range map[string]string{
		"search": seenServe(t, stall, header(1, "a@x.test")+header(2, "d@x.test"), 0),
		"batch":  seenServe(t, func(string, int) string { return "* SEARCH 1 2\r\n" }, header(1, "a@x.test")+header(2, "d@x.test"), 3*time.Second),
	} {
		start := time.Now()
		if _, err := seenFrom(hostileStore(t, addr, 300*time.Millisecond), "INBOX"); err == nil || time.Since(start) > 2*time.Second {
			t.Fatalf("%s: err %v after %v; want a failure at the timeout", name, err, time.Since(start))
		}
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
	}, header(1, "a@x.test"), 0)
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// Each batch gets a fresh timeout: batches that together take longer than
// one, each within it, pass.
func TestSeenRenewsTheTimeoutForEachBatch(t *testing.T) {
	search, fetch := seenUIDs(3 * seenBatch)
	addr := seenServe(t, func(string, int) string { return search }, fetch, 400*time.Millisecond)
	if got, err := seenFrom(hostileStore(t, addr, time.Second), "INBOX"); err != nil || len(got) != 3*seenBatch {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 3*seenBatch)
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
	if _, err := seenFrom(s, "INBOX"); err == nil {
		t.Fatal("a reply past one batch's budget passed")
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
