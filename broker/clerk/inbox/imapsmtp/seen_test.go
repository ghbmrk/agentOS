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

// seenServer is a raw IMAP server for Seen: each connection logs in and
// selects with the next UID validity of validities, a UID SEARCH answers
// UIDs 1 and 2, and a UID FETCH answers fetch ("NO" fails it).
func seenServer(t *testing.T, validities []int, fetch string) string {
	return seenSearch(t, validities, "* SEARCH 1 2\r\n", fetch)
}

// seenSearch is seenServer with the UID SEARCH's untagged answer ("NO" fails
// it).
func seenSearch(t *testing.T, validities []int, search, fetch string) string {
	return seenSearches(t, validities, []string{search}, fetch)
}

// seenSearches is seenSearch answering a connection's nth UID SEARCH with
// searches[n], or the last of them.
func seenSearches(t *testing.T, validities []int, searches []string, fetch string) string {
	t.Helper()
	l := listenLoopback(t)
	go func() {
		for _, v := range validities {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			w := bufio.NewWriter(c)
			say := func(s string) { w.WriteString(s); w.Flush() }
			say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
			r := bufio.NewReader(c)
			n := 0
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					break
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
					say("* 2 EXISTS\r\n* OK [UIDVALIDITY " + strconv.Itoa(v) + "] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
				case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH"):
					search := searches[min(n, len(searches)-1)]
					if n++; search == "NO" {
						say(tag + " NO failed\r\n")
					} else {
						say(search + tag + " OK done\r\n")
					}
				case cmd == "UID" && fetch == "NO":
					say(tag + " NO failed\r\n")
				case cmd == "UID":
					say(fetch + tag + " OK done\r\n")
				case cmd == "LOGOUT":
					say("* BYE\r\n" + tag + " OK done\r\n")
				default:
					say(tag + " OK done\r\n")
				}
			}
			c.Close()
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
	addr := seenServer(t, []int{7}, header(1, "a@x.test")+header(1, "b@x.test")+header(9, "c@x.test")+header(2, "d@x.test"))
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
	addr := seenServer(t, []int{7}, "NO")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A search the server fails fails the call: it is not a folder with no read
// mail.
func TestSeenFailsWhenTheSearchFails(t *testing.T) {
	addr := seenSearch(t, []int{7}, "NO", "")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A FETCH that answers OK without a header for a searched message still
// there and read fails the call, and so does a From header longer than
// headMax, which the server cut or would have to: either leaves a sender out.
// A long header's error names its folder.
func TestSeenFailsWhenAHeaderIsMissingOrCut(t *testing.T) {
	long := "a@x.test (" + strings.Repeat("x", headMax) + ")"
	for name, c := range map[string]struct {
		fetch string
		want  error
	}{
		"missing": {header(1, "a@x.test"), ErrUnanswered},
		"cut":     {header(1, long) + header(2, "d@x.test"), ErrLongHeader},
	} {
		addr := seenServer(t, []int{7}, c.fetch)
		if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); !errors.Is(err, c.want) || !strings.Contains(err.Error(), "INBOX") && c.want == ErrLongHeader {
			t.Fatalf("%s: headers %q, err %v; want %v", name, got, err, c.want)
		}
	}
}

// A searched mail that did not answer because the owner deleted it or marked
// it unread since is let go: searched again, it is not there. Only the UIDs
// that did not answer count, whatever else the search names.
func TestSeenLetsGoOfAMailGoneSinceTheSearch(t *testing.T) {
	addr := seenSearches(t, []int{7}, []string{"* SEARCH 1 2\r\n", "* SEARCH 1 9\r\n"}, header(1, "a@x.test"))
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err != nil || len(got) != 1 {
		t.Fatalf("headers %q, err %v; want the one still there", got, err)
	}
}

// Every batch of seenBatch UIDs is fetched in the one session the search ran
// in, signed in once: the server accepts a single connection.
func TestSeenSignsInOnceForEveryBatch(t *testing.T) {
	search, fetch := seenUIDs(2*seenBatch + 1)
	addr := seenSearch(t, []int{7}, search, fetch)
	got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
	if err != nil || len(got) != 2*seenBatch+1 {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 2*seenBatch+1)
	}
}

// Each batch gets a fresh read budget: replies that together pass one
// batch's budget, each within it, pass.
func TestSeenRenewsTheBudgetForEachBatch(t *testing.T) {
	const base = 64 << 10
	search, fetch := seenUIDs(3 * seenBatch)
	var b strings.Builder
	b.WriteString(fetch)
	for pad := header(1<<30, strings.Repeat("x", headMax-64)+"@x.test"); b.Len() < (base+seenBatch*(headMax+fetchFrame))*2/3; {
		b.WriteString(pad)
	}
	s := hostileStore(t, seenSearch(t, []int{7}, search, b.String()), 5*time.Second)
	s.replyBase = base
	if got, err := seenFrom(s, "INBOX"); err != nil || len(got) != 3*seenBatch {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, 3*seenBatch)
	}
}

// The batch, not the search, sizes the read budget (M21): with more UIDs
// found than one batch fetches, a reply just past one batch's budget, padded
// with invented messages, still fails the call.
func TestSeenBudgetsTheBatchNotTheSearch(t *testing.T) {
	const base = 64 << 10
	search, fetch := seenUIDs(4 * seenBatch)
	var b strings.Builder
	b.WriteString(fetch)
	for pad := header(1<<30, strings.Repeat("x", headMax-64)+"@x.test"); b.Len() < base+seenBatch*(headMax+fetchFrame); {
		b.WriteString(pad)
	}
	s := hostileStore(t, seenSearch(t, []int{7}, search, b.String()), 5*time.Second)
	s.replyBase = base
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
	addr := seenServer(t, []int{7}, header(1, "a@x.test")+header(2, "d@x.test"))
	n := 0
	err := hostileStore(t, addr, 5*time.Second).Seen(context.Background(), "INBOX", func([]byte, time.Time) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err %v after %d headers, want stop after 1", err, n)
	}
}
