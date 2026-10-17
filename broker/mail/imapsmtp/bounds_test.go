package imapsmtp

// REQ: CRED-1, CRED-8

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
)

// flood is a raw IMAP server that logs in, selects any folder with UID
// validity 7 and answers a UID FETCH with prefix and then chunk, over
// and over, until the client stops reading. It stands in for a hostile
// mail host that never ends a reply (SR3-mail-k18b). The number of bytes
// it wrote is sent on the returned channel when the connection ends.
func flood(t testing.TB, prefix, chunk string) (string, <-chan int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	wrote := make(chan int64, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		w := bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s); w.Flush() }
		say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				wrote <- 0
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
				say("* 1 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
			case cmd == "UID":
				n, err := c.Write([]byte(prefix))
				total := int64(n)
				for err == nil {
					n, err = c.Write([]byte(chunk))
					total += int64(n)
				}
				wrote <- total
				return
			default:
				say(tag + " BAD unknown\r\n")
			}
		}
	}()
	return l.Addr().String(), wrote
}

// TestHostileReplyIsBounded (SR3-mail-k18b): a reply that never ends,
// whatever shape it takes, costs one call and a bounded amount of the
// vault's memory, not the process. Each case would otherwise be read
// until the store's timeout, into memory that grows with it; a declared
// 4 GB literal was allocated whole before a byte of it arrived.
func TestHostileReplyIsBounded(t *testing.T) {
	big := strings.Repeat("x", 64<<10)
	msg := "* 1 FETCH (UID 1 BODY[] {1024}\r\n" + strings.Repeat("y", 1024) + ")\r\n"
	many := func(field string) string { return strings.Repeat(field, (64<<10)/len(field)) }
	list := "* 1 FETCH (UID 1 X ("
	for _, c := range []struct{ name, prefix, chunk string }{
		{"declared 4 GB literal", "* 1 FETCH (UID 1 BODY[] {4000000000}\r\n", big},
		{"endless atom", "* 1 FETCH (UID 1 FLAGS (", big},
		{"endless quoted string", "* 1 FETCH (UID 1 BODY[] \"", big},
		{"endless status text", "* OK ", big},
		{"endless FETCH responses", "", strings.Repeat(msg, 32)},
		// One response of many tiny fields keeps every field live until
		// the response ends, so these are the worst cases per byte read.
		{"many atoms", list, many("a ")},
		{"many empty lists", list, many("() ")},
		{"many NILs", list, many("NIL ")},
		{"many empty literals", list, many("{0}\r\n ")},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, wrote := flood(t, c.prefix, c.chunk)
			s := hostileStore(t, addr, 8*time.Second)
			s.cfg.MaxFetch = 4 << 10
			s.replyBase = 1 << 20 // keeps the case quick under -race
			budget := s.replyBudget(1)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			peak := heapPeak()
			start := time.Now()
			_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
			d := time.Since(start)
			grew := peak()
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Fatal("an endless reply was answered as success")
			}
			if d > 5*time.Second {
				t.Fatalf("the call took %v: it read until the timeout instead of stopping at its budget", d)
			}
			var n int64
			select {
			case n = <-wrote:
			case <-time.After(10 * time.Second):
				t.Fatal("the connection was left open after the call failed")
			}
			// Socket buffers on both ends absorb some bytes the client never read.
			if n > budget+32<<20 {
				t.Fatalf("the server wrote %d bytes before the client hung up; budget %d", n, budget)
			}
			a := after.TotalAlloc - before.TotalAlloc
			if a > uint64(4*budget+64<<20) {
				t.Fatalf("the call allocated %d bytes; budget %d", a, budget)
			}
			// M21: the heap in use peaks at about 40 times the bytes read,
			// for a reply of nothing but two-byte atoms.
			if grew > uint64(peakPerByte*budget+16<<20) {
				t.Fatalf("the heap grew by %d bytes at its peak; budget %d", grew, budget)
			}
			t.Logf("server wrote %d bytes, the call allocated %d, peak heap growth %d (%.0fx); budget %d",
				n, a, grew, float64(grew)/float64(budget), budget)
		})
	}
}

// peakPerByte is M21's bound on the heap a hostile reply can hold per
// byte of its read budget.
const peakPerByte = 48

// heapPeak samples the heap's live and unswept objects until the
// returned function is called, which reports the most they grew past
// where they started. Sampling can miss a spike between samples, so it
// understates the peak a little, never overstates it.
func heapPeak() func() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(s); return s[0].Value.Uint64() }
	base, top := read(), uint64(0)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			if v := read(); v > top {
				top = v
			}
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	return func() uint64 {
		close(stop)
		<-done
		if top < base {
			return 0
		}
		return top - base
	}
}

// The budget grows with the messages a call fetches, so a legitimate
// fetch of many full-size messages is not cut off.
func TestReplyBudgetCoversTheFetch(t *testing.T) {
	s := hostileStore(t, "127.0.0.1:1", time.Second)
	if got, want := s.replyBudget(100)-s.replyBudget(0), int64(100*(s.cfg.MaxFetch+fetchFrame)); got != want {
		t.Fatalf("100 messages add %d bytes to the budget, want %d", got, want)
	}
}

const deepChildEnv = "AGENTOS_K18B_DEEP_CHILD"

// TestDeepNestingFailsTheCall (SR3-mail-k18b): a FETCH reply nested
// deeper than any real one overflowed the reader goroutine's stack, a
// fatal error no recover catches. The child caps its stack at 8 MB, as
// Security's reproduction did, so the overflow is quick and cheap; run in
// a subprocess so that without the bound it is reported here instead of
// ending this test binary.
func TestDeepNestingFailsTheCall(t *testing.T) {
	if os.Getenv(deepChildEnv) == "1" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDeepNestingChild$", "-test.v")
	cmd.Env = append(os.Environ(), deepChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the child hung after the nested reply:\n%s", tail(string(out), 1500))
	}
	if err != nil || strings.Contains(string(out), "stack overflow") {
		t.Fatalf("the nested reply ended the process: %v\n%s", err, tail(string(out), 1500))
	}
	if !strings.Contains(string(out), "k18b: call failed:") {
		t.Fatalf("child did not report the failed call:\n%s", tail(string(out), 1500))
	}
}

func TestDeepNestingChild(t *testing.T) {
	if os.Getenv(deepChildEnv) != "1" {
		t.Skip("run by TestDeepNestingFailsTheCall")
	}
	debug.SetMaxStack(8 << 20)
	addr, ended := hostile(t, "* 1 FETCH (UID 1 BODY[] "+strings.Repeat("(", 200000), false)
	s := hostileStore(t, addr, 30*time.Second)
	start := time.Now()
	_, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
	if err == nil {
		t.Fatal("a nested FETCH reply was answered as success")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the call took %v: it waited out a timeout instead of failing on the bound", d)
	}
	select {
	case end := <-ended:
		if end != "eof" {
			t.Fatalf("the server saw %q, want the client to close the connection (eof)", end)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the connection was left open after the nested reply")
	}
	t.Logf("k18b: call failed: %v", err)
}

// TestResponseFieldsAreBounded (SR3-mail-k18b): one response of tiny
// fields, the shape that holds the most memory per byte, stops at a
// million fields, which bounds what any response holds whatever the
// read budget. A UID SEARCH of a million messages still parses.
func TestResponseFieldsAreBounded(t *testing.T) {
	const max = 1 << 20
	read := func(fields int) (uint64, error) {
		reply := "* SEARCH " + strings.Repeat("a ", fields-1) + "a\r\n"
		runtime.GC()
		peak := heapPeak()
		_, err := imap.ReadResp(imap.NewReader(bufio.NewReader(strings.NewReader(reply))))
		return peak(), err
	}
	if _, err := read(max - 1); err != nil {
		t.Fatalf("a SEARCH of %d UIDs failed: %v", max-1, err)
	}
	grew, err := read(max + 1)
	if !errors.Is(err, imap.ErrTooManyFields) {
		t.Fatalf("a response of %d fields: err %v, want ErrTooManyFields", max+1, err)
	}
	if grew > 96<<20 {
		t.Fatalf("a response stopped at the field bound grew the heap by %d bytes at its peak", grew)
	}
	t.Logf("a response stopped at the field bound grew the heap by %d bytes at its peak", grew)
}

// TestFlagsUpdateKeepsTheBody (SR3-mail-k18b): a server may send an
// unsolicited FLAGS-only FETCH for a message during the UID FETCH that
// reads it (a flag changed meanwhile). That response must not take the
// message's one slot, or the body that follows is dropped and the message
// is answered blank.
func TestFlagsUpdateKeepsTheBody(t *testing.T) {
	body := "Subject: canary\r\n\r\nhello\r\n"
	addr, _ := hostile(t, "* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n"+
		"* 1 FETCH (UID 1 FLAGS (\\Seen) BODY[] {"+strconv.Itoa(len(body))+"}\r\n"+body+")\r\n"+
		"$TAG OK done\r\n", false)
	s := hostileStore(t, addr, 10*time.Second)
	got, err := s.Fetch(context.Background(), "INBOX", 7, []uint32{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject != "canary" {
		t.Fatalf("got %+v, want the one message with its body", got)
	}
}

// smtpFlood is a raw SMTP server that answers each command with 250
// (AUTH 235, DATA 354 and then 250, QUIT 221) until the client sends
// one starting with on, and then writes prefix
// and chunk, over and over, until the client stops reading. An empty on
// floods the greeting. It stands in for a hostile mail host that never
// ends an SMTP reply (SR3-mail-k18d-smtp). The number of bytes it wrote
// is sent on the returned channel when the connection ends.
func smtpFlood(t testing.TB, on, prefix, chunk string) (string, <-chan int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	wrote := make(chan int64, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		pour := func() {
			n, err := c.Write([]byte(prefix))
			total := int64(n)
			for err == nil {
				n, err = c.Write([]byte(chunk))
				total += int64(n)
			}
			wrote <- total
		}
		if on == "" {
			pour()
			return
		}
		c.Write([]byte("220 ready\r\n"))
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				wrote <- 0
				return
			}
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, on):
				pour()
				return
			case strings.HasPrefix(cmd, "AUTH"):
				c.Write([]byte("235 ok\r\n"))
			case strings.HasPrefix(cmd, "DATA"):
				c.Write([]byte("354 go on\r\n"))
				for line != ".\r\n" {
					if line, err = r.ReadString('\n'); err != nil {
						wrote <- 0
						return
					}
				}
				c.Write([]byte("250 ok\r\n"))
			case strings.HasPrefix(cmd, "QUIT"):
				c.Write([]byte("221 bye\r\n"))
			default:
				c.Write([]byte("250 ok\r\n"))
			}
		}
	}()
	return l.Addr().String(), wrote
}

// TestHostileSMTPReplyIsBounded (SR3-mail-k18d-smtp): net/smtp reads a
// reply with textproto's ReadResponse, which has no line or reply limit,
// so an SMTP reply that never ends would be held in memory until the
// store's timeout. With the read budget it costs one call and bounded
// memory, as an IMAP reply does (M21).
func TestHostileSMTPReplyIsBounded(t *testing.T) {
	big := strings.Repeat("x", 64<<10)
	more := strings.Repeat("250-"+strings.Repeat("x", 60)+"\r\n", 1<<10)
	for _, c := range []struct{ name, on, prefix, chunk string }{
		{"endless greeting line", "", "220 ", big},
		{"endless greeting continuation", "", "", strings.ReplaceAll(more, "250-", "220-")},
		{"endless EHLO line", "EHLO", "250 ", big},
		{"endless EHLO continuation", "EHLO", "", more},
		{"endless MAIL reply", "MAIL", "250 ", big},
	} {
		t.Run(c.name, func(t *testing.T) {
			addr, wrote := smtpFlood(t, c.on, c.prefix, c.chunk)
			s := hostileStore(t, addr, 8*time.Second)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			peak := heapPeak()
			start := time.Now()
			err := s.Submit(context.Background(), []string{"friend@example.test"},
				[]byte("From: owner@example.test\r\nTo: friend@example.test\r\n\r\nhi\r\n"))
			d := time.Since(start)
			grew := peak()
			runtime.ReadMemStats(&after)
			if err == nil {
				t.Fatal("an endless reply was answered as success")
			}
			if d > 5*time.Second {
				t.Fatalf("the call took %v: it read until the timeout instead of stopping at its budget", d)
			}
			var n int64
			select {
			case n = <-wrote:
			case <-time.After(10 * time.Second):
				t.Fatal("the connection was left open after the call failed")
			}
			budget := int64(smtpReplyBudget)
			if n > budget+32<<20 {
				t.Fatalf("the server wrote %d bytes before the client hung up; budget %d", n, budget)
			}
			a := after.TotalAlloc - before.TotalAlloc
			if a > uint64(8*budget+16<<20) {
				t.Fatalf("the call allocated %d bytes; budget %d", a, budget)
			}
			if grew > uint64(8*budget+16<<20) {
				t.Fatalf("the heap grew by %d bytes at its peak; budget %d", grew, budget)
			}
			t.Logf("server wrote %d bytes, the call allocated %d, peak heap growth %d; budget %d", n, a, grew, budget)
		})
	}
}

// TestSMTPSubmitWithinBudget: an ordinary submission, greeting to QUIT,
// reads far less than the SMTP budget, so the bound refuses no real
// server.
func TestSMTPSubmitWithinBudget(t *testing.T) {
	addr, _ := smtpFlood(t, "NEVER", "", "")
	s := hostileStore(t, addr, 8*time.Second)
	if err := s.Submit(context.Background(), []string{"friend@example.test"},
		[]byte("From: owner@example.test\r\nTo: friend@example.test\r\n\r\nhi\r\n")); err != nil {
		t.Fatalf("an ordinary submission failed: %v", err)
	}
}
