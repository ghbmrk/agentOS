package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
)

// REQ: OP-9, CH-3, CAP-9

// Each of the vault process's owner-notice lines maps to a notice, so a
// reworded line fails here rather than going quiet.
func TestEveryOwnerNoticeLineMapsToANotice(t *testing.T) {
	for line, want := range map[string]notice.Code{
		noteSIPReplaced: notice.LineCallReplaced,
		noteSIPRemoved:  notice.LineCallRemoved,
		noteSMSReplaced: notice.LineTextReplaced,
		noteSMSRemoved:  notice.LineTextRemoved,
		noteSMSMissed:   notice.LineTextsMissed,
	} {
		if n, ok := notice.FromLog(line); !ok || n.Code != want {
			t.Errorf("%q: %+v %v, want %s", line, n, ok, want)
		}
	}
	for id := range providerNames {
		if n, ok := notice.FromLog("private data allowed for " + providerName(id)); !ok || n.Name != providerName(id) {
			t.Errorf("allowed for %s: %+v %v", id, n, ok)
		}
	}
}

// Through the real custody (#1266's flow): a wrong code and an allow on
// /providers/private each queue the notice for the owner, and a line
// that is not an owner notice is only logged.
func TestCustodyNoticesReachTheQueue(t *testing.T) {
	q := newNoticeQueue()
	r := newFastRig(t, true)
	log := r.c.notify
	r.c.notify = func(s string) { log(s); ownerNotify(q)(s) }
	call := handlerCall(t, r.c)
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if st, _ := call("POST", "/providers/private", privateBody("openai", true, "000000")); st == http.StatusNoContent {
		t.Fatal("a wrong code allowed it")
	}
	if st, out := call("POST", "/providers/private", privateBody("openai", true, r.next())); st != http.StatusNoContent {
		t.Fatalf("allow: %d %v", st, out)
	}
	b, _ := q.take(q.boot, 0)
	want := []notice.Notice{
		{Code: notice.WrongCode, Name: "allowing a provider private data"},
		{Code: notice.PrivateAllowed, Name: "OpenAI"},
	}
	if len(b.Notices) != len(want) {
		t.Fatalf("queued %+v; notes %q", b.Notices, r.notes)
	}
	for i, it := range b.Notices {
		if it.Notice != want[i] || it.Seq != uint64(i+1) {
			t.Errorf("notice %d: %+v", i, it)
		}
	}
	if !hasNote(r.notes, "vault unlocked") {
		t.Fatalf("the unlock was not logged: %q", r.notes)
	}
}

func noticeServer(t *testing.T, q *noticeQueue, uid int) *http.Client {
	t.Helper()
	// Unix socket paths are short; t.TempDir can exceed the limit.
	dir, err := os.MkdirTemp("", "nt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	srv, err := serveNotices(filepath.Join(dir, "run"), q, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	sock := filepath.Join(dir, "run", notice.Socket)
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
}

func pull(t *testing.T, c *http.Client, boot string, after uint64) notice.Batch {
	t.Helper()
	res, err := c.Get(fmt.Sprintf("http://vault/notices?boot=%s&after=%d", boot, after))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var b notice.Batch
	if err := json.NewDecoder(res.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func codes(b notice.Batch) (out []string) {
	for _, it := range b.Notices {
		out = append(out, fmt.Sprintf("%d:%s", it.Seq, it.Code))
	}
	return out
}

// agentosd pulls the queue: it gets what is queued, what it has seen is
// dropped, an empty queue waits for the next notice, and a new boot id
// (the vault process restarted, or agentosd has none yet) sends all.
func TestTheNoticeSocketAnswersAcksAndWaits(t *testing.T) {
	q := newNoticeQueue()
	c := noticeServer(t, q, os.Getuid())
	q.push(notice.Notice{Code: notice.MailReplaced})
	q.push(notice.Notice{Code: notice.LineTextRemoved})

	b := pull(t, c, "", 0)
	if b.Boot != q.boot || len(b.Boot) < 16 || fmt.Sprint(codes(b)) != "[1:mail_replaced 2:line_text_removed]" {
		t.Fatalf("first pull: %+v", b)
	}
	if b := pull(t, c, b.Boot, 1); fmt.Sprint(codes(b)) != "[2:line_text_removed]" {
		t.Fatalf("after 1: %+v", b)
	}
	if b := pull(t, c, "another-boot", 1); fmt.Sprint(codes(b)) != "[2:line_text_removed]" {
		t.Fatalf("another boot: %+v", b)
	}
	if len(q.items) != 1 {
		t.Fatalf("seen notices kept: %+v", q.items)
	}

	defer func(w time.Duration) { noticeWait = w }(noticeWait)
	noticeWait = 50 * time.Millisecond
	if b := pull(t, c, q.boot, 2); len(b.Notices) != 0 || b.Missed != 0 {
		t.Fatalf("nothing new: %+v", b)
	}
	noticeWait = 10 * time.Second
	go func() {
		time.Sleep(100 * time.Millisecond)
		q.push(notice.Notice{Code: notice.PrivateAllowed, Name: "OpenAI"})
	}()
	start := time.Now()
	b = pull(t, c, q.boot, 2)
	if fmt.Sprint(codes(b)) != "[3:private_allowed]" || b.Notices[0].Name != "OpenAI" || time.Since(start) > 5*time.Second {
		t.Fatalf("waited pull: %+v after %v", b, time.Since(start))
	}
	if len(q.items) != 1 {
		t.Fatalf("queue: %+v", q.items)
	}
}

// A full queue drops the oldest notice and says how many were missed,
// until agentosd has seen past the last one dropped.
func TestAFullQueueReportsWhatWasMissed(t *testing.T) {
	q := newNoticeQueue()
	for i := 0; i < noticeCap+3; i++ {
		q.push(notice.Notice{Code: notice.WrongCode})
	}
	b, _ := q.take(q.boot, 0)
	if b.Missed != 3 || len(b.Notices) != noticeCap || b.Notices[0].Seq != 4 {
		t.Fatalf("missed %d, %d notices from %d", b.Missed, len(b.Notices), b.Notices[0].Seq)
	}
	if b, _ := q.take(q.boot, 4); b.Missed != 0 || len(b.Notices) != noticeCap-1 {
		t.Fatalf("after seeing past the gap: missed %d, %d notices", b.Missed, len(b.Notices))
	}
	if b, _ := q.take("other", 0); b.Missed != 0 {
		t.Fatalf("a new boot sees the gap again: %d", b.Missed)
	}
}

// The socket admits agentosd's uid only (the existing peer listener), and
// it answers GET /notices only.
func TestTheNoticeSocketAdmitsOnlyAgentosd(t *testing.T) {
	q := newNoticeQueue()
	q.push(notice.Notice{Code: notice.MailRemoved})
	c := noticeServer(t, q, os.Getuid()+1)
	c.Timeout = 2 * time.Second
	if res, err := c.Get("http://vault/notices?after=0"); err == nil {
		res.Body.Close()
		t.Fatalf("another uid was answered: %d", res.StatusCode)
	}
	if len(q.items) != 1 {
		t.Fatal("a refused peer changed the queue")
	}

	h := noticeHandler(q)
	for _, tc := range []struct{ method, target string }{
		{"POST", "/notices?after=0"},
		{"GET", "/other"},
		{"GET", "/notices?after=-1"},
		{"GET", "/notices?after=x"},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.target, nil))
		if w.Code == http.StatusOK {
			t.Errorf("%s %s: %d", tc.method, tc.target, w.Code)
		}
	}
	if len(q.items) != 1 {
		t.Fatal("a refused request changed the queue")
	}
}

// A pull whose caller hangs up while waiting returns without answering.
func TestAWaitingPullEndsWithItsCaller(t *testing.T) {
	q := newNoticeQueue()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w := httptest.NewRecorder()
		noticeHandler(q).ServeHTTP(w, httptest.NewRequest("GET", "/notices?after=0", nil).WithContext(ctx))
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the pull kept waiting")
	}
}
