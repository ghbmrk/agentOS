package main

// REQ: OP-9, CH-3, CAP-9

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner/notice"
	"github.com/ghbmrk/agentos/broker/owner/notice/noticesock"
)

// fakeNoticeSock serves notice.sock with whatever batch the test sets, and
// records the boot and after each poll asked with.
type fakeNoticeSock struct {
	mu    sync.Mutex
	batch notice.Batch
	asked []string
}

func (f *fakeNoticeSock) set(b notice.Batch) { f.mu.Lock(); f.batch = b; f.mu.Unlock() }

func (f *fakeNoticeSock) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, r.URL.Query().Get("boot")+"/"+r.URL.Query().Get("after"))
	json.NewEncoder(w).Encode(f.batch)
}

func pullRig(t *testing.T) (*noticePuller, *fakeNoticeSock, *[]string, func() []string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "np")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, notice.Socket)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	fv := &fakeNoticeSock{}
	srv := &http.Server{Handler: fv}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	var mu sync.Mutex
	var got []string
	p := newNoticePuller(sock, func(s string) error {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, s)
		return nil
	})
	return p, fv, &got, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string{}, got...) }
}

func item(seq uint64, c notice.Code, name string) notice.Item {
	return notice.Item{Seq: seq, Notice: notice.Notice{Code: c, Name: name}}
}

func TestNoticePullTextsEachNoticeOnceInOrder(t *testing.T) {
	p, fv, _, texts := pullRig(t)
	fv.set(notice.Batch{Boot: "b1", Notices: []notice.Item{item(1, notice.MailReplaced, ""), item(2, notice.PrivateAllowed, "Acme")}})
	c := noticesock.New(p.socket)
	for i := 0; i < 2; i++ {
		if err := p.poll(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	want1, _ := notice.Text(notice.Notice{Code: notice.MailReplaced})
	want2, _ := notice.Text(notice.Notice{Code: notice.PrivateAllowed, Name: "Acme"})
	if g := texts(); len(g) != 2 || g[0] != want1 || g[1] != want2 {
		t.Fatalf("texts = %q", g)
	}
	if fv.asked[1] != "b1/2" {
		t.Fatalf("second poll asked %q, want b1/2", fv.asked[1])
	}
}

func TestNoticePullRetriesAFailedTextWithoutSkipping(t *testing.T) {
	var calls []string
	fail := true
	dir, _ := os.MkdirTemp("", "np")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, notice.Socket)
	ln, _ := net.Listen("unix", sock)
	fv := &fakeNoticeSock{}
	fv.set(notice.Batch{Boot: "b", Notices: []notice.Item{item(1, notice.MailRemoved, "")}})
	srv := &http.Server{Handler: fv}
	go srv.Serve(ln)
	defer srv.Close()
	p := newNoticePuller(sock, func(s string) error {
		if fail {
			return errors.New("no owner channel")
		}
		calls = append(calls, s)
		return nil
	})
	c := noticesock.New(p.socket)
	if err := p.poll(context.Background(), c); err == nil {
		t.Fatal("a failed text must fail the poll")
	}
	fail = false
	if err := p.poll(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || p.after != 1 {
		t.Fatalf("calls=%q after=%d", calls, p.after)
	}
}

func TestNoticePullNewBootStartsOver(t *testing.T) {
	p, fv, _, texts := pullRig(t)
	c := noticesock.New(p.socket)
	fv.set(notice.Batch{Boot: "b1", Notices: []notice.Item{item(5, notice.MailRemoved, "")}})
	p.poll(context.Background(), c)
	fv.set(notice.Batch{Boot: "b2", Notices: []notice.Item{item(1, notice.MailReplaced, "")}})
	p.poll(context.Background(), c)
	if len(texts()) != 2 {
		t.Fatalf("a restarted vault's notice 1 must be texted: %q", texts())
	}
}

func TestNoticePullDropsWhatHasNoTextAndSaysWhenNoticesWereMissed(t *testing.T) {
	p, fv, _, texts := pullRig(t)
	c := noticesock.New(p.socket)
	fv.set(notice.Batch{Boot: "b", Missed: 3, Notices: []notice.Item{item(1, notice.Code("free_text"), ""), item(2, notice.PrivateAllowed, "evil.example.com")}})
	for i := 0; i < 2; i++ {
		if err := p.poll(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	if g := texts(); len(g) != 1 || g[0] != noticeMissedText {
		t.Fatalf("texts = %q, want only the missed line once", g)
	}
	if p.after != 2 {
		t.Fatalf("after = %d: unrenderable notices must still be passed over", p.after)
	}
}

func TestNoticePullRunStopsWithContextAndKeepsAskingAfterErrors(t *testing.T) {
	p := newNoticePuller(filepath.Join(os.TempDir(), "no-such-notice.sock"), func(string) error { return nil })
	p.retry = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.run(ctx); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop")
	}
}
