package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/notice"
)

// The vault process's owner notices reach the owner through agentosd,
// which holds the owner channel (#1421): custody's notify queues each
// line notice.FromLog knows, and agentosd pulls the queue on notice.sock.
// The queue lives in memory only; a restart starts a new boot id.

// noticeCap bounds the queue; past it the oldest notice is dropped and
// counted as missed.
const noticeCap = 64

// noticeWait is how long a pull with nothing to answer waits for a notice.
var noticeWait = 25 * time.Second

type noticeQueue struct {
	mu    sync.Mutex
	boot  string
	seq   uint64
	items []notice.Item
	// missed notices were dropped unread; the last had number missedTo.
	missed, missedTo uint64
	wake             chan struct{}
}

func newNoticeQueue() *noticeQueue {
	b := make([]byte, 16)
	rand.Read(b)
	return &noticeQueue{boot: hex.EncodeToString(b), wake: make(chan struct{})}
}

// push queues n. It never blocks: custody calls notify under c.mu.
func (q *noticeQueue) push(n notice.Notice) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	q.items = append(q.items, notice.Item{Seq: q.seq, Notice: n})
	if len(q.items) > noticeCap {
		q.missed++
		q.missedTo = q.items[0].Seq
		q.items = append(q.items[:0:0], q.items[1:]...)
	}
	close(q.wake)
	q.wake = make(chan struct{})
}

// take drops what a caller of this boot has seen (numbers up to after)
// and returns the rest, with a channel closed at the next push. A caller
// of another boot has seen nothing.
func (q *noticeQueue) take(boot string, after uint64) (notice.Batch, <-chan struct{}) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if boot != q.boot {
		after = 0
	}
	i := 0
	for i < len(q.items) && q.items[i].Seq <= after {
		i++
	}
	if i > 0 {
		q.items = append(q.items[:0:0], q.items[i:]...)
	}
	if q.missed > 0 && after >= q.missedTo {
		q.missed, q.missedTo = 0, 0
	}
	return notice.Batch{Boot: q.boot, Notices: append([]notice.Item{}, q.items...), Missed: q.missed}, q.wake
}

// ownerNotify is custody's notify: every line is logged as before, and an
// owner notice is queued for agentosd too.
func ownerNotify(q *noticeQueue) func(string) {
	return func(s string) {
		log.Print(s)
		if n, ok := notice.FromLog(s); ok {
			q.push(n)
		}
	}
}

// noticeHandler serves GET /notices?boot=B&after=N: the notices after N,
// waiting up to noticeWait for one when there are none.
func noticeHandler(q *noticeQueue) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/notices" {
			http.Error(w, "GET /notices only", http.StatusNotFound)
			return
		}
		after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if err != nil {
			http.Error(w, "after: a notice number", http.StatusBadRequest)
			return
		}
		boot := r.URL.Query().Get("boot")
		timer := time.NewTimer(noticeWait)
		defer timer.Stop()
		b, wake := q.take(boot, after)
	wait:
		for len(b.Notices) == 0 && b.Missed == 0 {
			select {
			case <-wake:
				b, wake = q.take(boot, after)
			case <-timer.C:
				break wait
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(b)
	})
}

// serveNotices opens notice.sock in dir for agentosd's uid.
func serveNotices(dir string, q *noticeQueue, brokerUID int) (*http.Server, error) {
	if err := runDir(dir); err != nil {
		return nil, err
	}
	ln, err := listen(dir, notice.Socket, brokerUID)
	if err != nil {
		return nil, err
	}
	srv := newServer(noticeHandler(q))
	go srv.Serve(ln)
	return srv, nil
}
