package replay

// REQ: CHG-1, LOOP-5, OP-7, ARC-6, OP-1

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
)

// This exercises the real guest /mcp HTTP handler and recorded effect service
// without the Linux VM lifecycle; the RunObserved composition also has a
// retained full replay test in replay_test.go.
type boundaryMachines struct{}

func (boundaryMachines) Step(context.Context, string) error { return nil }
func (boundaryMachines) RaisePrivate(string) error          { return nil }
func (boundaryMachines) Lineage(id string) (string, error)  { return id, nil }

type boundaryEffects map[string]*recorded

func (b boundaryEffects) record(id string) *recorded {
	machine, _, _ := strings.Cut(id, "/")
	return b[machine]
}
func (b boundaryEffects) Submit(in journal.Intent) (journal.Status, error) {
	return b.record(in.ID).Submit(in)
}
func (b boundaryEffects) Authorize(_ context.Context, id string) (journal.Status, error) {
	return b.record(id).Authorize(id)
}
func (b boundaryEffects) Dispatch(_ context.Context, id string) (journal.Status, error) {
	return b.record(id).Dispatch(id)
}
func (b boundaryEffects) Get(id string) (journal.Status, error) { return b.record(id).Get(id) }

func boundaryPlane(t *testing.T, records boundaryEffects, mods ...func(*guest.Config)) (*guest.Plane, map[string]*http.Client) {
	t.Helper()
	dir, err := os.MkdirTemp("", "p3b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := guest.Config{Dir: dir, Machines: boundaryMachines{}, Effects: records, ObserveMCP: func(id string) func(bool) { return records[id].observeMCP() }, Route: func(string) (string, bool) { return "replay", true }, SubmitBurst: 2, SubmitEvery: time.Hour}
	for _, mod := range mods {
		mod(&cfg)
	}
	p, err := guest.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Shutdown)
	clients := map[string]*http.Client{}
	for id := range records {
		where, err := p.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(where, guest.Socket)
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		clients[id] = &http.Client{Transport: transport}
	}
	return p, clients
}

func boundaryCall(t *testing.T, client *http.Client, tool string, arguments any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": arguments}, "machine": "other"})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", "http://broker/mcp", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Machine", "other")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
}

func boundarySend() map[string]any {
	in := resultIntent("original")
	return map[string]any{"request_id": "send", "account": in.Account, "action": in.Action, "params": in.Params, "recipients": in.Recipients}
}

func TestMCPRefusalsCannotDisappearFromObservedResults(t *testing.T) {
	for _, outcome := range []change.Outcome{change.Accepted, change.Rejected} {
		for name, arguments := range map[string]any{
			"broker-state": map[string]any{"request_id": "forbidden", "account": "broker", "action": "meta.canary"},
			"malformed":    "not-an-object",
			"bad-id":       map[string]any{"request_id": "bad/id", "account": "mail", "action": "mail.send"},
		} {
			t.Run(string(outcome)+"/"+name, func(t *testing.T) {
				r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
				_, clients := boundaryPlane(t, boundaryEffects{"test": r})
				client := clients["test"]
				if outcome == change.Accepted {
					boundaryCall(t, client, "effect_request", boundarySend())
				}
				boundaryCall(t, client, "effect_request", arguments)
				expect, _ := change.MailSendExpectation(resultIntent("original"))
				c := change.Case{Class: change.ClassTask, Task: "original", Outcome: outcome, ResultFormat: change.MailSendResultV1, Expect: expect}
				out, err := r.result([]byte("Done"))
				if err == nil && change.ObservedEffectGrader(c, out) {
					t.Fatal("an early-refused effect request disappeared from the trace")
				}
			})
		}
	}
}

func boundaryCase(outcome change.Outcome) change.Case {
	expect, _ := change.MailSendExpectation(resultIntent("original"))
	return change.Case{Class: change.ClassTask, Task: "original", Outcome: outcome, ResultFormat: change.MailSendResultV1, Expect: expect}
}

func TestMCPRateRefusalCountsButNormalReadsAndIdempotencyDoNot(t *testing.T) {
	for _, limited := range []bool{false, true} {
		r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
		_, clients := boundaryPlane(t, boundaryEffects{"test": r})
		client := clients["test"]
		boundaryCall(t, client, "effect_request", boundarySend())
		boundaryCall(t, client, "effect_request", boundarySend()) // same id: still one effect
		boundaryCall(t, client, "effect_status", map[string]any{"request_id": "missing"})
		boundaryCall(t, client, "unknown_read_tool", map[string]any{}) // normal tool fallback
		if limited {
			boundaryCall(t, client, "effect_request", boundarySend())
		}
		out, err := r.result([]byte("Done"))
		pass := err == nil && change.ObservedEffectGrader(boundaryCase(change.Accepted), out)
		if pass == limited {
			t.Fatalf("limited=%v pass=%v err=%v", limited, pass, err)
		}
	}
}

func TestMCPObserverUsesSocketMachineNotGuestIdentityFields(t *testing.T) {
	a := newRecorded(nil)
	b := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
	_, clients := boundaryPlane(t, boundaryEffects{"test": a, "other": b})
	// boundaryCall forges both the header and JSON identity as "other".
	boundaryCall(t, clients["test"], "effect_request", "bad arguments")
	boundaryCall(t, clients["other"], "effect_request", boundarySend())
	if out, err := a.result([]byte("Done")); err == nil && change.ObservedEffectGrader(boundaryCase(change.Rejected), out) {
		t.Fatal("refusal was charged to the forged machine")
	}
	if out, err := b.result([]byte("Done")); err != nil || !change.ObservedEffectGrader(boundaryCase(change.Accepted), out) {
		t.Fatal("another machine's refusal poisoned this run", err)
	}
}

func TestOwnerReplyFreezesAfterItsSuccessfulEffectRequestFinishes(t *testing.T) {
	r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
	passed := make(chan bool, 1)
	p, clients := boundaryPlane(t, boundaryEffects{"test": r}, func(c *guest.Config) {
		c.OwnerReply = func(machine string, rep guest.Reply) {
			out, err := r.result([]byte(rep.Text))
			passed <- machine == "test" && err == nil && change.ObservedEffectGrader(boundaryCase(change.Accepted), out)
		}
	})
	if _, err := p.DeliverOwner("test", "send the message", false); err != nil {
		t.Fatal(err)
	}
	res, err := clients["test"].Get("http://broker/owner/next")
	if err != nil {
		t.Fatal(err)
	}
	var msg struct{ ID string }
	if err := json.NewDecoder(res.Body).Decode(&msg); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	boundaryCall(t, clients["test"], "effect_request", boundarySend())
	b, _ := json.Marshal(map[string]string{"id": msg.ID, "text": "Done"})
	res, err = clients["test"].Post("http://broker/owner/reply", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	select {
	case pass := <-passed:
		if !pass {
			t.Fatal("completion raced its own successful MCP request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner reply did not reach its callback")
	}
}

func TestConcurrentEffectRequestCannotFinishAsEmptyEvidence(t *testing.T) {
	r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, clients := boundaryPlane(t, boundaryEffects{"test": r}, func(c *guest.Config) {
		c.Route = func(string) (string, bool) { close(entered); <-release; return "replay", true }
	})
	go func() { defer close(done); boundaryCall(t, clients["test"], "effect_request", boundarySend()) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("effect did not enter its handler")
	}
	_, err := r.result([]byte("No effects"))
	close(release)
	<-done
	if err == nil {
		t.Fatal("an in-flight effect was certified as no attempt")
	}
}

func TestMCPAdmissionRefusalCannotDisappearBeforeOwnerReply(t *testing.T) {
	for _, outcome := range []change.Outcome{change.Accepted, change.Rejected} {
		t.Run(string(outcome), func(t *testing.T) {
			r := newRecorded([]journal.Status{{Intent: resultIntent("original"), State: journal.Succeeded}})
			passed := make(chan bool, 1)
			p, clients := boundaryPlane(t, boundaryEffects{"test": r}, func(c *guest.Config) {
				c.MaxConns = 8
				c.OwnerReply = func(_ string, rep guest.Reply) {
					out, err := r.result([]byte(rep.Text))
					passed <- err == nil && change.ObservedEffectGrader(boundaryCase(outcome), out)
				}
			})
			client := clients["test"]
			id, err := p.DeliverOwner("test", "synthetic task", true)
			if err != nil {
				t.Fatal(err)
			}
			res, err := client.Get("http://broker/owner/next")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if outcome == change.Accepted {
				boundaryCall(t, client, "effect_request", boundarySend())
			}

			// Occupy all eight request slots using the production owner long poll.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var polls sync.WaitGroup
			for i := 0; i < 8; i++ {
				polls.Add(1)
				go func() {
					defer polls.Done()
					req, _ := http.NewRequestWithContext(ctx, "GET", "http://broker/owner/next", nil)
					if res, err := client.Do(req); err == nil {
						_ = res.Body.Close()
					}
				}()
			}
			time.Sleep(200 * time.Millisecond) // same admission setup as guest's concurrency-cap regression
			body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"effect_request","arguments":{"request_id":"extra","account":"broker","action":"meta.canary"}}}`)
			res, err = client.Post("http://broker/mcp", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if res.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("slots were not saturated: %d", res.StatusCode)
			}
			cancel()
			polls.Wait()
			// Wait for server-side cancellation to release at least one slot.
			deadline := time.Now().Add(2 * time.Second)
			for {
				res, err = client.Get("http://broker/no-such-service")
				if err != nil {
					t.Fatal(err)
				}
				_ = res.Body.Close()
				if res.StatusCode == http.StatusNotFound {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cancelled polls kept their slots")
				}
				time.Sleep(time.Millisecond)
			}
			body, _ = json.Marshal(map[string]string{"id": id, "text": "Done"})
			res, err = client.Post("http://broker/owner/reply", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			select {
			case pass := <-passed:
				if pass {
					t.Fatal("an HTTP-admission-refused effect vanished from grading")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("owner reply did not complete")
			}
		})
	}
}

func TestMCPEscapedPathRefusalCannotDisappear(t *testing.T) {
	r := newRecorded(nil)
	_, clients := boundaryPlane(t, boundaryEffects{"test": r})
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"effect_request","arguments":{"request_id":"extra","account":"broker","action":"meta.canary"}}}`)
	res, err := clients["test"].Post("http://broker/m%63p", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("escaped path reached MCP: %d", res.StatusCode)
	}
	if out, err := r.result([]byte("Done")); err == nil && change.ObservedEffectGrader(boundaryCase(change.Rejected), out) {
		t.Fatal("escaped-path refusal disappeared from grading")
	}
}
