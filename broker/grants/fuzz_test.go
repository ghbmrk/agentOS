package grants

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-10, ADP-9

// fuzzAnswer is the first answer the owner gave on one intent.
type fuzzAnswer struct {
	approved  bool
	at        time.Time
	recipient string
}

// FuzzApprovals (FUZZ-3): over any sequence of effects, flushes, approvals,
// denials, record changes, clock moves, stops, resumes, dispatches and a
// revoke, each intent runs at most once, and only after an approval and no
// denial of it, while its record still names the recipient the approval
// named, within DefaultFresh of that approval, and never once its grant is
// revoked.
func FuzzApprovals(f *testing.F) {
	f.Add([]byte{0, 0, 1, 0, 2, 0})                         // approve, and it runs
	f.Add([]byte{0, 0, 1, 0, 6, 0, 2, 0, 3, 2, 7, 0, 5, 0}) // approve under STOP, then too late
	f.Add([]byte{0, 0, 1, 0, 6, 0, 2, 0, 4, 6, 7, 0, 5, 0}) // approve under STOP, then the recipient moves
	f.Add([]byte{0, 0, 1, 0, 6, 0, 2, 0, 8, 0, 7, 0, 5, 0}) // approve under STOP, then revoke
	f.Add([]byte{0, 0, 1, 0, 2, 1, 2, 0, 5, 0})             // deny, then approve
	f.Add([]byte{0, 0, 0, 1, 1, 0, 2, 0, 2, 4, 3, 1, 5, 1}) // two effects, approved one by one
	f.Fuzz(func(t *testing.T, b []byte) { fuzzApprovals(t, t, b, nil) })
}

// fuzzT is the part of testing.T the oracle reports through, so a control
// can hand it a recorder and show that a planted defect is reported.
type fuzzT interface {
	Helper()
	Fatalf(format string, args ...any)
}

type stopRun struct{}

type recorder struct{ msgs []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
	panic(stopRun{})
}

func (r *recorder) run(f func(fuzzT)) (msgs []string) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(stopRun); !ok {
				panic(p)
			}
		}
		msgs = r.msgs
	}()
	f(r)
	return r.msgs
}

// fuzzApprovals drives the grants as the input says. defect, when set, runs
// after each operation and may change what the rig's executor has run: a
// planted defect.
func fuzzApprovals(t *testing.T, rep fuzzT, b []byte, defect func(r *rig, op int, id string)) {
	r := newRig(t, nil)
	gid := r.grant(mailGrant())
	ctx := context.Background()
	ids := []string{"agent/a", "agent/b", "agent/c"}
	recs := []string{"inv-a", "inv-b", "inv-c"}
	names := []string{"sam@example.com", "mallory@example.net"}
	recipient := map[string]string{} // record: the recipient it names now
	setRecord := func(rec string, to byte) {
		v := sam()
		v.Record = rec
		if to%3 != 0 {
			v.Item.Recipient = names[1]
		}
		if to%3 == 2 {
			v.Recipients = []string{names[1]}
		}
		recipient[rec] = v.Item.Recipient
		r.ver.set(rec, v)
	}
	for _, rec := range recs {
		setRecord(rec, 0)
	}
	submitted := map[string]bool{}
	answer := map[string]fuzzAnswer{}
	revoked := false
	runs := map[string]int{}
	at := func(i int) byte {
		if i < len(b) {
			return b[i]
		}
		return 0
	}
	for i, ops := 0, 0; i < len(b) && ops < 64; ops++ {
		op, arg := at(i)%9, at(i+1)
		i += 2
		k := int(arg) % len(ids)
		id := ids[k]
		switch op {
		case 0: // the agent asks for an effect
			if submitted[id] {
				break
			}
			submitted[id] = true
			in := journal.Intent{ID: id, Origin: "guest:agent", Account: "mail", Action: "invoice.send",
				Params: map[string]any{"record": recs[k]}, Recipients: []string{names[0]},
				Executor: "mail", Machine: "agent", Label: "private"}
			st, err := r.g.Submit(in)
			if err == nil && st.State == journal.Pending {
				st, err = r.g.Authorize(ctx, id)
			}
			if err == nil && st.State == journal.Authorized {
				r.g.Dispatch(ctx, id)
			}
		case 1:
			r.g.Flush()
		case 2: // the owner answers every unanswered item of one request
			r.own.mu.Lock()
			var req string
			var items []owner.Item
			// Only requests about an effect: the grant's own request is
			// answered by the rig, so picking it reaches no effect path.
			var effects []string
			for _, q := range r.own.order {
				for _, it := range r.own.reqs[q] {
					if recOf(ids, recs, it.Ref) != "" {
						effects = append(effects, q)
						break
					}
				}
			}
			if n := len(effects); n > 0 {
				req = effects[int(arg>>2)%n]
				items = append(items, r.own.reqs[req]...)
			}
			r.own.mu.Unlock()
			approved := arg&1 == 0
			for j, it := range items {
				if _, mine := recipient[recOf(ids, recs, it.Ref)]; !mine {
					continue
				}
				if _, done := answer[it.Ref]; !done {
					answer[it.Ref] = fuzzAnswer{approved: approved, at: r.now(), recipient: it.Recipient}
				}
				r.g.Decide(owner.Decision{Request: req, Item: j + 1, Ref: it.Ref, Approved: approved, Why: "owner"})
			}
		case 3:
			r.advance([]time.Duration{time.Minute, 30 * time.Minute, DefaultFresh + time.Minute}[arg%3])
		case 4:
			setRecord(recs[k], arg>>2)
		case 5:
			r.g.Dispatch(ctx, id)
		case 6:
			r.eng.Stop(ctx)
		case 7:
			r.eng.Resume()
		case 8:
			r.g.Narrow("REVOKE", gid)
			revoked = true
		}
		if defect != nil {
			defect(r, int(op), id)
		}
		r.g.Wait()
		for j, id := range ids {
			n := r.exec.runs(id)
			if n == runs[id] {
				continue
			}
			what := fmt.Sprintf("op %d: %s ran %d times", ops, id, n)
			a, ok := answer[id]
			switch {
			case n > 1 || runs[id] != 0:
				rep.Fatalf("%s: more than once", what)
			case !ok || !a.approved:
				rep.Fatalf("%s: with no approval first (answer %+v)", what, a)
			case recipient[recs[j]] != a.recipient:
				rep.Fatalf("%s: to %s, but %s was approved", what, recipient[recs[j]], a.recipient)
			case r.now().Before(a.at) || r.now().Sub(a.at) > DefaultFresh:
				rep.Fatalf("%s: %s after its approval", what, r.now().Sub(a.at))
			case revoked:
				rep.Fatalf("%s: after its grant was revoked", what)
			}
			runs[id] = n
		}
	}
}

// recOf is the record intent ref's effect sends, or "" when ref is not one
// of ids.
func recOf(ids, recs []string, ref string) string {
	for i, id := range ids {
		if id == ref {
			return recs[i]
		}
	}
	return ""
}

// Each control plants a defect after the operations and shows the oracle
// reports it, then shows the real grants pass the same input.
func TestFuzzApprovalsReportsAPlantedDefect(t *testing.T) {
	runNow := func(r *rig, id string) {
		r.exec.Execute(context.Background(), journal.Intent{ID: id}, 1)
	}
	for name, c := range map[string]struct {
		in     []byte
		defect func(*rig, int, string)
	}{
		"runs with no approval": {[]byte{0, 0, 1, 0, 2, 0}, func(r *rig, op int, id string) {
			if op == 0 {
				runNow(r, id)
			}
		}},
		"runs twice": {[]byte{0, 0, 1, 0, 2, 0, 5, 0}, func(r *rig, op int, id string) {
			if op == 5 && r.exec.runs(id) > 0 {
				runNow(r, id)
			}
		}},
	} {
		var rec recorder
		if len(rec.run(func(ft fuzzT) { fuzzApprovals(t, ft, c.in, c.defect) })) == 0 {
			t.Errorf("%s: the oracle did not report the planted defect", name)
		}
		rec = recorder{}
		if msgs := rec.run(func(ft fuzzT) { fuzzApprovals(t, ft, c.in, nil) }); len(msgs) != 0 {
			t.Errorf("%s: the real grants reported: %v", name, msgs)
		}
	}
}
