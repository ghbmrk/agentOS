package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// What agentosd keeps of the old learning plane (W3) once the learning
// loop (MIG-4-untrusted-learn) and the owner's FORGET and RENEW (#2781)
// are deleted: their state in the learn directory is erased at each
// start, their owner texts get fixed replies, and intents left open for
// their executors settle as not applied. Forget comes back on the
// kernel's log (#2823, LOG-4).

// learnedFiles are the old learning plane's state in the learn
// directory: the learning loop's (the directories are the pipeline's
// bodies, change.FileStore.Bodies) and FORGET's task texts, tombstones
// and owed done texts. Nothing reads them any more, so they are removed
// at start and nothing of a task stays at rest that the owner cannot
// forget (CAP-3). The restored forget log (forgetLogFile) stays: the
// restore hold reads it.
var learnedFiles = []string{"change.json", "change.json.d", "harvest.json", "values.json",
	"loops.json", "loop2.json", "routing-learned.json",
	"tasks.json", "forgotten.json", "forget-owed.json", "forget-owed.json.bad"}

// learnTemp is durable.TempPrefix: durable.WriteFile's temp files carry
// it, and a crash between write and rename leaves one behind. It is
// spelled here, not imported, so agentosd's imports of the old core do
// not grow (trace.py --ratchet).
const learnTemp = ".durable-"

// sweepLearnTemp removes every learnTemp file in dir, as
// durable.SweepTemp does: one that will not go does not shield the rest.
func sweepLearnTemp(dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, learnTemp+"*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		if err := os.Remove(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// sweepTemp and removeAll are removeLearned's, swapped by tests.
var (
	sweepTemp = sweepLearnTemp
	removeAll = os.RemoveAll
)

// removeLearned removes learnedFiles and the temps a crash left in dir
// (durable.WriteFile's, learnTemp, which may hold a copy of harvest.json or
// values.json and so task text; security 1 on #2801). Nothing else writes
// to dir yet. A file it cannot remove is logged by name only and tried
// again at the next start; it reports whether all went, so STATUS can
// tell the owner (LOG-4).
func removeLearned(dir string) bool {
	ok := true
	if err := sweepTemp(dir); err != nil {
		log.Printf("learn: crash-left temp files not removed: %v", err)
		ok = false
	}
	for _, name := range learnedFiles {
		if err := removeAll(filepath.Join(dir, name)); err != nil {
			log.Printf("learn: old learning state %s not removed: %v", name, err)
			ok = false
		}
	}
	return ok
}

// openLearnState erases the old learning plane's state in dir and wires
// the owner's old settings texts, and STATUS's lines about both, into the
// daemon's configuration.
func openLearnState(dir string, cfg *daemon.Config) {
	erased := true
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("learn directory: %v", err)
		erased = false
	} else {
		erased = removeLearned(dir)
	}
	wireSettings(cfg)
	cfg.Notes = append(cfg.Notes, func() string { return lineIf(!erased, forgetNotErased) })
}

// loopsOffText answers the owner's loop settings texts (LOOPS, LEARNING,
// SECURITY TESTS or UPDATE CHECKS OFF/ON, SPARE BUDGET, HELP LOOPS and
// the rest of loops.ParseText, the UPDATES texts among them): the box
// runs no spare-time work in this version (MIG-4-untrusted-learn; HLD-4).
const loopsOffText = "I don't do spare-time work (learning, self-tests, update checks) in this version, so nothing changes."

// forgetOffText answers FORGET, and renewOffText RENEW: neither runs in
// this version (#2781), and the box keeps no task texts for FORGET to
// list.
const (
	forgetOffText = "I can't forget tasks in this version yet. A later box version adds it."
	renewOffText  = "I don't keep agent memory across tasks in this version, so there is nothing to renew."
)

// wireSettings answers the owner's old settings texts with fixed replies:
// FORGET, RENEW and the old loop settings. All are answered by the box,
// locked or not, never sent to the agent as chat, and change nothing, so
// they run in a locked session.
func wireSettings(cfg *daemon.Config) {
	cfg.Settings = func(ctx context.Context, msg string, unlocked bool) (string, bool) {
		if r, ok := oldSetting(msg); ok {
			return r, true
		}
		if _, ok := loops.ParseText(msg); ok {
			return loopsOffText, true
		}
		return "", false
	}
	cfg.Narrows = func(msg string) bool {
		_, ok := loops.ParseText(msg)
		return ok
	}
}

// ownerWords is msg's words in upper case, letters and digits only, as
// the old FORGET and RENEW parsers read it.
func ownerWords(msg string) []string {
	return strings.Fields(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, strings.ToUpper(msg)))
}

// oldSetting reads the texts the deleted FORGET and RENEW took, so they
// stay settings and never reach the agent as chat: FORGET alone, FORGET
// LAST or FORGET and a list number of at most two digits; RENEW alone or
// with one more word. Longer texts are task chat, as before.
func oldSetting(msg string) (string, bool) {
	f := ownerWords(msg)
	if len(f) == 0 || len(f) > 2 {
		return "", false
	}
	switch f[0] {
	case "FORGET":
		if len(f) == 1 || f[1] == "LAST" {
			return forgetOffText, true
		}
		if _, err := strconv.Atoi(f[1]); err == nil && len(f[1]) <= 2 {
			return forgetOffText, true
		}
	case "RENEW":
		return renewOffText, true
	}
	return "", false
}

// forgetLogFile is the restored copy of the forget log in the forget
// plane's directory, which broker/recovery writes once the log's check
// passes (Layout.ForgetLog); its PendingSuffix marker says the check held
// the restore (W3-forget-b1; security C3).
const forgetLogFile = "forget-log.json"

// restoreHold refuses agentosd's start while dir holds the marker of a
// restore the forget log's check held: its error carries the owner's
// notice (recovery.PendingNotice, the marker's second line) and the
// reason. A marker that does not read holds the start too.
func restoreHold(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, forgetLogFile+".pending"))
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("agentosd: restore on hold: %v", err)
	}
	reason, notice, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if notice == "" {
		notice = "Restore on hold."
	}
	return fmt.Errorf("agentosd: not starting: %s (%s)", strings.TrimSpace(notice), strings.TrimSpace(reason))
}

// retiredExecutor settles an intent for an executor this version no
// longer has (change and loops, deleted with the learning loop): nothing
// runs, so every attempt is not applied, and an open approval (a pending
// LOOPS ON or SPARE BUDGET) or a parked attempt settles on YES or RETRY
// instead of failing with journal.ErrNoExecutor (NL-8). FORGET's and
// recall's executors (RENEW, recall's rollbacks) are retired the same way
// (#2781). The kernel's log replaces the journal.
type retiredExecutor struct{}

func (retiredExecutor) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "retired in this version"}
}

func (r retiredExecutor) Reconcile(ctx context.Context, in journal.Intent, n int) journal.Outcome {
	return r.Execute(ctx, in, n)
}

// registerRetired registers retiredExecutor for the deleted executors.
// Recall's is the daemon's Recall, not a broker executor (its name is
// reserved).
func registerRetired(cfg *daemon.Config) {
	cfg.Recall = retiredExecutor{}
	if cfg.BrokerExecutors == nil {
		cfg.BrokerExecutors = map[string]journal.Executor{}
	}
	for _, name := range []string{change.Executor, loops.Executor, grants.ForgetExecutor} {
		cfg.BrokerExecutors[name] = retiredExecutor{}
	}
}
