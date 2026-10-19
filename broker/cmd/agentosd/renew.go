package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// The owner's RENEW (RECALL-prov-owner, CAP-3). An agent whose reads
// reached the cap gets nothing new from recall until the owner starts
// its memory over. RENEW lists those agents by name (the broker's own
// lineages, never guest text); RENEW n asks to renew one. The ask is the
// broker's recall rollback question, so the gate puts it to the owner as
// an approval request naming the renewal and its cost, and only the
// owner's YES, with the request's texted code, runs it.

const (
	// renewListFor is how long RENEW n picks from the list last sent.
	renewListFor = 10 * time.Minute
	// renewList caps how many agents RENEW lists.
	renewList = 9
	// renewClip caps a name in the list.
	renewClip = 16
)

// Fixed texts.
const (
	renewNone    = "No agent's memory is full."
	renewStale   = "Send RENEW to see which agents' memory is full."
	renewNotOpen = "I can't renew an agent's memory yet: memory is not open."
	renewRefused = "I couldn't ask to renew that agent's memory. Try again."
	renewHelp    = "RENEW: start agent memory over."
	renewUsage   = "Send RENEW to list agents whose memory is full, then RENEW and a number from that list."
)

// renewer is recall's side (recalltool.LateExecutor).
type renewer interface {
	Full() []string
	AskRenew(ctx context.Context, lineage string) error
}

type ownerRenew struct {
	r      renewer
	now    func() time.Time
	mu     sync.Mutex
	list   []string
	listAt time.Time
}

// parseRenew reads RENEW (n 0) or RENEW n; RENEW and one other word
// that is not a list number is n -1, answered with the usage.
func parseRenew(msg string) (n int, ok bool) {
	f := strings.Fields(strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return ' '
	}, strings.ToUpper(msg)))
	if len(f) == 0 || f[0] != "RENEW" || len(f) > 2 {
		return 0, false
	}
	if len(f) == 1 {
		return 0, true
	}
	if v, err := strconv.Atoi(f[1]); err == nil && v > 0 && len(f[1]) <= 2 {
		return v, true
	}
	return -1, true
}

// renewName shows a lineage by its agent's name: letters, digits, - and
// _ only, clipped; anything else reads "agent".
func renewName(lineage string) string {
	name := recalltool.AgentName(lineage)
	if len(name) > renewClip {
		name = name[:renewClip]
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "agent"
		}
	}
	if name == "" {
		return "agent"
	}
	return name
}

// Text answers RENEW (the owner channel's settings hook). In a locked
// session it is not taken, so the channel asks for the unlock (CH-21).
func (o *ownerRenew) Text(ctx context.Context, msg string, unlocked bool) (string, bool) {
	n, ok := parseRenew(msg)
	if !ok || !unlocked {
		return "", false
	}
	if n < 0 {
		return renewUsage, true
	}
	now := o.now()
	o.mu.Lock()
	defer o.mu.Unlock()
	if n == 0 {
		full := o.r.Full()
		if len(full) > renewList {
			full = full[:renewList]
		}
		o.list, o.listAt = full, now
		if len(full) == 0 {
			return renewNone, true
		}
		var b strings.Builder
		b.WriteString("Reply RENEW n to start an agent's memory over; its work since its first read is lost:")
		for i, l := range full {
			fmt.Fprintf(&b, " %d %s", i+1, renewName(l))
		}
		return b.String(), true
	}
	if n > len(o.list) || now.Sub(o.listAt) > renewListFor {
		return renewStale, true
	}
	lineage := o.list[n-1]
	err := o.r.AskRenew(ctx, lineage)
	switch {
	case err == nil:
		// No reply of its own: the request names the renewal and what it
		// costs, and comes before anything is reset, so it is the notice.
		return "", true
	case errors.Is(err, recalltool.ErrNotFull):
		return renewStale, true
	case errors.Is(err, recalltool.ErrNotOpen):
		return renewNotOpen, true
	}
	log.Printf("renew: ask: %v", err)
	return renewRefused, true
}

// wire adds RENEW ahead of the settings already wired, and its HELP line.
func (o *ownerRenew) wire(cfg *daemon.Config) {
	prev := cfg.Settings
	cfg.Settings = func(ctx context.Context, msg string, unlocked bool) (string, bool) {
		if r, ok := o.Text(ctx, msg, unlocked); ok {
			return r, true
		}
		if prev != nil {
			return prev(ctx, msg, unlocked)
		}
		return "", false
	}
	if cfg.HelpExtra != "" {
		cfg.HelpExtra += " "
	}
	cfg.HelpExtra += renewHelp
}
