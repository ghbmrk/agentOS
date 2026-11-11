// Package load replaces the enforcer's running nftables ruleset with a
// compiled one (briefs/ENF.md decision 4). It is the only enforcer package
// that starts a process (broker/daemon/arc2_test.go): it runs `nft -f -`
// with the ruleset on standard input, which nft applies as one
// transaction, so a ruleset that fails to load leaves the previous one in
// force and no window opens between them (P5).
package load

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var ErrLoad = errors.New("load: ruleset refused; the previous one stays")

// ErrNoTable is a listing of a table that is not there: nft exited 1 with
// "Error: No such file or directory" (ENOENT). Every other failure to list
// (EPERM, a deadline, a killed nft, a missing binary) is not it, so the
// table may be there and unread (ENF-l-15).
var ErrNoTable = errors.New("load: table absent")

// Loader runs nft. Bin is the absolute path of the image's nft binary; it
// is never looked up on PATH.
type Loader struct {
	Bin string
}

// Load applies ruleset atomically. The ruleset must flush everything first
// (nft.Compile's always does), so what runs after a load is exactly it.
func (l Loader) Load(ctx context.Context, ruleset string) error {
	if !strings.HasPrefix(ruleset, "flush ruleset\n") {
		return fmt.Errorf("%w: ruleset does not start by flushing", ErrLoad)
	}
	return l.apply(ctx, ruleset)
}

func (l Loader) apply(ctx context.Context, ruleset string) error {
	if !strings.HasPrefix(l.Bin, "/") {
		return fmt.Errorf("%w: nft path %q is not absolute", ErrLoad, l.Bin)
	}
	cmd := exec.CommandContext(ctx, l.Bin, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Env = []string{}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %v: %s", ErrLoad, err, firstLine(stderr.String()))
	}
	return nil
}

// Update applies text, a change to the running ruleset that is not a full
// load: either the byte caps' drop state (nft.Drops), whose first line is
// nft.DropHeader, or the resolver's step (nft.Refresh), every line of
// which adds or deletes elements of the enforcer's table. Like a load it
// is one transaction, so a refused text leaves the ruleset as it was.
func (l Loader) Update(ctx context.Context, text string) error {
	if !strings.HasPrefix(text, dropHeader+"\n") && !elementsOnly(text) {
		return fmt.Errorf("%w: not a byte-cap drop update or an answer refresh", ErrLoad)
	}
	return l.apply(ctx, text)
}

// elementsOnly reports whether text is one or more lines, each adding or
// deleting addresses in one fresh or recent set of the enforcer's table
// and nothing else: a set name answerSet matches, and a list of only the
// characters addresses are written with, so the text changes no rule, set
// or chain, no other set's elements (a deny set such as doh_4, an allow
// set, a byte cap's), and carries no second statement.
func elementsOnly(text string) bool {
	lines, ok := strings.CutSuffix(text, "\n")
	if !ok || lines == "" {
		return false
	}
	for _, ln := range strings.Split(lines, "\n") {
		rest, ok := strings.CutPrefix(ln, "add element inet "+table+" ")
		if !ok {
			rest, ok = strings.CutPrefix(ln, "delete element inet "+table+" ")
		}
		name, el, ok2 := strings.Cut(rest, " { ")
		el, ok3 := strings.CutSuffix(el, " }")
		if !ok || !ok2 || !ok3 || el == "" || !answerSet.MatchString(name) ||
			strings.Trim(el, "0123456789abcdef.:, ") != "" {
			return false
		}
	}
	return true
}

// answerSet matches the names of the fresh and recent sets, the only sets
// an answer refresh changes: nft.AllowSet.Fresh and Recent, each an allow
// set's name (nft.CoreSet, nft.DeviceSet) with "_f" or "_r". This package
// cannot import nft; nft's TestUpdateTakesOnlyElementChanges keeps them
// equal.
var answerSet = regexp.MustCompile(`^(core|d[1-9][0-9]*)_[46]_[fr]$`)

// table is nft.Table, which this package cannot import either; nft's
// TestDropHeaderIsTheLoaders keeps them equal.
const table = "enforcer"

// dropHeader is nft.DropHeader, which this package cannot import (nft's
// tests import it); nft's TestDropHeaderIsTheLoaders keeps them equal.
const dropHeader = "flush chain inet enforcer capd_4"

// QuotaPast reports whether this kernel's nft quota "over N" matches only
// once its count is past N, as Linux's nft_quota does since its fix "match
// correctly when the quota just depleted", rather than once it reaches N,
// as before. The byte caps' drop is loaded from it so it stops the first
// byte past a cap on either (nft.Drop.Past). It loads a probe table, sends
// one 29-byte datagram over loopback through a 29-byte quota, reads
// whether the quota matched, and deletes the table.
func (l Loader) QuotaPast(ctx context.Context) (bool, error) {
	probe := "add table inet " + probeTable + "\ndelete table inet " + probeTable + "\n" +
		"table inet " + probeTable + " {\n\tquota q { over 29 bytes; }\n\tcounter hit { }\n" +
		"\tchain out {\n\t\ttype filter hook output priority filter; policy accept;\n" +
		"\t\tip daddr 127.0.0.1 udp dport 9 quota name \"q\" counter name \"hit\" drop\n\t}\n}\n"
	if err := l.apply(ctx, probe); err != nil {
		return false, err
	}
	defer l.apply(context.WithoutCancel(ctx), "delete table inet "+probeTable+"\n")
	// One datagram from loopback to loopback, never off the box: 20 + 8 +
	// 1 bytes, refused when the quota drops it.
	loop := net.IPv4(127, 0, 0, 1)
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if err != nil {
		return false, fmt.Errorf("load: quota probe: %v", err)
	}
	_, err = c.WriteToUDP([]byte{0}, &net.UDPAddr{IP: loop, Port: 9})
	c.Close()
	// The quota's drop refuses the send (EPERM); any other failure means
	// the datagram never reached the quota, so the probe says nothing.
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false, fmt.Errorf("load: quota probe: %v", err)
	}
	cmd := exec.CommandContext(ctx, l.Bin, "-j", "list", "counter", "inet", probeTable, "hit")
	cmd.Env = []string{}
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("load: quota probe: %v", err)
	}
	var doc struct {
		Nftables []struct {
			Counter *struct{ Packets uint64 } `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return false, fmt.Errorf("load: quota probe: %v", err)
	}
	for _, o := range doc.Nftables {
		if o.Counter != nil {
			return o.Counter.Packets == 0, nil
		}
	}
	return false, errors.New("load: quota probe: no counter")
}

const probeTable = "enforcer_probe"

// List is the table as nft's JSON (`nft -j list table inet <table>`): its
// counters and its sets with their elements' counters, which slice i's
// traffic summaries read (broker/enforcer/traffic). The table name must be
// a plain identifier.
func (l Loader) List(ctx context.Context, table string) ([]byte, error) {
	if !strings.HasPrefix(l.Bin, "/") {
		return nil, fmt.Errorf("load: nft path %q is not absolute", l.Bin)
	}
	if table == "" || strings.TrimLeft(table, "abcdefghijklmnopqrstuvwxyz_") != "" {
		return nil, fmt.Errorf("load: table name %q", table)
	}
	cmd := exec.CommandContext(ctx, l.Bin, "-j", "list", "table", "inet", table)
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		line := firstLine(stderr.String())
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 && strings.HasSuffix(line, "No such file or directory") {
			return nil, fmt.Errorf("load: listing %s: %w: %s", table, ErrNoTable, line)
		}
		return nil, fmt.Errorf("load: listing %s: %v: %s", table, err, line)
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
