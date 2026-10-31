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
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

var ErrLoad = errors.New("load: ruleset refused; the previous one stays")

// Loader runs nft. Bin is the absolute path of the image's nft binary; it
// is never looked up on PATH.
type Loader struct {
	Bin string
}

// Load applies ruleset atomically. The ruleset must flush everything first
// (nft.Compile's always does), so what runs after a load is exactly it.
func (l Loader) Load(ctx context.Context, ruleset string) error {
	if !strings.HasPrefix(l.Bin, "/") {
		return fmt.Errorf("%w: nft path %q is not absolute", ErrLoad, l.Bin)
	}
	if !strings.HasPrefix(ruleset, "flush ruleset\n") {
		return fmt.Errorf("%w: ruleset does not start by flushing", ErrLoad)
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
		return nil, fmt.Errorf("load: listing %s: %v: %s", table, err, firstLine(stderr.String()))
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
