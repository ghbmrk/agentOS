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
// load: only the byte caps' drop state (nft.Drops), whose first line is
// nft.DropHeader. Like a load it is one transaction, so a refused text
// leaves the drop as it was.
func (l Loader) Update(ctx context.Context, text string) error {
	if !strings.HasPrefix(text, dropHeader+"\n") {
		return fmt.Errorf("%w: not a byte-cap drop update", ErrLoad)
	}
	return l.apply(ctx, text)
}

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
	c.WriteToUDP([]byte{0}, &net.UDPAddr{IP: loop, Port: 9})
	c.Close()
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
