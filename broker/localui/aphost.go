package localui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// ExecHost is the image's APHost (P2-1): it runs nft and systemctl. Each
// run gets its own timeout, so a hung nft or systemctl cannot hold
// APLoader's lock, and with it every bring-up, down and station join
// (DEV-net-h).
type ExecHost struct {
	// NftPath and SystemctlPath default to the binaries on the image's
	// PATH.
	NftPath, SystemctlPath string
	// Timeout bounds each run; zero means DefaultHostTimeout.
	Timeout time.Duration
}

// DefaultHostTimeout bounds one nft or systemctl run. A systemctl restart
// of the exempt unit waits for its oneshot, a few nft calls.
const DefaultHostTimeout = 30 * time.Second

// hostEnv is every host run's whole environment.
var hostEnv = childproc.NewEnv("PATH=/usr/sbin:/usr/bin:/sbin:/bin")

func (h ExecHost) run(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	t := h.Timeout
	if t <= 0 {
		t = DefaultHostTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	var out, errb bytes.Buffer
	o := childproc.Options{Stdout: &out, Stderr: &errb, WaitDelay: time.Second}
	if stdin != "" {
		o.Stdin = strings.NewReader(stdin)
	}
	err := childproc.Command(ctx, hostEnv, o, name, args...).Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("localui: %s %s: %w", name, strings.Join(args, " "), ctx.Err())
	}
	if err != nil {
		// nft and systemctl name no secret in their messages; they help
		// the journal say which step failed.
		return nil, fmt.Errorf("localui: %s %s: %w: %s", name, strings.Join(args, " "), err,
			strings.TrimSpace(firstLine(errb.String())))
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return s
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Nft runs script as one nftables transaction (nft -f -).
func (h ExecHost) Nft(ctx context.Context, script string) error {
	_, err := h.run(ctx, script, or(h.NftPath, "nft"), "-f", "-")
	return err
}

// StartUnit runs systemctl restart, so a oneshot's ExecStart runs even if
// the unit was left active.
func (h ExecHost) StartUnit(ctx context.Context, unit string) error {
	_, err := h.run(ctx, "", or(h.SystemctlPath, "systemctl"), "restart", unit)
	return err
}

// StopUnit runs systemctl stop.
func (h ExecHost) StopUnit(ctx context.Context, unit string) error {
	_, err := h.run(ctx, "", or(h.SystemctlPath, "systemctl"), "stop", unit)
	return err
}

// apDropRe is NftRules' drop line as nft lists it, after trimming; the
// same exact line ap-exempt checks with grep -x.
var apDropRe = regexp.MustCompile(`^iifname "([a-zA-Z0-9_.-]{1,15})" drop$`)

// APTableIface asks nft whether agentos_ap is loaded (nft list tables
// inet, exact line) and, only if it is, which interface its input chain
// drops. It returns "" only for a table nft lists as absent: a failing
// listing, a missing chain or a chain without exactly one drop line is an
// error, never "" (DEV-net-i).
func (h ExecHost) APTableIface(ctx context.Context) (string, error) {
	nft := or(h.NftPath, "nft")
	tables, err := h.run(ctx, "", nft, "list", "tables", "inet")
	if err != nil {
		return "", err
	}
	loaded := false
	for _, l := range strings.Split(string(tables), "\n") {
		if strings.TrimSpace(l) == "table inet agentos_ap" {
			loaded = true
		}
	}
	if !loaded {
		return "", nil
	}
	chain, err := h.run(ctx, "", nft, "list", "chain", "inet", "agentos_ap", "input")
	if err != nil {
		return "", err
	}
	var ifaces []string
	for _, l := range strings.Split(string(chain), "\n") {
		if m := apDropRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			ifaces = append(ifaces, m[1])
		}
	}
	if len(ifaces) != 1 {
		return "", errors.New("localui: agentos_ap's input chain does not drop exactly one interface")
	}
	return ifaces[0], nil
}
