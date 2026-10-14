package localui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// Hostapd is the image's AccessPoint (P2-1): hostapd for the Wi-Fi
// (HostapdConf), dnsmasq for DHCP and DNS (DnsmasqConf), and ip for the
// box's address on the interface. The loader loads the firewall
// (NftRules) through BringUp before Start. Debian's hostapd and dnsmasq
// do this job; agentOS writes only their configuration and supervises
// them, so a dead child fires Exited and the loader brings the access
// point down.
type Hostapd struct {
	// HostapdPath, DnsmasqPath and IPPath default to the binaries on the
	// image's PATH.
	HostapdPath, DnsmasqPath, IPPath string
	// Dir holds the generated configuration while the access point runs;
	// default /run/agentos-ap.
	Dir string
	// Ready bounds the wait for hostapd's AP-ENABLED (default 30 s).
	Ready time.Duration
	// Settle is how long dnsmasq must keep running for Start to count it
	// up (default 1 s): with --keep-in-foreground it stays in the
	// foreground and exits at once on a bad configuration or bind.
	Settle time.Duration
	// StopWait bounds each child's exit after SIGTERM before SIGKILL, and
	// each ip run (default 10 s).
	StopWait time.Duration

	mu  sync.Mutex
	run *apRun
}

type apRun struct {
	cfg      APConfig
	children []*apChild
	exited   chan struct{}
	once     sync.Once
}

type apChild struct {
	cmd  *childproc.Cmd
	done chan struct{}
}

// apStdoutCap bounds the bytes Start reads from hostapd while it waits for
// AP-ENABLED; past it hostapd's output goes unread but drained.
const apStdoutCap = 1 << 20

func (h *Hostapd) dir() string { return or(h.Dir, "/run/agentos-ap") }

func durOr(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// Start writes the configuration, gives the interface the box's address,
// and starts hostapd and then dnsmasq. It returns once hostapd reports
// AP-ENABLED and dnsmasq has settled; on any failure it stops what it
// started and removes the address and the files.
func (h *Hostapd) Start(ctx context.Context, cfg APConfig) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	hc, err := HostapdConf(cfg)
	if err != nil {
		return err
	}
	dc, err := DnsmasqConf(cfg)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run != nil {
		return errors.New("localui: the access point already runs")
	}
	r := &apRun{cfg: cfg, exited: make(chan struct{})}
	if err := h.start(ctx, r, hc, dc); err != nil {
		return errors.Join(err, h.teardown(r))
	}
	h.run = r
	return nil
}

func (h *Hostapd) start(ctx context.Context, r *apRun, hc, dc string) error {
	dir := h.dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	hostapdConf, dnsmasqConf := filepath.Join(dir, "hostapd.conf"), filepath.Join(dir, "dnsmasq.conf")
	// hostapd.conf holds the Wi-Fi password (CH-7).
	if err := os.WriteFile(hostapdConf, []byte(hc), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(dnsmasqConf, []byte(dc), 0o600); err != nil {
		return err
	}
	if err := h.ip(ctx, "addr", "replace", r.cfg.Addr.String(), "dev", r.cfg.Iface); err != nil {
		return err
	}
	if err := h.ip(ctx, "link", "set", r.cfg.Iface, "up"); err != nil {
		return err
	}

	// hostapd: wait for AP-ENABLED on its standard output. Its later lines
	// name client MAC addresses, so they are drained unread, never logged.
	hcmd := childproc.Command(context.Background(), hostEnv, childproc.Options{WaitDelay: time.Second},
		or(h.HostapdPath, "hostapd"), hostapdConf)
	out, err := hcmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := hcmd.Start(); err != nil {
		return fmt.Errorf("localui: hostapd: %w", err)
	}
	enabled := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(io.LimitReader(out, apStdoutCap))
		ok := false
		for sc.Scan() {
			if strings.Contains(sc.Text(), "AP-ENABLED") {
				ok = true
				break
			}
		}
		enabled <- ok
		io.Copy(io.Discard, out)
	}()
	hc0 := h.supervise(r, hcmd)
	select {
	case ok := <-enabled:
		if !ok {
			return errors.New("localui: hostapd exited before the access point was enabled")
		}
	case <-time.After(durOr(h.Ready, 30*time.Second)):
		return errors.New("localui: hostapd did not enable the access point in time")
	case <-ctx.Done():
		return ctx.Err()
	}

	// dnsmasq: in the foreground, no pid file, no lease file and no DHCP
	// log lines (both name client MAC addresses).
	dcmd := childproc.Command(context.Background(), hostEnv, childproc.Options{WaitDelay: time.Second},
		or(h.DnsmasqPath, "dnsmasq"), "--keep-in-foreground", "--conf-file="+dnsmasqConf, "--pid-file=",
		"--leasefile-ro", "--quiet-dhcp", "--quiet-dhcp6", "--quiet-ra")
	if err := dcmd.Start(); err != nil {
		return fmt.Errorf("localui: dnsmasq: %w", err)
	}
	dc0 := h.supervise(r, dcmd)
	select {
	case <-dc0.done:
		return errors.New("localui: dnsmasq exited at start")
	case <-hc0.done:
		return errors.New("localui: hostapd exited at start")
	case <-time.After(durOr(h.Settle, time.Second)):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// supervise records a started child and fires r.exited when it exits.
func (h *Hostapd) supervise(r *apRun, cmd *childproc.Cmd) *apChild {
	c := &apChild{cmd: cmd, done: make(chan struct{})}
	r.children = append(r.children, c)
	go func() {
		cmd.Wait()
		close(c.done)
		r.once.Do(func() { close(r.exited) })
	}()
	return c
}

// Exited is closed when a child of the running access point exits; nil
// (never ready) when none runs.
func (h *Hostapd) Exited() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		return nil
	}
	return h.run.exited
}

// SetPassthrough is not implemented yet (ONB-5): the access point serves
// the page only.
func (h *Hostapd) SetPassthrough(bool, string) error {
	return errors.New("localui: passthrough is not supported by this access point yet")
}

// Stop stops dnsmasq and hostapd, removes the box's address and the
// configuration, and returns nil when no access point runs.
func (h *Hostapd) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.run == nil {
		return nil
	}
	err := h.teardown(h.run)
	h.run = nil
	return err
}

// teardown stops r's children in reverse order, then removes the address
// and the files.
func (h *Hostapd) teardown(r *apRun) error {
	wait := durOr(h.StopWait, 10*time.Second)
	var errs []error
	for i := len(r.children) - 1; i >= 0; i-- {
		c := r.children[i]
		select {
		case <-c.done:
			continue
		default:
		}
		c.cmd.Signal(syscall.SIGTERM)
		select {
		case <-c.done:
		case <-time.After(wait):
			c.cmd.Kill()
			select {
			case <-c.done:
			case <-time.After(wait):
				errs = append(errs, errors.New("localui: an access point child did not exit"))
			}
		}
	}
	if r.cfg.Iface != "" {
		// An error means the address or the interface is gone already.
		h.ip(context.Background(), "addr", "del", r.cfg.Addr.String(), "dev", r.cfg.Iface)
	}
	for _, f := range []string{"hostapd.conf", "dnsmasq.conf"} {
		if err := os.Remove(filepath.Join(h.dir(), f)); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h *Hostapd) ip(ctx context.Context, args ...string) error {
	_, err := ExecHost{Timeout: durOr(h.StopWait, 10*time.Second)}.run(ctx, "", or(h.IPPath, "ip"), args...)
	return err
}
