package localui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

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
	// User is the user hostapd runs as (#1426). As root, hostapd would
	// pass egress's uid-0 broker check and could reach verify.sock, so
	// Start refuses a nil User unless asCaller is set.
	User *APUser
	// asCaller runs hostapd as the caller, with no User: this package's
	// stub tests only. It is unexported so that no other package can opt
	// in to running hostapd as root.
	asCaller bool

	mu  sync.Mutex
	run *apRun
}

// APUser is hostapd's own user. hostapd runs with that uid and gid, no
// supplementary groups, no_new_privs, and NET_ADMIN and NET_RAW as its
// only capabilities (ambient, so they survive the exec as a non-root
// user) and the only ones left in its bounding set.
// It reads hostapd.conf through the group: the loader, which shares the
// group, gives Dir and hostapd.conf to it, so it needs no CAP_CHOWN.
// dnsmasq.conf stays root's.
type APUser struct {
	UID, GID uint32
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
	if u := h.User; u != nil && (u.UID == 0 || u.GID == 0) {
		return errors.New("localui: hostapd must not run as root")
	}
	if h.User == nil && !h.asCaller {
		return errors.New("localui: hostapd has no user of its own")
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
	// hostapd.conf holds the Wi-Fi password (CH-7): root's and hostapd's
	// group's only.
	if err := writeConf(hostapdConf, hc, h.User); err != nil {
		return err
	}
	var hattr *syscall.SysProcAttr
	if u := h.User; u != nil {
		// hostapd's group may enter Dir and read, never create (0710).
		if err := os.Chown(dir, -1, int(u.GID)); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o710); err != nil {
			return err
		}
		hattr = &syscall.SysProcAttr{
			Credential:  &syscall.Credential{Uid: u.UID, Gid: u.GID, Groups: []uint32{}},
			AmbientCaps: apCaps,
		}
	}
	if err := writeConf(dnsmasqConf, dc, nil); err != nil {
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
	hcmd := childproc.Command(context.Background(), hostEnv, childproc.Options{WaitDelay: time.Second, SysProcAttr: hattr},
		or(h.HostapdPath, "hostapd"), hostapdConf)
	out, err := hcmd.StdoutPipe()
	if err != nil {
		return err
	}
	start := hcmd.Start
	if h.User != nil {
		start = func() error { return startConfined(hcmd) }
	}
	if err := start(); err != nil {
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

// apCaps are the only capabilities hostapd keeps (#1426).
var apCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}

// startConfined starts cmd from an OS thread of its own that first sets
// no_new_privs and drops every capability but apCaps from its bounding
// set; the child inherits both. Both are per thread, so the thread is
// never returned to the runtime: when its goroutine ends, the runtime
// ends the thread, or, if it is the process's main thread, wedges it for
// good (runtime.mexit) with no goroutine ever running on it again. Either
// way no later Go code or child runs confined.
// (No parent-death signal is set, which would fire when the thread ends.)
func startConfined(cmd *childproc.Cmd) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked
		if err := confineThread(); err != nil {
			errc <- err
			return
		}
		errc <- cmd.Start()
	}()
	return <-errc
}

func confineThread() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	// The kernel may know more capabilities than this build: read until
	// it refuses the number.
	for c := uintptr(0); ; c++ {
		if _, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, c, 0, 0, 0); err == unix.EINVAL {
			return nil
		} else if err != nil {
			return fmt.Errorf("capability bounding set: %w", err)
		}
		if slices.Contains(apCaps, c) {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			return fmt.Errorf("capability bounding set: drop %d: %w", c, err)
		}
	}
}

// writeConf writes a configuration file afresh, never through a link, mode 0600;
// with u, it then gives the file to u's group to read (0640).
func writeConf(path, conf string, u *APUser) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(conf)
	if err == nil && u != nil {
		err = f.Chown(-1, int(u.GID))
		if err == nil {
			err = f.Chmod(0o640)
		}
	}
	return errors.Join(err, f.Close())
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
