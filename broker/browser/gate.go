package browser

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// MaxLine bounds one driver reply.
const MaxLine = 8 << 20

// MaxDownloadScan bounds how much of a downloaded file the gate reads to scan;
// a larger file is withheld rather than passed unscanned.
const MaxDownloadScan = 50 << 20

// Config starts one executor: one account, one driver process.
type Config struct {
	// Driver is the sandboxed driver's argv; the gate appends
	// --origins <declared...> --workspace <dir>.
	Driver []string
	// Origins are the account's declared origins (CRED-10).
	Origins []string
	// Workspace is the only directory the driver writes to (screenshots,
	// downloads). Created 0700 if missing.
	Workspace string
	// Scrub removes the vault's exact secret values from every output.
	Scrub Scrubber
	// Timeout bounds one driver reply; 0 means 60s. A driver that misses it
	// is stopped.
	Timeout time.Duration
	// Env is the driver's whole environment beyond PATH, HOME and LANG; the
	// broker's own environment is never inherited.
	Env []string
}

// Result is everything an agent can see from one request. Fields the driver
// sends that are not here are dropped.
type Result struct {
	OK                 bool     `json:"ok"`
	Error              string   `json:"error,omitempty"`
	Detail             string   `json:"detail,omitempty"`
	URL                string   `json:"url,omitempty"`
	Title              string   `json:"title,omitempty"`
	Snapshot           string   `json:"snapshot,omitempty"`
	Truncated          bool     `json:"truncated,omitempty"`
	Redactions         int      `json:"redactions,omitempty"`
	PasswordFields     int      `json:"password_fields,omitempty"`
	Path               string   `json:"path,omitempty"`
	Bytes              int64    `json:"bytes,omitempty"`
	RefusedNavigations []string `json:"refused_navigations,omitempty"`
}

// Gate is one running executor behind the protocol gate.
type Gate struct {
	cfg     Config
	origins Origins
	filter  filter
	ws      string

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	lines   chan []byte
	stopped bool
}

// Start launches the driver for one account.
func Start(ctx context.Context, cfg Config) (*Gate, error) {
	origins, err := NewOrigins(cfg.Origins)
	if err != nil {
		return nil, err
	}
	if len(cfg.Driver) == 0 {
		return nil, errors.New("browser: no driver")
	}
	ws, err := filepath.Abs(cfg.Workspace)
	if err != nil || cfg.Workspace == "" {
		return nil, errors.New("browser: no workspace")
	}
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return nil, err
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	args := append(append([]string{}, cfg.Driver[1:]...), "--origins")
	args = append(append(args, cfg.Origins...), "--workspace", ws)
	cmd := exec.CommandContext(ctx, cfg.Driver[0], args...)
	cmd.Env = append([]string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + ws, "LANG=C.UTF-8"}, cfg.Env...)
	cmd.Dir = ws
	cmd.Stderr = nil // driver diagnostics may quote page text; never relayed
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	g := &Gate{cfg: cfg, origins: origins, filter: filter{scrub: cfg.Scrub}, ws: ws,
		cmd: cmd, stdin: stdin, lines: make(chan []byte)}
	go g.read(stdout)
	return g, nil
}

func (g *Gate) read(r io.Reader) {
	defer close(g.lines)
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br)
		if err != nil {
			return
		}
		g.lines <- line
	}
}

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > MaxLine {
			return nil, errors.New("reply too long")
		}
		if err == nil {
			return out, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}

// Close stops the driver and everything it started.
func (g *Gate) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stop()
	return nil
}

func (g *Gate) stop() {
	if g.stopped {
		return
	}
	g.stopped = true
	g.stdin.Close()
	if g.cmd.Process != nil {
		_ = syscall.Kill(-g.cmd.Process.Pid, syscall.SIGKILL)
	}
	go func() {
		for range g.lines {
		}
	}()
	_ = g.cmd.Wait()
}

var stoppedResult = Result{Error: "stopped", Detail: "the browser executor is not running"}

// Do runs one request line from an agent and returns what the agent may see.
func (g *Gate) Do(ctx context.Context, raw []byte) Result {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return stoppedResult
	}
	req, err := Parse(raw)
	if err != nil {
		d, _ := g.filter.text(err.Error())
		return Result{Error: "protocol", Detail: d}
	}
	if req.Verb == "navigate" && !g.origins.Declared(req.URL) {
		return Result{Error: "off_origin", Detail: "not a declared origin; use an uncredentialed context"}
	}
	if req.Verb == "screenshot" {
		// CRED-10: a screenshot of a page with a match is withheld. The gate
		// looks at the page itself first, with the vault's values too.
		snap, ok := g.roundtrip(ctx, Request{Verb: "snapshot"})
		if !ok {
			return snap
		}
		if !snap.OK || snap.Redactions > 0 {
			return Result{Error: "withheld", Detail: "page shows a value the detector matched (CRED-10)",
				RefusedNavigations: snap.RefusedNavigations}
		}
	}
	res, ok := g.roundtrip(ctx, req)
	if !ok || !res.OK {
		return res
	}
	if req.Verb == "download" && res.Path != "" {
		return g.scanDownload(res)
	}
	return res
}

// roundtrip sends one canonical request and filters the reply. ok is false
// when the executor was stopped.
func (g *Gate) roundtrip(ctx context.Context, req Request) (Result, bool) {
	if _, err := g.stdin.Write(append(req.Encode(), '\n')); err != nil {
		g.stop()
		return stoppedResult, false
	}
	t := time.NewTimer(g.cfg.Timeout)
	defer t.Stop()
	var line []byte
	select {
	case l, open := <-g.lines:
		if !open {
			g.stop()
			return stoppedResult, false
		}
		line = l
	case <-t.C:
		g.stop()
		return Result{Error: "timeout", Detail: "the browser did not answer in time; executor stopped"}, false
	case <-ctx.Done():
		g.stop()
		return Result{Error: "timeout", Detail: "request cancelled; executor stopped"}, false
	}
	var res Result
	if err := json.Unmarshal(line, &res); err != nil {
		g.stop()
		return Result{Error: "driver", Detail: "malformed executor reply; executor stopped"}, false
	}
	return g.post(res)
}

var errCode = regexp.MustCompile(`^[A-Za-z_]{1,40}$`)

// post filters one driver reply (CRED-10) and enforces confinement.
func (g *Gate) post(res Result) (Result, bool) {
	if res.URL != "" && res.URL != "about:blank" && !g.origins.Declared(res.URL) {
		// The driver should never end a verb off its origins; if it did,
		// confinement failed and nothing from that page is relayed.
		g.stop()
		return Result{Error: "confinement", Detail: "the executor left its declared origins and was stopped"}, false
	}
	if res.Error != "" && !errCode.MatchString(res.Error) {
		res.Error = "driver"
	}
	if res.Redactions < 0 {
		res.Redactions = 0
	}
	n := 0
	for _, s := range []*string{&res.Detail, &res.URL, &res.Title, &res.Snapshot, &res.Error} {
		var k int
		*s, k = g.filter.text(*s)
		n += k
	}
	for i := range res.RefusedNavigations {
		var k int
		res.RefusedNavigations[i], k = g.filter.text(res.RefusedNavigations[i])
		n += k
	}
	res.Redactions += n
	if len(res.Snapshot) > MaxSnapshot {
		cut := MaxSnapshot
		for cut > 0 && !utf8.RuneStart(res.Snapshot[cut]) {
			cut--
		}
		res.Snapshot = res.Snapshot[:cut] + "\n[snapshot truncated]"
		res.Truncated = true
	}
	if res.Path != "" {
		size, err := g.checkPath(res.Path)
		if err != nil {
			return Result{Error: "driver", Detail: "executor named an invalid output file"}, true
		}
		res.Bytes = size
	} else {
		res.Bytes = 0
	}
	return res, true
}

// checkPath accepts only a flat name of a regular file directly in the
// workspace.
func (g *Gate) checkPath(name string) (int64, error) {
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") || len(name) > 128 {
		return 0, fmt.Errorf("bad name")
	}
	fi, err := os.Lstat(filepath.Join(g.ws, name))
	if err != nil || !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("not a regular file")
	}
	return fi.Size(), nil
}

// scanDownload withholds and removes a downloaded file whose text carries a
// vault value or a detector match. Binary formats are scanned as bytes only.
func (g *Gate) scanDownload(res Result) Result {
	p := filepath.Join(g.ws, res.Path)
	withhold := func(why string) Result {
		_ = os.Remove(p)
		return Result{Error: "withheld", Detail: why, URL: res.URL, Title: res.Title,
			RefusedNavigations: res.RefusedNavigations}
	}
	if res.Bytes > MaxDownloadScan {
		return withhold("downloaded file too large to scan")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return withhold("downloaded file unreadable")
	}
	if _, k := g.filter.text(strings.ToValidUTF8(string(b), "�")); k > 0 {
		return withhold("downloaded file contains a value the detector matched (CRED-10)")
	}
	return res
}
