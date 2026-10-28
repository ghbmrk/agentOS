package main

// REQ: CLK-1, CLK-2, KRN-2, PLN-2, CLK-7

// Run as root, TestRealMailClerkAsRoot runs this test binary as the real
// process under nobody's uid, so its uid checks are the real ones; CI's root
// step requires that it ran.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/readerwire"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

const roleEnv = "AGENTOS_CLERK_MAIL_TEST_ROLE"

func TestMain(m *testing.M) {
	if os.Getenv(roleEnv) != "clerk" {
		os.Exit(m.Run())
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv(roleEnv+"_ARGS")), &args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, start(args, os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")))
	os.Exit(2)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// shortDir is a directory short enough for a socket's path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cm")
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

var good = []string{
	"-dir", "/var/lib/agentos-mail", "-anchors", "/run/agentos-keeper/anchors",
	"-kernel-sock", "/run/agentos-mail/kernel.sock", "-kernel-uid", "980",
	"-owner-sock", "/run/agentos-mail/owner.sock", "-owner-uid", "0",
	"-planner-sock", "/run/agentos-mail/planner.sock", "-planner-uid", "982",
}

func with(flag, v string) []string {
	a := slices.Clone(good)
	a[slices.Index(a, flag)+1] = v
	return a
}

func TestFlags(t *testing.T) {
	c, err := parse(good, io.Discard)
	if err != nil || c.kernelUID != 980 || c.ownerUID != 0 || c.plannerUID != 982 || c.imapConn != "" {
		t.Fatalf("parse(good) = %+v, %v", c, err)
	}
	if _, err := parse(append(slices.Clone(good), "-imap-conn", "/run/agentos-imapconn/conn.sock"), io.Discard); err != nil {
		t.Fatalf("-imap-conn refused: %v", err)
	}
	bad := map[string][]string{
		"relative dir":      with("-dir", "var/lib/agentos-mail"),
		"no anchors":        with("-anchors", ""),
		"relative socket":   with("-kernel-sock", "kernel.sock"),
		"root kernel":       with("-kernel-uid", "0"),
		"root planner":      with("-planner-uid", "0"),
		"no owner":          with("-owner-uid", "-1"),
		"negative kernel":   with("-kernel-uid", "-5"),
		"kernel is planner": with("-planner-uid", "980"),
		"owner is kernel":   with("-owner-uid", "980"),
		"relative imap":     append(slices.Clone(good), "-imap-conn", "conn.sock"),
		"stray argument":    append(slices.Clone(good), "x"),
	}
	for name, args := range bad {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func testAnchors(t *testing.T) ([]key.PublicKey, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	must(t, err)
	a := []key.PublicKey{key.Ed25519(pub)}
	b, err := handoff.EncodeAnchors(a)
	must(t, err)
	return a, b
}

// anchorsFile writes b as an anchors file in a directory of its own.
func anchorsFile(t *testing.T, b []byte) string {
	t.Helper()
	d := filepath.Join(shortDir(t), "a")
	must(t, os.Mkdir(d, 0o755))
	p := filepath.Join(d, "anchors")
	must(t, os.WriteFile(p, b, 0o644))
	return p
}

func keyPipe(t *testing.T, name string, k [clerkkey.Len]byte) *os.File {
	t.Helper()
	b, err := clerkkey.Marshal(clerkkey.Key{Name: name, Key: k})
	must(t, err)
	r, w, err := os.Pipe()
	must(t, err)
	t.Cleanup(func() { r.Close() })
	_, err = w.Write(b)
	must(t, err)
	w.Close()
	return r
}

// fullPipe holds a hand-off-sized payload, its writer closed.
func fullPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	must(t, err)
	t.Cleanup(func() { r.Close() })
	_, err = w.Write(make([]byte, 90))
	must(t, err)
	w.Close()
	return r
}

func unread(t *testing.T, r *os.File) {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil || len(b) != 90 {
		t.Fatalf("the key was read: %d bytes left, %v", len(b), err)
	}
}

// CLK-1: a clerk refused as root or as a peer's uid takes no key, so the key
// never sits in a process a peer could read.
func TestARefusedClerkLeavesItsKeyUnread(t *testing.T) {
	me := strconv.Itoa(os.Getuid())
	r := fullPipe(t)
	err := start(with("-planner-uid", me), io.Discard, r)
	if err == nil || !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "peer uid") {
		t.Fatalf("got %v, want a root or peer-uid refusal", err)
	}
	unread(t, r)
}

// D-146: the owner's anchors come only from a file that neither the kernel's
// uid nor the clerk's can write; any other refuses before the key is read.
func TestTheAnchorsFileMustBeRootsAlone(t *testing.T) {
	_, b := testAnchors(t)
	me := os.Getuid()
	if a, err := readAnchors(anchorsFile(t, b), me); err != nil || len(a) != 1 {
		t.Fatalf("a good anchors file: %v, %v", a, err)
	}
	if _, err := readAnchors(anchorsFile(t, b), me+1); err == nil {
		t.Error("an anchors file of another uid's read")
	}
	groupWritable := anchorsFile(t, b)
	must(t, os.Chmod(groupWritable, 0o664))
	otherWritable := anchorsFile(t, b)
	must(t, os.Chmod(otherWritable, 0o646))
	openDir := anchorsFile(t, b)
	must(t, os.Chmod(filepath.Dir(openDir), 0o777))
	link := filepath.Join(filepath.Dir(anchorsFile(t, b)), "link")
	must(t, os.Symlink(anchorsFile(t, b), link))
	inDir := filepath.Join(filepath.Dir(anchorsFile(t, b)), "d")
	must(t, os.Mkdir(inDir, 0o755))
	many := make([]byte, 0, 17*ed25519.PublicKeySize)
	for i := range 17 {
		k := make([]byte, ed25519.PublicKeySize)
		k[0] = byte(i + 1)
		many = append(many, k...)
	}
	for name, p := range map[string]string{
		"group-writable": groupWritable, "other-writable": otherWritable, "in an open directory": openDir,
		"a symlink": link, "a directory": inDir, "missing": filepath.Join(filepath.Dir(link), "none"),
		"empty": anchorsFile(t, nil), "damaged": anchorsFile(t, []byte("agentos-anchors/v1\nxx")),
		"too many keys": anchorsFile(t, many), "too long": anchorsFile(t, make([]byte, maxAnchorsFile+1)),
	} {
		if _, err := readAnchors(p, me); err == nil {
			t.Errorf("%s anchors file read", name)
		}
	}
	if os.Getuid() == 0 {
		return
	}
	// Through start, as a uid no peer has: the anchors file refuses, and
	// the key stays unread. guard makes this test process non-dumpable,
	// which nothing here relies on.
	r := fullPipe(t)
	args := with("-anchors", groupWritable)
	args[slices.Index(args, "-owner-uid")+1] = strconv.Itoa(me + 3)
	args[slices.Index(args, "-kernel-uid")+1] = strconv.Itoa(me + 1)
	args[slices.Index(args, "-planner-uid")+1] = strconv.Itoa(me + 2)
	if err := start(args, io.Discard, r); err == nil || !strings.Contains(err.Error(), "anchors") {
		t.Fatalf("got %v, want the anchors file refused", err)
	}
	unread(t, r)
}

// A hand-off of another clerk's key, or none, opens nothing.
func TestTheKeyMustBeTheMailClerks(t *testing.T) {
	a, _ := testAnchors(t)
	c := config{dir: shortDir(t)}
	for name, r := range map[string]*os.File{"the model clerk's": keyPipe(t, "model", [32]byte{1}), "a damaged": fullPipe(t)} {
		if err := serve(context.Background(), c, a, r); !errors.Is(err, clerkkey.ErrKey) {
			t.Errorf("%s key: %v", name, err)
		}
	}
}

// The clerk serves each side on its own socket, each with its own table: the
// owner's status, the planner's listing, and the kernel's calls, checked
// against the file's anchors. A do with no account set up reaches the mail
// clerk itself, which answers no-account.
func TestTheMailClerkServesItsThreeSockets(t *testing.T) {
	anchors, _ := testAnchors(t)
	rd := shortDir(t)
	state := filepath.Join(rd, "s")
	must(t, os.Mkdir(state, 0o700))
	me := os.Getuid()
	c := config{
		dir:        state,
		kernelSock: filepath.Join(rd, "k.sock"), kernelUID: me,
		ownerSock: filepath.Join(rd, "o.sock"), ownerUID: me,
		plannerSock: filepath.Join(rd, "p.sock"), plannerUID: me,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, anchors, keyPipe(t, "mail", [32]byte{7})) }()
	owner := runMailOwner(c.ownerSock, me)
	planner := runMailPlanner(c.plannerSock, me)
	waitUp(t, owner, done)
	if _, err := planner.Listing(); err == nil || !strings.Contains(err.Error(), run.ErrNoMailAccount.Error()) {
		t.Fatalf("the planner's listing with no account: %v", err)
	}
	if err := planner.Call("status", nil, nil); err == nil || !strings.Contains(err.Error(), "no call") {
		t.Fatalf("the owner's status on the planner's socket: %v", err)
	}
	if _, err := runMailPlanner(c.ownerSock, me).Listing(); err == nil || !strings.Contains(err.Error(), "no call") {
		t.Fatalf("the planner's listing on the owner's socket: %v", err)
	}
	if a := kernelCall(t, c.kernelSock); a["outcome"] != "failed" || a["detail"] != run.DNoAccount {
		t.Fatalf("the kernel's do with no account: %v", a)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after its context ended: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not end with its context")
	}
}

func runMailOwner(sock string, uid int) run.MailOwner {
	return run.MailOwner{Conn: proc.Conn{Socket: sock, UID: uid, Timeout: 10 * time.Second}}
}

func runMailPlanner(sock string, uid int) run.MailPlanner {
	return run.MailPlanner{Conn: proc.Conn{Socket: sock, UID: uid, Timeout: 10 * time.Second}}
}

func waitUp(t *testing.T, owner run.MailOwner, done <-chan error) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if _, err := owner.Status(); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("the clerk ended before it served: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the owner's socket never answered")
		}
	}
}

// kernelCall sends the kernel's wire a do with an empty view.
func kernelCall(t *testing.T, sock string) map[string]string {
	t.Helper()
	line, err := kernelAnswer(sock)
	must(t, err)
	var a map[string]string
	must(t, json.Unmarshal(line, &a))
	return a
}

// errNoDial wraps a dial that failed, which is no refusal by the clerk.
var errNoDial = errors.New("no connection to the socket")

// kernelAnswer sends the kernel's wire a do with an empty view and reads the
// answer's line; a socket that closes unanswered gives no bytes and an error.
func kernelAnswer(sock string) ([]byte, error) {
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNoDial, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(`{"op":"do","req":{},"view":{}}` + "\n")); err != nil {
		return nil, err
	}
	return bufio.NewReader(conn).ReadBytes('\n')
}

// D-154 rule 4: the keeper's mail process links no main-side code, and
// nothing that opens the sealed store (only the unlock step does).
func TestTheMailProcessLinksNoMainSideCode(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	must(t, err)
	const b = "github.com/ghbmrk/agentos/broker/"
	for _, dep := range strings.Fields(string(out)) {
		if dep == b+"owner" {
			t.Errorf("the mail clerk's process links the owner channel %s", dep)
		}
		for _, no := range []string{"infer", "guest", "browser", "localui", "localsrv", "modelroute", "tpmseal", "clerk/seal", "owner/kernelsock", "daemon", "voice"} {
			if dep == b+no || strings.HasPrefix(dep, b+no+"/") {
				t.Errorf("the mail clerk's process links %s", dep)
			}
		}
	}
}

// #2937 gap 2: with no -imap-conn the clerk never parses IMAP itself, as
// imapsmtp would on a nil Conn (imapconn.Pipe, in-process): every session
// is refused before any byte is read.
func TestNoIMAPConnParsesNoIMAPInProcess(t *testing.T) {
	conn := imapConn("")
	if conn == nil {
		t.Fatal("no -imap-conn gave a nil Conn, which imapsmtp fills with an in-process parser")
	}
	if c, err := conn(context.Background()); c != nil || !errors.Is(err, errNoIMAPConn) {
		t.Fatalf("a session with no connection process: %v, %v", c, err)
	}
}

// The quarantined read and the world are other rows' (MAIL-reader-sock,
// MAIL-world). Until then no mail is classed and the world is empty, so the
// clerk acts on nothing: both fail closed.
func TestNoReaderClassesNothing(t *testing.T) {
	ask := func(context.Context, string) (string, error) { return "", errNoReader }
	got := inbox.Read(context.Background(), ask, []inbox.Mail{{Raw: []byte("Subject: x\r\n\r\nspam")}})
	if len(got) != 1 || got[0].Class != "" {
		t.Fatalf("a mail classed with no reader: %+v", got)
	}
}

// The reader's flags: both or neither, an absolute path, and a uid of the
// reader's own, never root's.
func TestReaderFlags(t *testing.T) {
	r := func(sock, uid string) []string {
		return append(slices.Clone(good), "-reader-sock", sock, "-reader-uid", uid)
	}
	c, err := parse(r("/run/agentos-reader/reader.sock", "984"), io.Discard)
	if err != nil || c.readerSock != "/run/agentos-reader/reader.sock" || c.readerUID != 984 {
		t.Fatalf("parse = %+v, %v", c, err)
	}
	bad := map[string][]string{
		"relative path":      r("reader.sock", "984"),
		"root":               r("/run/r.sock", "0"),
		"negative":           r("/run/r.sock", "-2"),
		"the kernel's":       r("/run/r.sock", "980"),
		"the planner's":      r("/run/r.sock", "982"),
		"the owner side's":   append(with("-owner-uid", "983"), "-reader-sock", "/run/r.sock", "-reader-uid", "983"),
		"a socket alone":     append(slices.Clone(good), "-reader-sock", "/run/r.sock"),
		"a uid alone":        append(slices.Clone(good), "-reader-uid", "984"),
		"a root uid alone":   append(slices.Clone(good), "-reader-uid", "0"),
		"an empty socket":    r("", "984"),
		"no uid with socket": r("/run/r.sock", "-1"),
	}
	for name, args := range bad {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Without the flags the read fails closed.
	if _, err := reader(config{})(context.Background(), "x"); !errors.Is(err, errNoReader) {
		t.Errorf("no reader: %v", err)
	}
}

// CLK-7: two reads of the same mails over the real frame ask the reader once
// per distinct mail; a failed call is asked again at the next read.
func TestTheReaderIsAskedOncePerMail(t *testing.T) {
	sock := filepath.Join(shortDir(t), "r.sock")
	ln, err := readerwire.Listen(sock, os.Getuid())
	must(t, err)
	defer ln.Close()
	var calls, fails atomic.Int32
	go readerwire.Serve(ln, func(_ context.Context, p string) (string, error) {
		calls.Add(1)
		// The first ask for the third mail gets a reply past the frame's
		// bound: that mail fails, and the reader is not paused.
		if strings.HasSuffix(p, "three") && fails.Add(1) == 1 {
			return strings.Repeat("spam", 20), nil
		}
		return "bulk", nil
	})
	// Built by hand, since parse refuses a root reader and CI runs this as root too.
	ask := reader(config{readerSock: sock, readerUID: os.Getuid()})
	mails := []inbox.Mail{{Raw: []byte("Subject: a\r\n\r\none")}, {Raw: []byte("Subject: b\r\n\r\ntwo")}, {Raw: []byte("Subject: a\r\n\r\none")}, {Raw: []byte("Subject: c\r\n\r\nthree")}}
	got := inbox.Read(context.Background(), ask, mails)
	if n := calls.Load(); n != 3 || got[0].Class != "bulk" || got[2].Class != "bulk" || got[3].Class != "" {
		t.Fatalf("first read: %d calls, classes %q %q %q %q", n, got[0].Class, got[1].Class, got[2].Class, got[3].Class)
	}
	got = inbox.Read(context.Background(), ask, mails)
	if n := calls.Load(); n != 4 || got[3].Class != "bulk" {
		t.Fatalf("second read: %d calls in all, the failed mail classed %q", n, got[3].Class)
	}
	inbox.Read(context.Background(), ask, mails)
	if n := calls.Load(); n != 4 {
		t.Fatalf("third read: %d calls in all", n)
	}
}

// The cache keeps at most its bound, evicting the least recently used, and
// never keeps a failure.
func TestTheCacheEvictsTheLeastRecentlyUsed(t *testing.T) {
	var asked []string
	fail := true
	ask := cache(func(_ context.Context, p string) (string, error) {
		asked = append(asked, p)
		if p == "f" && fail {
			return "", errors.New("down")
		}
		return "r-" + p, nil
	}, 2)
	for _, p := range []string{"a", "b", "a", "c", "a", "b", "f", "f"} {
		ask(context.Background(), p)
	}
	fail = false
	if r, err := ask(context.Background(), "f"); r != "r-f" || err != nil {
		t.Fatalf("f after a failure: %q, %v", r, err)
	}
	// a, b, (a hit), c evicts b, (a hit), b evicts c, f fails twice, f.
	if want := "a b c b f f f"; strings.Join(asked, " ") != want {
		t.Fatalf("asked %q, want %q", strings.Join(asked, " "), want)
	}
}

// The longest prompt inbox.Read sends fits the frame.
func TestPromptFitsTheFrame(t *testing.T) {
	if inbox.MaxPrompt > readerwire.MaxPrompt {
		t.Fatalf("inbox.MaxPrompt %d is past readerwire.MaxPrompt %d", inbox.MaxPrompt, readerwire.MaxPrompt)
	}
}

// As root: the built main runs as nobody, with distinct peers. It serves the
// owner side (root here) and refuses every other peer on the kernel's and the
// planner's sockets, and it is non-dumpable, so its /proc files are root's.
func TestRealMailClerkAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: runs the clerk as nobody")
	}
	base := shortDir(t)
	must(t, os.Chmod(base, 0o755))
	_, ab := testAnchors(t)
	// D-146: the file's owner is checked on its own. In root's own
	// directory, a file the kernel's uid owns is refused.
	theirs := anchorsFile(t, ab)
	must(t, os.Chown(theirs, 65533, 65533))
	if _, err := readAnchors(theirs, 0); err == nil {
		t.Error("an anchors file another uid owns, in root's directory, was read")
	}
	ad := filepath.Join(base, "a")
	must(t, os.Mkdir(ad, 0o755))
	must(t, os.WriteFile(filepath.Join(ad, "anchors"), ab, 0o644))
	state, sockets := filepath.Join(base, "s"), filepath.Join(base, "r")
	for _, d := range []string{state, sockets} {
		must(t, os.Mkdir(d, 0o700))
		must(t, os.Chown(d, 65534, 65534))
	}
	must(t, os.Chmod(sockets, 0o711))
	self, err := os.Executable()
	must(t, err)
	b, err := os.ReadFile(self)
	must(t, err)
	bin := filepath.Join(base, "bin")
	must(t, os.WriteFile(bin, b, 0o755))
	args := []string{
		"-dir", state, "-anchors", filepath.Join(ad, "anchors"),
		"-kernel-sock", filepath.Join(sockets, "k.sock"), "-kernel-uid", "65533",
		"-owner-sock", filepath.Join(sockets, "o.sock"), "-owner-uid", "0",
		"-planner-sock", filepath.Join(sockets, "p.sock"), "-planner-uid", "65532",
	}
	ja, err := json.Marshal(args)
	must(t, err)
	cmd := exec.Command(bin, "-test.run=^$")
	cmd.Env = []string{roleEnv + "=clerk", roleEnv + "_ARGS=" + string(ja)}
	cmd.ExtraFiles = []*os.File{keyPipe(t, "mail", [32]byte{9})}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	logf, err := os.Create(filepath.Join(base, "out"))
	must(t, err)
	defer logf.Close()
	output := func() string { b, _ := os.ReadFile(logf.Name()); return string(b) }
	cmd.Stdout, cmd.Stderr = logf, logf
	must(t, cmd.Start())
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill(); <-exited })
	owner := runMailOwner(filepath.Join(sockets, "o.sock"), 65534)
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := owner.Status(); err == nil {
			break
		}
		select {
		case <-exited:
			t.Fatalf("the clerk exited; its output:\n%s", output())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the owner's socket never answered; output:\n%s", output())
		}
	}
	// Root is neither the kernel's nor the planner's uid: each socket
	// closes on it unanswered (ErrLost). An answered error, such as a
	// socket bound to the owner side's uid answering no-account or "no
	// call", is not a refusal.
	if err := (proc.Conn{Socket: filepath.Join(sockets, "p.sock"), UID: 65534, Timeout: 5 * time.Second}).Call("listing", nil, nil); !errors.Is(err, proc.ErrLost) {
		t.Errorf("the planner's socket did not close on root unanswered: %v", err)
	}
	// The kernel's wire answers a do it accepts (no-account here) and
	// closes on any other call unanswered, so only a do tells the uid
	// binding apart from the call table.
	// A refused peer may see EOF, a reset or a broken pipe: any error
	// after the dial, with no answer byte, is a refusal.
	if a, err := kernelAnswer(filepath.Join(sockets, "k.sock")); len(a) != 0 || err == nil || errors.Is(err, errNoDial) {
		t.Errorf("the kernel's socket answered root's do: %q, %v", a, err)
	}
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
	must(t, err)
	for _, l := range strings.Split(string(st), "\n") {
		if f := strings.Fields(l); len(f) == 5 && (f[0] == "Uid:" || f[0] == "Gid:") && strings.Join(f[1:], " ") != "65534 65534 65534 65534" {
			t.Errorf("the clerk runs with %s", l)
		}
	}
	var pst syscall.Stat_t
	must(t, syscall.Stat(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid), &pst))
	if pst.Uid != 0 {
		t.Errorf("the clerk's /proc files are uid %d's: it is dumpable", pst.Uid)
	}
}
