package main

// The end-to-end test runs this test binary again in two roles. "unlock" is
// this command with a test pin source; it execs the binary once more as
// "kernel", which is cmd/agentos-kernel's body: its anchor (the TPM counter,
// over the connection on handoff.TPMFD) and proc.RunKernel. Run as root, the
// kernel drops to nobody, and every uid check is the real one.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel/anchor"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// REQ: STO-2, CLK-1, HW-5a

const (
	roleEnv   = "AGENTOS_UNLOCK_ROLE"
	unlockEnv = "AGENTOS_UNLOCK_CFG"
	asKernel  = "as-kernel" // the kernel main's argument from the unlock step
)

func TestMain(m *testing.M) {
	role := os.Getenv(roleEnv)
	if len(os.Args) == 3 && os.Args[1] == asKernel {
		role = "kernel" // the unlock step exec'd this, with an empty environment
	}
	switch role {
	case "":
		os.Exit(m.Run())
	case "unlock":
		var r unlockRole
		if err := json.Unmarshal([]byte(os.Getenv(unlockEnv)), &r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, unlockAndExec(r.Config(), r.pins))
		os.Exit(2)
	case "kernel":
		var cfg kernelRole
		if err := json.Unmarshal([]byte(os.Args[2]), &cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		keys, err := handoff.ReadKeys(os.NewFile(handoff.KeyFD, "keys"))
		var a kernel.Anchor
		if err == nil {
			a, err = anchor.Open(cfg.AnchorDir, keys, os.NewFile(handoff.TPMFD, "tpm"))
		}
		if err == nil {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
			err = proc.RunKernel(ctx, cfg.Main, keys, a)
			stop()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(0)
	}
	os.Exit(3)
}

// kernelRole is the kernel main's configuration: its one argument after
// asKernel, as JSON.
type kernelRole struct {
	Main      proc.MainConfig
	AnchorDir string
}

// unlockRole is the unlock step's command line, and the pins a test source
// gives it.
type unlockRole struct {
	Store, TPM, Exec string
	Kernel           string // the kernel's kernelRole, as JSON: its one argument after asKernel
	UID, GID         int
	PolicyKey        []byte // PKIX
	Anchor           []byte
	Request          string // -recovery-request
}

func (r unlockRole) Config() config {
	c := config{store: r.Store, tpm: r.TPM, exec: r.Exec, uid: r.UID, gid: r.GID, request: r.Request, args: []string{asKernel, r.Kernel}}
	if os.Geteuid() != 0 {
		// A plain user cannot shed its supplementary groups. Every other
		// check of the drop still runs first; as root the real drop runs.
		c.dropTo = func(uid, gid int) error {
			if err := drop(uid, gid); !errors.Is(err, errExtraGroup) {
				return err
			}
			return nil
		}
	}
	return c
}

// extraGroups says whether this process has a supplementary group besides
// its gid.
func extraGroups() bool {
	gs, err := syscall.Getgroups()
	if err != nil {
		panic(err)
	}
	for _, g := range gs {
		if g != os.Getgid() {
			return true
		}
	}
	return false
}

func (r unlockRole) pins(transport.TPM) (*ecdsa.PublicKey, []byte, error) {
	k, err := x509.ParsePKIXPublicKey(r.PolicyKey)
	if err != nil {
		return nil, nil, err
	}
	return k.(*ecdsa.PublicKey), r.Anchor, nil
}

func gen(seed byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)
}

var pcrs = []uint{9, 12}

// rig is a box as enrollment leaves it: a software TPM, a sealed store
// with a tpm slot, the log's counter and the owner's anchors, the anchor's
// head file, and the ids the processes run as.
type rig struct {
	t                  *testing.T
	sw                 *swtpm.TPM
	dir, store, bin    string
	policy             *ecdsa.PrivateKey
	recovery           []byte
	anchor             []byte
	kernelUID, kernelG int
	ownerUID, meterUID int
	keys               handoff.KernelKeys // what the store derives, read through its recovery slot
	request            string             // the unlock step's -recovery-request; "" for none
}

// newRig makes the box; putAnchors false leaves the owner's anchors out of
// the store.
func newRig(t *testing.T, putAnchors bool) *rig {
	t.Helper()
	r := &rig{t: t, sw: swtpm.Start(t)}
	r.reboot()
	r.kernelUID, r.kernelG, r.ownerUID, r.meterUID = os.Getuid(), os.Getgid(), os.Getuid(), os.Getuid()
	if os.Geteuid() == 0 {
		r.kernelUID, r.kernelG, r.meterUID = 65534, 65534, 65533
	}
	// Socket paths must stay short, so not t.TempDir.
	dir, err := os.MkdirTemp("", "unlock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	r.dir = dir
	must(t, os.Chmod(dir, 0o755))
	kdir := filepath.Join(dir, "k")
	must(t, os.Mkdir(kdir, 0o700))
	must(t, os.Chown(kdir, r.kernelUID, r.kernelG))
	r.bin = testBinary(t, dir)

	r.policy, err = tpmseal.NewPolicyKey()
	must(t, err)
	p, err := tpmseal.SignCurrent(r.sw.TPM(), r.policy, pcrs)
	must(t, err)
	rec := make([]byte, seal.RecoveryLen)
	rec[0] = 1
	r.recovery = rec
	r.store = filepath.Join(dir, "store")
	st, err := seal.Create(r.store, seal.Recovery{Key: rec})
	must(t, err)
	defer st.Close()
	_, err = st.AddSlot(seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Policies: []tpmseal.Policy{p}, Host: "Test PC"})
	must(t, err)
	if putAnchors {
		must(t, st.Put(handoff.AnchorsEntry, append(bytes.Clone(gen(1)), gen(2)...)))
	}
	r.anchor, err = st.Anchor()
	must(t, err)
	r.keys.Log, err = st.LogKey()
	must(t, err)
	r.keys.Head, err = st.HeadKey()
	must(t, err)
	r.keys.ClerkRoot, err = st.ClerkRoot()
	must(t, err)
	r.keys.Counter = r.enrollCounter(st)
	return r
}

// enrollCounter defines the log's counter, records it in the store and
// starts the anchor's head file, as agentos-enroll does (STO-2c).
func (r *rig) enrollCounter(st *seal.Store) handoff.Counter {
	t := r.t
	srk, err := tpmseal.Identity(r.sw.TPM())
	must(t, err)
	auth := []byte("0123456789abcdef0123456789abcdef")
	ref, err := tpmseal.DefineCounter(r.sw.TPM(), srk, st.ID(), auth)
	must(t, err)
	b, err := json.Marshal(map[string]any{"ref": json.RawMessage(ref.Marshal()), "auth": auth})
	must(t, err)
	must(t, st.Put(handoff.CounterEntry, b))
	dir := r.anchorDir()
	must(t, os.Mkdir(dir, 0o700))
	c := tpmseal.Counter{TPM: r.sw.TPM(), SRK: srk, Ref: ref, Auth: auth}
	must(t, proc.InitCounterAnchor(dir, r.mainConfig().Log, c, r.keys.Head))
	for _, p := range []string{filepath.Join(dir, "anchor"), dir} {
		must(t, os.Lchown(p, r.kernelUID, r.kernelG))
	}
	return handoff.Counter{SRK: srk, Handle: ref.Handle, Name: ref.Name, Auth: auth}
}

func (r *rig) anchorDir() string { return filepath.Join(r.dir, "k", "anchor") }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// testBinary is this test binary where the kernel's uid can exec it.
func testBinary(t *testing.T, dir string) string {
	self, err := os.Executable()
	must(t, err)
	if os.Geteuid() != 0 {
		return self
	}
	b, err := os.ReadFile(self)
	must(t, err)
	bin := filepath.Join(dir, "bin")
	must(t, os.WriteFile(bin, b, 0o755))
	return bin
}

func (r *rig) role(pk *ecdsa.PublicKey, anchor []byte) unlockRole {
	der, err := x509.MarshalPKIXPublicKey(pk)
	must(r.t, err)
	return unlockRole{Store: r.store, TPM: r.sw.Socket(), Exec: r.bin, UID: r.kernelUID, GID: r.kernelG, PolicyKey: der, Anchor: anchor, Request: r.request}
}

func (r *rig) mainConfig() proc.MainConfig {
	c := proc.MainConfig{
		Log:        filepath.Join(r.dir, "k", "log"),
		KeyDir:     filepath.Join(r.dir, "k", "keys"),
		ContentDir: filepath.Join(r.dir, "k", "content"),
		BackupDir:  filepath.Join(r.dir, "k", "backups"),
		OwnerSock:  filepath.Join(r.dir, "k", "owner.sock"), OwnerUID: r.ownerUID,
		MeterSock: filepath.Join(r.dir, "k", "meter.sock"), MeterUID: r.meterUID,
		Tick: 50 * time.Millisecond,
		Up:   filepath.Join(r.dir, "k", "up"),
	}
	if r.kernelUID != r.ownerUID {
		c.Peers = []int{r.ownerUID, r.meterUID}
	}
	return c
}

// reboot power-cycles the PC into its approved boot path. Each boot needs
// one: an unlock caps the slot until the next (#2977).
func (r *rig) reboot() {
	r.sw.Reboot()
	r.sw.Measure(9, "initrd-A")
	r.sw.Measure(12, "usrhash=aaaa quiet")
}

// boot power-cycles the PC and runs the unlock step, which becomes the
// kernel process.
func (r *rig) boot() (*exec.Cmd, *bytes.Buffer) {
	r.t.Helper()
	r.reboot()
	k, err := json.Marshal(kernelRole{Main: r.mainConfig(), AnchorDir: r.anchorDir()})
	must(r.t, err)
	role := r.role(&r.policy.PublicKey, r.anchor)
	role.Kernel = string(k)
	u, err := json.Marshal(role)
	must(r.t, err)
	cmd := exec.Command(r.bin, "-test.run=^$")
	cmd.Env = append(os.Environ(), roleEnv+"=unlock", unlockEnv+"="+string(u))
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	must(r.t, cmd.Start())
	r.t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd, &out
}

func (r *rig) owner() proc.Owner {
	return proc.Owner{Conn: proc.Conn{Socket: r.mainConfig().OwnerSock, UID: r.kernelUID, Timeout: 5 * time.Second}}
}

// up waits for the owner socket to answer, as the kernel's uid.
func (r *rig) up(cmd *exec.Cmd, out *bytes.Buffer) {
	r.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := r.owner().Status(); err == nil {
			return
		}
		if cmd.ProcessState != nil || time.Now().After(deadline) {
			r.t.Fatalf("the kernel never answered; its output:\n%s", out)
		}
	}
}

// exited waits for a kernel that should refuse to start; one still running
// after the wait fails the test.
func (r *rig) exited(cmd *exec.Cmd) error {
	r.t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		r.t.Fatal("the kernel started")
		return nil
	}
}

func (r *rig) shutdown(cmd *exec.Cmd, out *bytes.Buffer) {
	r.t.Helper()
	must(r.t, cmd.Process.Signal(syscall.SIGTERM))
	if err := cmd.Wait(); err != nil {
		r.t.Fatalf("the kernel's exit: %v; its output:\n%s", err, out)
	}
}

// STO-2, CLK-1, HW-5a, LOG-2: at boot the unlock step opens the store
// through this PC's tpm slot and becomes the kernel process under the
// kernel's own uid, which opens its counter anchor and answers on the owner
// socket. The process holds the store open nowhere, and a second boot reads
// the first boot's log and anchor, so the log key and counter it was handed
// are the store's.
//
// #3138: the store holds an ES256 hardware key beside an Ed25519 one, in
// the versioned entry, and the kernel takes a line raise co-signed by both,
// so the chain neither drops the hardware key nor rewraps it.
func TestTheUnlockStepBecomesTheKernel(t *testing.T) {
	r := newRig(t, true)
	hw := newWebAuthn(t)
	ed := key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))) // gen(1)
	v, err := handoff.EncodeAnchors([]key.PublicKey{hw.Public(), ed.Public()})
	must(t, err)
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	must(t, st.Put(handoff.AnchorsEntry, v))
	st.Close()
	cmd, out := r.boot()
	r.up(cmd, out)
	n, err := r.owner().LineChanges()
	must(t, err)
	what := kernel.LineHash(n, 300)
	if err := r.owner().SetLine(300, key.Approve(ed, what)); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("a raise with one anchor's cosign: got %v, want ErrNeedsCosign", err)
	}
	must(t, r.owner().SetLine(300, key.Approve(hw, what), key.Approve(ed, what)))
	// #2998: once its sockets listen, the kernel marks itself up, as its
	// own uid, for its unit to read when it exits.
	if fi, err := os.Lstat(r.mainConfig().Up); err != nil || !fi.Mode().IsRegular() || fi.Size() != 0 {
		t.Errorf("the kernel did not mark itself up: %v", err)
	}
	if os.Geteuid() == 0 {
		fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", cmd.Process.Pid))
		must(t, err)
		for _, fd := range fds {
			to, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", cmd.Process.Pid, fd.Name()))
			if strings.Contains(to, r.store) || strings.Contains(to, r.sw.Socket()) {
				t.Errorf("the kernel process holds %s open", to)
			}
		}
		env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", cmd.Process.Pid))
		must(t, err)
		if len(env) != 0 {
			t.Errorf("the kernel process inherited an environment: %q", env)
		}
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		must(t, err)
		for _, l := range strings.Split(string(st), "\n") {
			f := strings.Fields(l)
			if len(f) == 5 && (f[0] == "Uid:" || f[0] == "Gid:") && strings.Join(f[1:], " ") != "65534 65534 65534 65534" {
				t.Errorf("the kernel process runs with %s", l)
			}
			if len(f) >= 1 && f[0] == "Groups:" && len(f) > 1 && strings.Join(f[1:], " ") != "65534" {
				t.Errorf("the kernel process keeps %s", l)
			}
			if len(f) == 2 && (f[0] == "CapPrm:" || f[0] == "CapEff:" || f[0] == "CapAmb:" || f[0] == "CapInh:") && strings.Trim(f[1], "0") != "" {
				t.Errorf("the kernel process keeps %s", l)
			}
		}
	}
	must(t, r.owner().Stop())
	r.shutdown(cmd, out)

	cmd, out = r.boot()
	r.up(cmd, out)
	c, err := r.owner().Changes()
	must(t, err)
	if !c.Stopped {
		t.Fatal("the second boot lost the first boot's STOP")
	}
	r.shutdown(cmd, out)
}

// #2905 open point 2 (Mark, cmsg_01R91wiieBzMSvPKFsAJVvuK7gq3jqjc2vQq7vC7kHmrzJ):
// a store enrolled with no owner's anchors starts a setup-only kernel. It
// answers STATUS and the setup step and refuses everything else; it takes
// the owner's two hardware keys exactly once, each signing over this box's
// head key, and then serves normally without a restart. The window stays
// shut on the next boot, and a drive rolled back to before the setup entry
// starts no kernel, so the window never reopens.
func TestASetupOnlyKernelTakesTheOwnersKeysOnce(t *testing.T) {
	r := newRig(t, false)
	cmd, out := r.boot()
	r.up(cmd, out)
	o := r.owner()
	if err := o.Stop(); !errors.Is(err, proc.ErrSetupOnly) {
		t.Fatalf("STOP before setup: got %v, want ErrSetupOnly", err)
	}
	info, err := o.SetupInfo()
	must(t, err)
	box := r.keys.Head.Public().(ed25519.PublicKey)
	if !info.Open || !info.Box.Equal(box) {
		t.Fatalf("setup info %+v, want open over the box's head key", info)
	}
	saved := map[string][]byte{}
	for _, f := range []string{r.mainConfig().Log, filepath.Join(r.anchorDir(), "anchor")} {
		b, err := os.ReadFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		saved[f] = b
	}
	hw1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	hw2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	otherBox := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{13}, 32)).Public().(ed25519.PublicKey)
	unsigned := kernel.SignSetup(box, key.Ed25519Signer(hw1), key.Ed25519Signer(hw2))
	unsigned.Sigs[1] = unsigned.Sigs[0]
	for name, f := range map[string]kernel.FirstAnchors{
		"one key":            kernel.SignSetup(box, key.Ed25519Signer(hw1)),
		"the same key twice": kernel.SignSetup(box, key.Ed25519Signer(hw1), key.Ed25519Signer(hw1)),
		"another box":        kernel.SignSetup(otherBox, key.Ed25519Signer(hw1), key.Ed25519Signer(hw2)),
		"one key unsigned":   unsigned,
	} {
		if err := o.Setup(f); !errors.Is(err, kernel.ErrSetupKeys) {
			t.Errorf("%s: got %v, want ErrSetupKeys", name, err)
		}
	}
	must(t, o.Setup(kernel.SignSetup(box, key.Ed25519Signer(hw1), key.Ed25519Signer(hw2))))
	if info, err := o.SetupInfo(); err != nil || info.Open {
		t.Fatalf("setup info after setup: %+v %v, want closed", info, err)
	}
	if err := o.Setup(kernel.SignSetup(box, key.Ed25519Signer(hw2), key.Ed25519Signer(hw1))); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("a second setup: got %v, want ErrSetupClosed", err)
	}
	must(t, o.Stop()) // the kernel now serves as any other
	r.shutdown(cmd, out)

	cmd, out = r.boot()
	r.up(cmd, out)
	if c, err := r.owner().Changes(); err != nil || !c.Stopped {
		t.Fatalf("the second boot: %v %v, want the first boot's STOP", c, err)
	}
	if err := r.owner().Setup(kernel.SignSetup(box, key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{14}, 32))), key.Ed25519Signer(hw1))); !errors.Is(err, kernel.ErrSetupClosed) {
		t.Fatalf("setup on the second boot: got %v, want ErrSetupClosed", err)
	}
	r.shutdown(cmd, out)

	for f, b := range saved {
		if b == nil {
			must(t, os.Remove(f))
		} else {
			must(t, os.WriteFile(f, b, 0o600))
		}
	}
	cmd, out = r.boot()
	if err := r.exited(cmd); err == nil || !strings.Contains(out.String(), proc.ErrAnchorRolledBack.Error()) {
		t.Fatalf("a kernel started on a drive rolled back to before setup: %v\n%s", err, out)
	}
}

// LOG-2, STO-1: a drive rolled back, log and anchor together, to a copy
// from an earlier boot starts no kernel, since the counter has moved past
// it; the kernel says so and the copy is left as it was.
func TestARolledBackDriveStartsNoKernel(t *testing.T) {
	r := newRig(t, true)
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	files := []string{r.mainConfig().Log, filepath.Join(r.anchorDir(), "anchor")}
	saved := map[string][]byte{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		must(t, err)
		saved[f] = b
	}
	cmd, out = r.boot()
	r.up(cmd, out)
	must(t, r.owner().Stop())
	r.shutdown(cmd, out)
	for f, b := range saved {
		must(t, os.WriteFile(f, b, 0o600))
	}
	must(t, os.Remove(r.mainConfig().Up))
	cmd, out = r.boot()
	if err := r.exited(cmd); err == nil || !strings.Contains(out.String(), proc.ErrAnchorRolledBack.Error()) {
		t.Fatalf("the kernel started on a rolled-back drive: %v\n%s", err, out)
	}
	// #2998: a kernel refused at its start never says it came up, so its
	// unit does not reboot the box into the same refusal.
	if _, err := os.Lstat(r.mainConfig().Up); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused kernel marked itself up: %v", err)
	}
	for f, b := range saved {
		got, err := os.ReadFile(f)
		must(t, err)
		if !bytes.Equal(got, b) {
			t.Errorf("the refused kernel changed %s", f)
		}
	}
}

// STO-2a-b: a log the store's key does not open is never a fresh box. The
// kernel process refuses it, and the log is left as it was.
func TestTheKernelRefusesALogUnderAnotherKey(t *testing.T) {
	r := newRig(t, true)
	other := proc.KernelConfig{
		Log: r.mainConfig().Log, Anchor: &kernel.MemAnchor{}, Key: [32]byte{1},
		Pub: r.keys.Head.Public().(ed25519.PublicKey), Sign: r.keys.Head, Anchors: []key.PublicKey{key.Ed25519(gen(1)), key.Ed25519(gen(2))},
	}
	h, err := proc.OpenKernel(other, time.Now().UnixMilli())
	must(t, err)
	must(t, h.With(func(k *kernel.Kernel) error { return k.Stop(time.Now().UnixMilli()) }))
	h.Close()
	must(t, os.Chown(other.Log, r.kernelUID, r.kernelG))
	before, err := os.ReadFile(other.Log)
	must(t, err)
	cmd, out := r.boot()
	err = cmd.Wait()
	if err == nil || !strings.Contains(out.String(), proc.ErrLogKey.Error()) {
		t.Fatalf("the kernel took a log under another key: %v\n%s", err, out)
	}
	if _, err := os.Lstat(r.mainConfig().Up); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a kernel that refused its log marked itself up: %v", err)
	}
	after, err := os.ReadFile(other.Log)
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("the refused log was changed")
	}
}

// STO-2a-k: without its pins from off the drive, with the wrong anchor, or
// with another policy key, the step unlocks nothing and so execs nothing.
// A store with no owner's anchors is refused too.
func TestTheUnlockStepFailsClosed(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	if err := unlockAndExec(c, storePins(c.store)); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("no pins on the TPM: got %v, want ErrNoPins", err)
	}
	wrong := bytes.Clone(r.anchor)
	wrong[0] ^= 1
	if _, err := unlock(c, r.role(&r.policy.PublicKey, wrong).pins); !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("wrong anchor: got %v, want ErrTampered", err)
	}
	other, err := tpmseal.NewPolicyKey()
	must(t, err)
	if _, err := unlock(c, r.role(&other.PublicKey, r.anchor).pins); !errors.Is(err, seal.ErrNoSlot) {
		t.Fatalf("another policy key: got %v, want ErrNoSlot", err)
	}
	if b, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err != nil {
		t.Fatalf("the right pins: %v", err)
	} else {
		clear(b)
	}
	r.reboot()

	// #2905 open point 2: a store with no owner's anchors yet hands over
	// none, and the kernel starts setup-only; an anchors entry that does
	// not read is refused.
	bare := newRig(t, false)
	bc := bare.role(&bare.policy.PublicKey, bare.anchor)
	b, err := unlock(bc.Config(), bc.pins)
	if err != nil {
		t.Fatalf("no owner's anchors: got %v, want a setup-only hand-off", err)
	}
	pr, pw, err := os.Pipe()
	must(t, err)
	_, err = pw.Write(b)
	must(t, err)
	pw.Close()
	clear(b)
	if k, err := handoff.ReadKeys(pr); err != nil || len(k.Anchors) != 0 {
		t.Fatalf("no owner's anchors: hand-off %v %v, want none", k.Anchors, err)
	}
	st, err := seal.Unlock(bare.store, seal.Recovery{Key: bare.recovery})
	must(t, err)
	must(t, st.Put(handoff.AnchorsEntry, []byte("short")))
	st.Close()
	bare.reboot() // the first unlock capped the slot (#2977)
	if _, err := unlock(bc.Config(), bc.pins); err == nil || !strings.Contains(err.Error(), "hardware keys") {
		t.Fatalf("anchors that do not read: got %v", err)
	}

	// LOG-2: a store with no counter, or one that does not read, hands
	// the kernel nothing, so no kernel starts without its anchor.
	for name, v := range map[string][]byte{"none": nil, "garbled": []byte(`{"ref":{"handle":1},"auth":"YQ=="}`), "no auth": []byte(`{"ref":` + string(tpmseal.CounterRef{Handle: r.keys.Counter.Handle, Name: r.keys.Counter.Name}.Marshal()) + `}`)} {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		if v == nil {
			must(t, st.Delete(handoff.CounterEntry))
		} else {
			must(t, st.Put(handoff.CounterEntry, v))
		}
		st.Close()
		r.reboot()
		if _, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err == nil || !strings.Contains(err.Error(), "counter") {
			t.Errorf("%s counter: got %v", name, err)
		}
	}
}

// REQ: BAK-1
// MIG-4-recovery-e1: the unlock step hands the kernel the store's backup
// recipient, and the kernel it becomes holds it. A store enrolled before
// e1 has none: it hands none and its kernel still starts, saying no backup
// can be taken. An entry that does not read hands nothing.
func TestUnlockHandsTheRecipient(t *testing.T) {
	r := newRig(t, true)
	rcp, err := backup.RecipientFor(r.recovery)
	must(t, err)
	v, err := handoff.EncodeRecipient(rcp.X, rcp.EK)
	must(t, err)
	want, err := handoff.ParseRecipient(v)
	must(t, err)
	put := func(v []byte) {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		if v == nil {
			must(t, st.Delete(handoff.RecipientEntry))
		} else {
			must(t, st.Put(handoff.RecipientEntry, v))
		}
		st.Close()
	}
	handed := func() handoff.KernelKeys {
		t.Helper()
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		b, err := unlock(role.Config(), role.pins)
		must(t, err)
		pr, pw, err := os.Pipe()
		must(t, err)
		_, err = pw.Write(b)
		must(t, err)
		pw.Close()
		clear(b)
		k, err := handoff.ReadKeys(pr)
		must(t, err)
		return k
	}
	put(v)
	if k := handed(); !bytes.Equal(k.Recipient, want) || len(k.Anchors) != 2 {
		t.Fatalf("the hand-off's recipient is not the store's: %x", k.Recipient)
	}
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if strings.Contains(out.String(), proc.ErrNoRecipient.Error()) {
		t.Fatalf("the kernel said it has no recipient:\n%s", out)
	}

	put(nil)
	if k := handed(); k.Recipient != nil || len(k.Anchors) != 2 {
		t.Fatalf("no entry: handed %x", k.Recipient)
	}
	cmd, out = r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if !strings.Contains(out.String(), proc.ErrNoRecipient.Error()) {
		t.Fatalf("a kernel without a recipient did not say so:\n%s", out)
	}

	for name, bad := range map[string][]byte{"untagged": want, "short": v[:len(v)-1]} {
		put(bad)
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		if _, err := unlock(role.Config(), role.pins); err == nil || !strings.Contains(err.Error(), "backup recipient") {
			t.Errorf("%s entry: got %v", name, err)
		}
	}
}

// The kernel never runs as root, and a step that is not root cannot become
// anyone else.
func TestTheDropRefusesRootAndChecksItTook(t *testing.T) {
	for _, ids := range [][2]int{{0, 980}, {980, 0}, {-1, 980}} {
		if err := drop(ids[0], ids[1]); err == nil {
			t.Errorf("drop to %v was allowed", ids)
		}
		if err := unlockAndExec(config{uid: ids[0], gid: ids[1]}, storePins("/nonexistent")); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("unlock for %v went as far as the pins: %v", ids, err)
		}
	}
	if os.Geteuid() != 0 {
		if err := drop(os.Getuid()+1, os.Getgid()); err == nil {
			t.Error("a step that is not root became another uid")
		}
		// A plain user keeps any supplementary groups it has, and cannot
		// drop them, so the step refuses it (CI's runner is in several).
		err := drop(os.Getuid(), os.Getgid())
		if extraGroups() {
			if !errors.Is(err, errExtraGroup) {
				t.Errorf("a plain user with supplementary groups: got %v, want errExtraGroup", err)
			}
		} else if err != nil {
			t.Errorf("already the kernel's ids: %v", err)
		}
	}
}

// STO-2c: the production source reads the policy key and anchor that
// enrollment pinned on this TPM, and unlocks with them; pins of another key
// or anchor for the same store open nothing.
func TestTheProductionPinSourceReadsTheTPM(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	id, err := seal.ReadID(r.store)
	must(t, err)
	srk, err := tpmseal.Identity(r.sw.TPM())
	must(t, err)
	must(t, tpmseal.WritePins(r.sw.TPM(), srk, id, tpmseal.Pins{PolicyKey: &r.policy.PublicKey, Anchor: r.anchor}))
	b, err := unlock(c, storePins(r.store))
	must(t, err)
	want, err := handoff.KernelKeys{Log: r.keys.Log, Head: r.keys.Head, ClerkRoot: r.keys.ClerkRoot, Counter: r.keys.Counter, Anchors: []key.PublicKey{key.Ed25519(gen(1)), key.Ed25519(gen(2))}, Slot: handoff.SlotTPM}.Marshal()
	must(t, err)
	if !bytes.Equal(b, want) {
		t.Fatal("the hand-off is not the store's keys")
	}

	wrong := bytes.Clone(r.anchor)
	wrong[0] ^= 1
	r.reboot()
	must(t, tpmseal.FreePins(r.sw.TPM(), srk, id))
	must(t, tpmseal.WritePins(r.sw.TPM(), srk, id, tpmseal.Pins{PolicyKey: &r.policy.PublicKey, Anchor: wrong}))
	if _, err := unlock(c, storePins(r.store)); !errors.Is(err, seal.ErrTampered) {
		t.Fatalf("pins with another anchor: got %v, want ErrTampered", err)
	}
}

// K6 (#2977), CLK-1: once the unlock step has the store open, it caps the
// slot's boot path, so for the rest of the boot no connection to this TPM
// unseals it. PCRs are the TPM's, not a connection's, so this holds for the
// kernel's on handoff.TPMFD as for this test's (a software TPM serves one
// connection at a time, so it is tried once the kernel has stopped, still in
// the same boot). The next boot unlocks as before.
func TestTheSlotIsLockedAfterUnlock(t *testing.T) {
	r := newRig(t, true)
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	pins := r.role(&r.policy.PublicKey, r.anchor).pins
	b, err := unlock(c, pins)
	must(t, err)
	clear(b)
	if _, err := unlock(c, pins); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Fatalf("a second unlock in the same boot: got %v, want ErrNoPolicy", err)
	}
	tpmOpens := func() error {
		st, err := seal.Unlock(r.store, seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Anchor: r.anchor})
		if err == nil {
			st.Close()
		}
		return err
	}
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if err := tpmOpens(); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Errorf("after the kernel's boot, the tpm slot: got %v, want ErrNoPolicy", err)
	}
	r.reboot()
	must(t, tpmOpens())
}

// A boot path the step cannot cap (here a slot over PCR 16, which locality 0
// can reset) hands the kernel nothing, though the store opened.
func TestAnUncappableSlotUnlocksNothing(t *testing.T) {
	r := newRig(t, true)
	r.sw.Measure(16, "resettable")
	p, err := tpmseal.SignCurrent(r.sw.TPM(), r.policy, []uint{16})
	must(t, err)
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	_, err = st.AddSlot(seal.TPM{TPM: r.sw.TPM(), PolicyKey: &r.policy.PublicKey, Policies: []tpmseal.Policy{p}, Host: "Test PC"})
	must(t, err)
	st.Close()
	c := r.role(&r.policy.PublicKey, r.anchor).Config()
	if b, err := unlock(c, r.role(&r.policy.PublicKey, r.anchor).pins); err == nil || !strings.Contains(err.Error(), "cannot be capped") {
		clear(b)
		t.Fatalf("an uncappable slot: got %v", err)
	}
}

func TestParse(t *testing.T) {
	c, err := parse([]string{"-store", "/s", "-uid", "980", "-gid", "981", "-exec", "/usr/lib/agentos/agentos-kernel", "--", "-log", "/l"}, io.Discard)
	if err != nil || c.uid != 980 || c.gid != 981 || c.tpm != "/dev/tpmrm0" || len(c.args) != 2 || c.args[0] != "-log" {
		t.Fatalf("parse: %+v %v", c, err)
	}
	for _, bad := range [][]string{
		{"-store", "/s", "-uid", "0", "-gid", "981", "-exec", "/k"},
		{"-store", "/s", "-uid", "980", "-gid", "981", "-exec", "k"},
		{"-uid", "980", "-gid", "981", "-exec", "/k"},
	} {
		if _, err := parse(bad, io.Discard); err == nil {
			t.Errorf("parse %q: accepted", bad)
		}
	}
}

// A capability left after the drop is caught: root holds them all, a
// plain user none.
func TestNoCapsSeesCapabilities(t *testing.T) {
	err := noCaps()
	if os.Geteuid() == 0 && err == nil {
		t.Fatal("root's capabilities went unseen")
	}
	if os.Geteuid() != 0 && err != nil {
		t.Fatalf("a plain user: %v", err)
	}
}

// webauthn is a software WebAuthn passkey on box.example: it answers a get()
// for Challenge(msg) as a browser and authenticator would.
type webauthn struct{ p *ecdsa.PrivateKey }

func newWebAuthn(t *testing.T) webauthn {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	return webauthn{p}
}

func (w webauthn) Public() key.PublicKey {
	b, _ := w.p.PublicKey.Bytes()
	pk, _ := key.ES256("box.example", b)
	return pk
}

func (w webauthn) Sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://box.example"})
	rp := sha256.Sum256([]byte("box.example"))
	ad := append(rp[:], 0x05, 0, 0, 0, 0) // UP and UV
	cdh := sha256.Sum256(cd)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	s, _ := ecdsa.SignASN1(rand.Reader, w.p, h[:])
	b, _ := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: s})
	return b
}

// REQ: CH-9, BAK-1
// MIG-4-recovery-f1: the unlock step hands the kernel the store's page
// authority, and the kernel it becomes holds it. A store enrolled before
// f1 has none: it hands none and its kernel still starts, saying it
// certifies no page key. An entry that does not read hands nothing.
func TestUnlockHandsThePageCA(t *testing.T) {
	r := newRig(t, true)
	a, err := pageca.New(pageca.DefaultName, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), nil)
	must(t, err)
	v, err := pageca.Marshal(a)
	must(t, err)
	put := func(v []byte) {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		if v == nil {
			must(t, st.Delete(handoff.PageCAEntry))
		} else {
			must(t, st.Put(handoff.PageCAEntry, v))
		}
		st.Close()
	}
	handed := func() handoff.KernelKeys {
		t.Helper()
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		b, err := unlock(role.Config(), role.pins)
		must(t, err)
		pr, pw, err := os.Pipe()
		must(t, err)
		_, err = pw.Write(b)
		must(t, err)
		pw.Close()
		clear(b)
		k, err := handoff.ReadKeys(pr)
		must(t, err)
		return k
	}
	put(v)
	if k := handed(); !bytes.Equal(k.PageCA, v) || len(k.Anchors) != 2 {
		t.Fatal("the hand-off's page authority is not the store's")
	}
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if strings.Contains(out.String(), proc.ErrNoAuthority.Error()) {
		t.Fatalf("the kernel said it has no page authority:\n%s", out)
	}

	put(nil)
	if k := handed(); k.PageCA != nil || len(k.Anchors) != 2 {
		t.Fatal("no entry: handed an authority")
	}
	cmd, out = r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	if !strings.Contains(out.String(), proc.ErrNoAuthority.Error()) {
		t.Fatalf("a kernel without a page authority did not say so:\n%s", out)
	}

	bad := bytes.Clone(v)
	bad[len(bad)/2] ^= 1
	for name, e := range map[string][]byte{"damaged": bad, "short": v[:len(v)-1], "spaced": append(bytes.Clone(v), ' ')} {
		put(e)
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		if _, err := unlock(role.Config(), role.pins); err == nil || !strings.Contains(err.Error(), "page authority") {
			t.Errorf("%s entry: got %v", name, err)
		}
	}
}

// REQ: HW-15, REC-2
// EDGE-link-core-b: the hand-off names the slot that opened the store, so
// the kernel can cut the edge at a start that is not by this PC's tpm slot
// (§12.2), and carries the store's link key and first edge key. A store
// with neither entry hands none and its kernel still starts; an entry that
// does not read hands nothing.
// Revert mutant: `k.Slot = handoff.SlotPassphrase` set to SlotTPM (the
// passphrase unlock then hands "tpm").
func TestUnlockHandsTheSlot(t *testing.T) {
	r := newRig(t, true)
	phrase := []byte("correct horse battery staple")
	edit := func(f func(st *seal.Store)) {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		f(st)
		st.Close()
	}
	edit(func(st *seal.Store) {
		_, err := st.AddSlot(seal.Passphrase{Phrase: phrase})
		must(t, err)
	})
	handed := func(pass []byte) (handoff.KernelKeys, error) {
		t.Helper()
		r.reboot() // each unlock caps the tpm slot (#2977)
		role := r.role(&r.policy.PublicKey, r.anchor)
		c := role.Config()
		c.passphrase = pass
		b, err := unlock(c, role.pins)
		if err != nil {
			return handoff.KernelKeys{}, err
		}
		pr, pw, err := os.Pipe()
		must(t, err)
		_, err = pw.Write(b)
		must(t, err)
		pw.Close()
		clear(b)
		return handoff.ReadKeys(pr)
	}
	k, err := handed(nil)
	if err != nil || k.Slot != handoff.SlotTPM || k.LinkKey != nil || k.FirstEdge != nil {
		t.Fatalf("a tpm unlock of a store with neither entry: slot %q, link %v, edge %x, %v", k.Slot, k.LinkKey != nil, k.FirstEdge, err)
	}
	if k, err = handed(phrase); err != nil || k.Slot != handoff.SlotPassphrase {
		t.Fatalf("a passphrase unlock: slot %q, %v", k.Slot, err)
	}
	if _, err := handed([]byte("wrong")); !errors.Is(err, seal.ErrWrongFactor) {
		t.Fatalf("a wrong passphrase: got %v", err)
	}

	link := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	edge := gen(8)
	edit(func(st *seal.Store) {
		must(t, st.Put(handoff.LinkKeyEntry, link.Seed()))
		must(t, st.Put(handoff.FirstEdgeEntry, edge))
	})
	for _, pass := range [][]byte{nil, phrase} {
		if k, err := handed(pass); err != nil || !k.LinkKey.Equal(link) || !k.FirstEdge.Equal(edge) {
			t.Fatalf("the store's link keys (passphrase %v): %v", pass != nil, err)
		}
	}
	// The kernel the unlock step becomes starts on them.
	cmd, out := r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)

	for name, e := range map[string]struct {
		entry string
		v     []byte
		says  string
	}{
		"short link key":  {handoff.LinkKeyEntry, link.Seed()[:31], "link key"},
		"whole link key":  {handoff.LinkKeyEntry, link, "link key"},
		"long first edge": {handoff.FirstEdgeEntry, append(bytes.Clone(edge), 0), "first edge"},
	} {
		edit(func(st *seal.Store) {
			must(t, st.Put(handoff.LinkKeyEntry, link.Seed()))
			must(t, st.Put(handoff.FirstEdgeEntry, edge))
			must(t, st.Put(e.entry, e.v))
		})
		if _, err := handed(nil); err == nil || !strings.Contains(err.Error(), e.says) {
			t.Errorf("%s entry: got %v", name, err)
		}
	}
}

// MAIL-keys, D-146, #2995: the unlock step hands the kernel the store's
// clerk root key, and writes the owner's hardware keys for the clerks from
// the store alone: its kernel/anchors entry, or, on a box set up through the
// log, the clerks/anchors entry it copies from the log's first entry at the
// first boot that finds it and reads from then on, even with the log gone.
// A box with neither writes none, and removes an earlier boot's. The
// kernel still starts on a store holding the copy.
// Revert mutants: the st.Put of clerks/anchors dropped (the log-less unlock
// then writes none); clerkAnchors reading the log before the store entry
// (the log-less unlock then writes none).
func TestUnlockWritesTheClerksAnchors(t *testing.T) {
	handed := func(r *rig, path string) handoff.KernelKeys {
		t.Helper()
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		c := role.Config()
		c.clerkAnchors, c.log = path, r.mainConfig().Log
		b, err := unlock(c, role.pins)
		must(t, err)
		pr, pw, err := os.Pipe()
		must(t, err)
		_, err = pw.Write(b)
		must(t, err)
		pw.Close()
		clear(b)
		k, err := handoff.ReadKeys(pr)
		must(t, err)
		return k
	}
	written := func(path string) []key.PublicKey {
		t.Helper()
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		must(t, err)
		fi, err := os.Stat(path)
		must(t, err)
		if fi.Mode().Perm() != 0o644 || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			t.Fatalf("the anchors file is %v, owned by %d", fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid)
		}
		a, err := handoff.ParseAnchors(b)
		must(t, err)
		return a
	}
	root := func(r *rig) [32]byte {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		defer st.Close()
		k, err := st.ClerkRoot()
		must(t, err)
		return k
	}

	// A store with the kernel's anchors: the clerks get those.
	r := newRig(t, true)
	path := filepath.Join(r.dir, "clerks", "anchors")
	k := handed(r, path)
	if k.ClerkRoot == ([32]byte{}) || k.ClerkRoot != root(r) {
		t.Fatal("the hand-off's clerk root key is not the store's")
	}
	if a := written(path); len(a) != 2 || a[0] != key.Ed25519(gen(1)) || a[1] != key.Ed25519(gen(2)) {
		t.Fatalf("the clerks' anchors: %v, want the store's", a)
	}

	// A box set up through the log.
	r = newRig(t, false)
	path = filepath.Join(r.dir, "clerks", "anchors")
	must(t, os.MkdirAll(filepath.Dir(path), 0o755))
	must(t, os.WriteFile(path, []byte("an earlier boot's"), 0o644))
	handed(r, path)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a box with no anchors anywhere left a file: %v", err)
	}
	cmd, out := r.boot()
	r.up(cmd, out)
	box := r.keys.Head.Public().(ed25519.PublicKey)
	hw1 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	hw2 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))
	must(t, r.owner().Setup(kernel.SignSetup(box, key.Ed25519Signer(hw1), key.Ed25519Signer(hw2))))
	r.shutdown(cmd, out)
	want := []key.PublicKey{key.Ed25519(hw1.Public().(ed25519.PublicKey)), key.Ed25519(hw2.Public().(ed25519.PublicKey))}
	if a := written(path); a != nil {
		t.Fatalf("anchors before the boot that reads the log: %v", a)
	}
	handed(r, path)
	if a := written(path); len(a) != 2 || a[0] != want[0] || a[1] != want[1] {
		t.Fatalf("the clerks' anchors after setup: %v, want the log's", a)
	}
	// The kernel the unlock step becomes still starts: it is not handed
	// the clerks' copy, so its log's setup is not anchors twice.
	cmd, out = r.boot()
	r.up(cmd, out)
	r.shutdown(cmd, out)
	// From now on the store's copy is read, whatever the log holds.
	must(t, os.Rename(r.mainConfig().Log, r.mainConfig().Log+".gone"))
	handed(r, path)
	if a := written(path); len(a) != 2 || a[0] != want[0] {
		t.Fatalf("the clerks' anchors with the log gone: %v, want the store's copy", a)
	}
	// A directory others can write gets no file, and the kernel's
	// hand-off is unchanged.
	must(t, os.Chmod(filepath.Dir(path), 0o777))
	if k := handed(r, path); k.ClerkRoot != root(r) {
		t.Fatal("a refused anchors file changed the hand-off")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an anchors file in a directory others can write: %v", err)
	}
}

// REQ: REC-4
// The bits the lost-card step hands on are a card's: the key the store
// takes from them is the one card.StoreRecoveryKey reads from the printed
// card, so the card the page shows opens the store. Revert mutant: another
// HKDF info or length in handoff.StoreRecoveryKey.
func TestStoreRecoveryKeyIsTheCards(t *testing.T) {
	for range 8 {
		var bits [handoff.CardKeyLen]byte
		rand.Read(bits[:])
		got, err := handoff.StoreRecoveryKey(bits[:])
		must(t, err)
		want, err := card.StoreRecoveryKey(card.RecoveryKeyText(bits))
		must(t, err)
		if !bytes.Equal(got, want) || len(got) != seal.RecoveryLen {
			t.Fatalf("handoff's store key %x, the card's %x", got, want)
		}
	}
	for _, n := range []int{0, handoff.CardKeyLen - 1, handoff.CardKeyLen + 1, seal.RecoveryLen} {
		if _, err := handoff.StoreRecoveryKey(make([]byte, n)); err == nil {
			t.Errorf("%d bits read as a card", n)
		}
	}
}

// printed is the store key of the card that prints bits, read back from
// its text as the owner types it.
func printed(t *testing.T, bits []byte) []byte {
	t.Helper()
	if len(bits) != handoff.CardKeyLen {
		t.Fatalf("card bits of %d bytes", len(bits))
	}
	k, err := card.StoreRecoveryKey(card.RecoveryKeyText([handoff.CardKeyLen]byte(bits)))
	must(t, err)
	return k
}

// lostRig is a box whose store holds its recovery key's backup recipient,
// as enrollment since MIG-4-recovery-e1 leaves it, with the unlock step
// reading the owner's lost-card request at r.request.
func lostRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t, true)
	r.request = filepath.Join(r.dir, "recovery-request")
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	defer st.Close()
	must(t, st.Put(handoff.RecipientEntry, recipientEntry(t, r.recovery)))
	return r
}

// recipientEntry is rk's backup recipient in RecipientEntry's form.
func recipientEntry(t *testing.T, rk []byte) []byte {
	t.Helper()
	rcp, err := backup.RecipientFor(rk)
	must(t, err)
	v, err := handoff.EncodeRecipient(rcp.X, rcp.EK)
	must(t, err)
	return v
}

// recipientWire is rk's backup recipient in the hand-off's form.
func recipientWire(t *testing.T, rk []byte) []byte {
	t.Helper()
	w, err := handoff.ParseRecipient(recipientEntry(t, rk))
	must(t, err)
	return w
}

func recipientOf(t *testing.T, rk []byte) string {
	t.Helper()
	rcp, err := backup.RecipientFor(rk)
	must(t, err)
	return rcp.ID()
}

// lostCardApproval is the kernel's lost-card approval for the recipient
// old, a week from now.
func lostCardApproval(old string) handoff.Approval {
	return handoff.Approval{Route: handoff.RouteLost, Old: old, Expires: time.Now().UnixMilli() + handoff.LostApprovalFor}
}

// ask writes a, signed with the store's head key, as the owner's request.
func (r *rig) ask(a handoff.Approval) []byte {
	r.t.Helper()
	b, err := handoff.SignApproval(r.keys.Head, a)
	must(r.t, err)
	must(r.t, os.WriteFile(r.request, b, 0o600))
	return b
}

// unlockOnce reboots the PC and runs the unlock step's unlock, by the
// passphrase if pass is set, and returns what it would hand the kernel and
// what it said on stderr.
func (r *rig) unlockOnce(pass []byte) (handoff.KernelKeys, string, error) {
	r.t.Helper()
	r.reboot()
	role := r.role(&r.policy.PublicKey, r.anchor)
	c := role.Config()
	c.passphrase = pass
	pr, pw, err := os.Pipe()
	must(r.t, err)
	saved := os.Stderr
	os.Stderr = pw
	said := make(chan string)
	go func() { b, _ := io.ReadAll(pr); said <- string(b) }()
	b, err := unlock(c, role.pins)
	os.Stderr = saved
	pw.Close()
	out := <-said
	if err != nil {
		return handoff.KernelKeys{}, out, err
	}
	kr, kw, err := os.Pipe()
	must(r.t, err)
	_, err = kw.Write(b)
	must(r.t, err)
	kw.Close()
	clear(b)
	k, err := handoff.ReadKeys(kr)
	return k, out, err
}

// REQ: REC-4, BAK-1
// MIG-4-recovery-r3, D-201 route B: on a boot that opens the tpm slot, the
// owner's lost-card request, approved by the kernel for the store's current
// recipient, makes a new recovery key: the old key opens nothing, the new
// one opens the store, the store's recipient and the one handed are the new
// key's, and the other slots are kept. The step waits for the store's lock,
// and the request is gone once carried out. The kernel the step becomes
// holds the key for the owner's page until the card is confirmed.
// Revert mutants: lostCard's ReplaceAndPut writing the slot alone (the
// recipient checks fail); takeRequest taking no lock (the wait check fails).
func TestLostCardRequestReplacesAtBoot(t *testing.T) {
	r := lostRig(t)
	slots := func() []seal.SlotInfo {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		defer st.Close()
		return st.Slots()
	}
	before := slots()
	r.ask(lostCardApproval(recipientOf(t, r.recovery)))

	// Another writer holds the store's lock: the step waits for it.
	release, err := lockStore(filepath.Dir(r.store))
	must(t, err)
	type result struct {
		k   handoff.KernelKeys
		out string
		err error
	}
	done := make(chan result, 1)
	go func() { k, out, err := r.unlockOnce(nil); done <- result{k, out, err} }()
	select {
	case <-done:
		t.Fatal("the unlock step did not wait for the store's lock")
	case <-time.After(300 * time.Millisecond):
	}
	release()
	res := <-done
	k := res.k
	if res.err != nil || len(k.NewRecovery) != handoff.CardKeyLen || res.out != "" {
		t.Fatalf("the lost-card unlock: %v, card of %d bytes, stderr %q", res.err, len(k.NewRecovery), res.out)
	}
	// The printed card's key opens the store (#3410).
	next := printed(t, k.NewRecovery)
	if _, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery}); err == nil {
		t.Fatal("the old recovery key still opens the store")
	}
	st, err := seal.Unlock(r.store, seal.Recovery{Key: next})
	must(t, err)
	v, _, err := st.Get(handoff.RecipientEntry)
	must(t, err)
	after := st.Slots()
	st.Close()
	if !bytes.Equal(v, recipientEntry(t, next)) || !bytes.Equal(k.Recipient, recipientWire(t, next)) {
		t.Fatal("the store's or the handed recipient is not the new key's")
	}
	if len(after) != len(before) {
		t.Fatalf("slots %d, were %d", len(after), len(before))
	}
	for i := range after {
		if after[i].Kind != before[i].Kind || after[i].Kind != seal.KindRecovery && after[i].ID != before[i].ID {
			t.Fatalf("slot %d changed: %+v, was %+v", i, after[i], before[i])
		}
	}
	if _, err := os.Lstat(r.request); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the request is still there: %v", err)
	}
	r.recovery = next

	// The whole boot: the kernel holds the key until the card is confirmed.
	r.ask(lostCardApproval(recipientOf(t, r.recovery)))
	cmd, out := r.boot()
	r.up(cmd, out)
	id, err := r.owner().RecoveryCardID()
	must(t, err)
	tap := key.Approve(key.Ed25519Signer(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))), kernel.RecoveryCardHash(id))
	bits, err := r.owner().RecoveryCard(tap)
	if err != nil || len(bits) != handoff.CardKeyLen {
		t.Fatalf("the kernel's card: %v (output %s)", err, out)
	}
	newKey := printed(t, bits)
	if id != recipientOf(t, newKey) {
		t.Fatal("the card's ID is not its recipient's")
	}
	if bytes.Equal(newKey, r.recovery) {
		t.Fatal("the kernel's card is the old one")
	}
	if v, err := r.owner().Backups(); err != nil || v.Recipient != recipientOf(t, newKey) {
		t.Fatalf("the kernel's recipient after the rotation: %+v, %v", v, err)
	}
	must(t, r.owner().RecoveryCardDone())
	if _, err := r.owner().RecoveryCardID(); !errors.Is(err, proc.ErrNoRecoveryCard) {
		t.Fatalf("after the confirm: %v", err)
	}
	r.shutdown(cmd, out)
	st, err = seal.Unlock(r.store, seal.Recovery{Key: newKey})
	must(t, err)
	st.Close()
}

// REQ: REC-4
// A request that is not a lost-card approval for the store's recipient, from
// this store's kernel and still in time, or not a plain file, changes
// nothing: the step says so in one line and the kernel starts with the old
// key and recipient. No request says nothing.
// Revert mutants: the route check dropped (the card-route request
// rotates); the Old check dropped (the stale request rotates); O_NOFOLLOW
// dropped (the link rotates); the one-recovery-slot check weakened to none
// (a store with two recovery slots has one replaced).
func TestLostCardRequestIgnoredUnlessValid(t *testing.T) {
	r := lostRig(t)
	old := recipientOf(t, r.recovery)
	_, other, err := ed25519.GenerateKey(nil)
	must(t, err)
	valid := func() []byte {
		b, err := handoff.SignApproval(r.keys.Head, lostCardApproval(old))
		must(t, err)
		return b
	}
	sign := func(k ed25519.PrivateKey, a handoff.Approval) []byte {
		b, err := handoff.SignApproval(k, a)
		must(t, err)
		return b
	}
	card := lostCardApproval(old)
	card.Route, card.Next, card.Expires = handoff.RouteCard, recipientOf(t, bytes.Repeat([]byte{9}, 32)), time.Now().UnixMilli()+handoff.CardApprovalFor
	expired := lostCardApproval(old)
	expired.Expires = time.Now().UnixMilli() - 1
	stale := lostCardApproval(recipientOf(t, bytes.Repeat([]byte{8}, 32)))
	preE1 := lostCardApproval("")
	forged := valid()
	forged[len(forged)-1] ^= 1
	for name, put := range map[string]func(){
		"card route":   func() { must(t, os.WriteFile(r.request, sign(r.keys.Head, card), 0o600)) },
		"expired":      func() { must(t, os.WriteFile(r.request, sign(r.keys.Head, expired), 0o600)) },
		"stale":        func() { must(t, os.WriteFile(r.request, sign(r.keys.Head, stale), 0o600)) },
		"pre-e1 old":   func() { must(t, os.WriteFile(r.request, sign(r.keys.Head, preE1), 0o600)) },
		"other kernel": func() { must(t, os.WriteFile(r.request, sign(other, lostCardApproval(old)), 0o600)) },
		"forged":       func() { must(t, os.WriteFile(r.request, forged, 0o600)) },
		"oversized":    func() { must(t, os.WriteFile(r.request, append(valid(), make([]byte, maxRequest)...), 0o600)) },
		"symlinked": func() {
			target := filepath.Join(r.dir, "elsewhere")
			must(t, os.WriteFile(target, valid(), 0o600))
			must(t, os.Symlink(target, r.request))
		},
		"fifo":      func() { must(t, syscall.Mkfifo(r.request, 0o600)) },
		"directory": func() { must(t, os.Mkdir(r.request, 0o700)) },
	} {
		os.RemoveAll(r.request)
		put()
		was, err := os.ReadFile(r.store)
		must(t, err)
		k, out, err := r.unlockOnce(nil)
		now, rerr := os.ReadFile(r.store)
		must(t, rerr)
		if err != nil || k.NewRecovery != nil || !bytes.Equal(k.Recipient, recipientWire(t, r.recovery)) || !bytes.Equal(was, now) {
			t.Errorf("%s: %v, new key %v, store changed %v", name, err, k.NewRecovery != nil, !bytes.Equal(was, now))
		}
		if strings.Count(out, "\n") != 1 || !strings.Contains(out, "lost-card request") {
			t.Errorf("%s: stderr %q, want one line on the request", name, out)
		}
	}
	os.RemoveAll(r.request)
	if k, out, err := r.unlockOnce(nil); err != nil || k.NewRecovery != nil || out != "" {
		t.Fatalf("no request: %v, new key %v, stderr %q", err, k.NewRecovery != nil, out)
	}

	// The kernel starts on the old recipient past an expired request.
	must(t, os.WriteFile(r.request, sign(r.keys.Head, expired), 0o600))
	cmd, out := r.boot()
	r.up(cmd, out)
	if v, err := r.owner().Backups(); err != nil || v.Recipient != old {
		t.Fatalf("the kernel's recipient: %+v, %v", v, err)
	}
	if _, err := r.owner().RecoveryCardID(); !errors.Is(err, proc.ErrNoRecoveryCard) {
		t.Fatalf("a kernel with no new key: %v", err)
	}
	r.shutdown(cmd, out)
	if !strings.Contains(out.String(), "lost-card request") {
		t.Fatalf("the boot did not say why it ignored the request:\n%s", out)
	}

	// A store holding two recovery slots, as an interrupted rotation could
	// leave it, is refused whole: replacing one would leave the other old
	// key opening the store.
	two := lostRig(t)
	st, err := seal.Unlock(two.store, seal.Recovery{Key: two.recovery})
	must(t, err)
	_, err = st.AddSlot(seal.Recovery{Key: bytes.Repeat([]byte{7}, seal.RecoveryLen)})
	st.Close()
	must(t, err)
	two.ask(lostCardApproval(recipientOf(t, two.recovery)))
	was, err := os.ReadFile(two.store)
	must(t, err)
	k, said, err := two.unlockOnce(nil)
	now, rerr := os.ReadFile(two.store)
	must(t, rerr)
	if err != nil || k.NewRecovery != nil || !bytes.Equal(k.Recipient, recipientWire(t, two.recovery)) || !bytes.Equal(was, now) {
		t.Errorf("two recovery slots: %v, new key %v, store changed %v", err, k.NewRecovery != nil, !bytes.Equal(was, now))
	}
	if strings.Count(said, "\n") != 1 || !strings.Contains(said, "lost-card request") {
		t.Errorf("two recovery slots: stderr %q, want one line on the request", said)
	}
}

// REQ: REC-4
// The lost-card route runs only on a boot that opened this PC's tpm slot: a
// store opened by a card factor has the card (route A), so a valid request
// is left as it is and the store unchanged.
// Revert mutant: the k.Slot == handoff.SlotTPM condition dropped (the
// passphrase unlock rotates).
func TestLostCardOnlyAfterTPMOpen(t *testing.T) {
	r := lostRig(t)
	phrase := []byte("correct horse battery staple")
	st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
	must(t, err)
	_, err = st.AddSlot(seal.Passphrase{Phrase: phrase})
	must(t, err)
	st.Close()
	b := r.ask(lostCardApproval(recipientOf(t, r.recovery)))
	was, err := os.ReadFile(r.store)
	must(t, err)
	k, out, err := r.unlockOnce(phrase)
	now, rerr := os.ReadFile(r.store)
	must(t, rerr)
	if err != nil || k.Slot != handoff.SlotPassphrase || k.NewRecovery != nil || !bytes.Equal(was, now) || out != "" {
		t.Fatalf("a passphrase unlock: %v, slot %q, new key %v, store changed %v, stderr %q", err, k.Slot, k.NewRecovery != nil, !bytes.Equal(was, now), out)
	}
	if left, err := os.ReadFile(r.request); err != nil || !bytes.Equal(left, b) {
		t.Fatalf("the request was not left for a tpm boot: %v", err)
	}
	if k, _, err := r.unlockOnce(nil); err != nil || len(k.NewRecovery) != handoff.CardKeyLen {
		t.Fatalf("the next tpm boot: %v, new key %v", err, k.NewRecovery != nil)
	}
}

// REQ: CH-4, CLK-1, STO-2
// MIG-4-exit-c2: at each boot the unlock step hands the checker the store's
// code seed, sealed under the checker's clerk key, in a file only root
// reads, so the kernel, which gets the key and not the file, never holds
// the seed, and the kernel's hand-off is unchanged. A store with no seed
// removes an earlier boot's file; a directory others can reach gets none,
// and the kernel still starts.
// Revert mutant: seal under "mail"'s key (the checker then opens nothing).
func TestUnlockHandsTheCheckerItsSeed(t *testing.T) {
	r := newRig(t, true)
	path := filepath.Join(r.dir, "checker-seed", "seed")
	seed := []byte("synthetic-code-seed-01")
	edit := func(f func(st *seal.Store)) {
		st, err := seal.Unlock(r.store, seal.Recovery{Key: r.recovery})
		must(t, err)
		f(st)
		st.Close()
	}
	var root [32]byte
	edit(func(st *seal.Store) {
		v, err := handoff.EncodeCodeSeed(handoff.CodeSeed{Seed: seed, Step: 42})
		must(t, err)
		must(t, st.Put(handoff.CheckerSeedEntry, v))
		root, err = st.ClerkRoot()
		must(t, err)
	})
	handed := func() handoff.KernelKeys {
		t.Helper()
		r.reboot()
		role := r.role(&r.policy.PublicKey, r.anchor)
		c := role.Config()
		c.checkerSeed = path
		b, err := unlock(c, role.pins)
		must(t, err)
		defer clear(b)
		for i := 0; i+8 <= len(seed); i++ {
			if bytes.Contains(b, seed[i:i+8]) {
				t.Fatal("the kernel's hand-off holds the seed")
			}
		}
		pr, pw, err := os.Pipe()
		must(t, err)
		_, err = pw.Write(b)
		must(t, err)
		pw.Close()
		k, err := handoff.ReadKeys(pr)
		must(t, err)
		return k
	}
	if k := handed(); k.ClerkRoot != root {
		t.Fatal("the hand-off's clerk root is not the store's")
	}
	blob, err := os.ReadFile(path)
	must(t, err)
	fi, err := os.Stat(path)
	must(t, err)
	if fi.Mode().Perm() != 0o600 || fi.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		t.Fatalf("the seed file is %v, owned by %d", fi.Mode(), fi.Sys().(*syscall.Stat_t).Uid)
	}
	if bytes.Contains(blob, seed[:8]) {
		t.Fatal("the seed file holds the seed in the clear")
	}
	ck, err := clerkkey.Derive(&root, handoff.CheckerName)
	must(t, err)
	sealer, err := ck.Sealer()
	must(t, err)
	got, err := handoff.OpenCodeSeed(sealer, blob)
	if err != nil || !bytes.Equal(got.Seed, seed) || got.Step != 42 {
		t.Fatalf("the checker's key opens %+v, %v", got, err)
	}
	mk, _ := clerkkey.Derive(&root, "mail")
	ms, _ := mk.Sealer()
	if _, err := handoff.OpenCodeSeed(ms, blob); err == nil {
		t.Fatal("another clerk's key opens the seed")
	}

	// A store with no seed leaves no earlier boot's file.
	edit(func(st *seal.Store) { must(t, st.Delete(handoff.CheckerSeedEntry)) })
	handed()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a store with no seed left a file: %v", err)
	}
	// A directory others can reach gets none, and the kernel still starts.
	edit(func(st *seal.Store) {
		v, _ := handoff.EncodeCodeSeed(handoff.CodeSeed{Seed: seed})
		must(t, st.Put(handoff.CheckerSeedEntry, v))
	})
	must(t, os.Chmod(filepath.Dir(path), 0o755))
	if k := handed(); k.ClerkRoot != root {
		t.Fatal("a refused seed file changed the hand-off")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a seed file in a directory others can read: %v", err)
	}
}
