// Package swtpm runs a software TPM (swtpm) for tests: no real hardware in
// CI (P2-4b). Each TPM keeps its state in its own directory, so Reboot is a
// power cycle that keeps the TPM's seeds and resets its PCRs, as a PC
// restart does.
package swtpm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// TPM is one running swtpm.
type TPM struct {
	t   testing.TB
	dir string
	cmd *childproc.Cmd
	tpm transport.TPMCloser
}

// Start runs a fresh TPM for the test. Without swtpm installed the test is
// skipped, unless AGENTOS_REQUIRE_SWTPM is set (CI), where it fails.
func Start(t testing.TB) *TPM {
	t.Helper()
	if _, err := childproc.LookPath("swtpm"); err != nil {
		if os.Getenv("AGENTOS_REQUIRE_SWTPM") != "" {
			t.Fatal("swtpm is required (AGENTOS_REQUIRE_SWTPM) but not installed")
		}
		t.Skip("swtpm not installed")
	}
	// Socket paths must stay short (108 bytes), so not t.TempDir.
	dir, err := os.MkdirTemp("", "swtpm")
	if err != nil {
		t.Fatal(err)
	}
	s := &TPM{t: t, dir: dir}
	t.Cleanup(func() {
		s.stop()
		if t.Failed() {
			if b, err := os.ReadFile(filepath.Join(dir, "log")); err == nil {
				t.Logf("swtpm log:\n%s", b)
			}
		}
		os.RemoveAll(dir)
	})
	s.start()
	return s
}

func (s *TPM) sock() string { return filepath.Join(s.dir, "sock") }

func (s *TPM) start() {
	s.t.Helper()
	os.Remove(s.sock())
	logf, err := os.OpenFile(filepath.Join(s.dir, "log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.t.Fatal(err)
	}
	defer logf.Close()
	s.cmd = command("swtpm", childproc.Options{Stdout: logf, Stderr: logf}, "socket", "--tpm2",
		"--tpmstate", "dir="+s.dir,
		"--server", "type=unixio,path="+s.sock(),
		"--flags", "not-need-init,startup-clear")
	if err := s.cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	// The socket file appears before swtpm listens on it, so wait until a
	// connection is accepted, not merely until the file exists.
	for i := 0; ; i++ {
		if c, err := net.Dial("unix", s.sock()); err == nil {
			c.Close()
			break
		}
		if i == 500 {
			s.t.Fatal("swtpm did not accept connections on its socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tpm, err := linuxudstpm.Open(s.sock())
	if err != nil {
		s.t.Fatal(err)
	}
	s.tpm = tpm
}

func (s *TPM) stop() {
	if s.tpm != nil {
		s.tpm.Close()
		s.tpm = nil
	}
	if s.cmd != nil && s.cmd.Pid() > 0 {
		s.cmd.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { s.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			s.cmd.Kill()
			<-done
		}
		s.cmd = nil
	}
}

// Open returns a new connection to the running TPM, as a process opening
// /dev/tpmrm0 would.
func (s *TPM) Open() (transport.TPMCloser, error) { return linuxudstpm.Open(s.sock()) }

// TPM is the transport to the running TPM.
func (s *TPM) TPM() transport.TPM { return s.tpm }

// Reboot power-cycles the TPM: seeds and NV stay, PCRs reset.
func (s *TPM) Reboot() {
	s.t.Helper()
	s.stop()
	s.start()
}

// Measure extends pcr (SHA-256 bank) with the digest of data, as a boot
// stage measuring the next one.
func (s *TPM) Measure(pcr uint, data string) {
	s.t.Helper()
	d := sha256.Sum256([]byte(data))
	_, err := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256,
			Digest:  d[:],
		}}},
	}.Execute(s.tpm)
	if err != nil {
		s.t.Fatalf("extend PCR %d: %v", pcr, err)
	}
}

// Predict computes in software the value pcr will read after a boot that
// measures each of data in turn from reset: what an updater computes for
// a release before rebooting into it.
func Predict(data ...string) []byte {
	v := make([]byte, sha256.Size)
	for _, d := range data {
		m := sha256.Sum256([]byte(d))
		h := sha256.New()
		h.Write(v)
		h.Write(m[:])
		v = h.Sum(nil)
	}
	return v
}

// ThiefLockReset sends TPM2_DictionaryAttackLockReset with an empty
// lockout password, as someone holding the PC would to reset the PIN
// guess counter. It returns the TPM's answer.
func (s *TPM) ThiefLockReset() error {
	cmd := []byte{
		0x80, 0x02, 0, 0, 0, 27, 0, 0, 0x01, 0x39, // sessions, size, DictionaryAttackLockReset
		0x40, 0, 0, 0x0a, // TPM_RH_LOCKOUT
		0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // password session, empty
	}
	rsp, err := s.tpm.Send(cmd)
	if err != nil {
		return err
	}
	if rc := binary.BigEndian.Uint32(rsp[6:10]); rc != 0 {
		return tpm2.TPMRC(rc)
	}
	return nil
}

func (s *TPM) String() string { return fmt.Sprintf("swtpm(%s)", s.dir) }

// toolPath is all of swtpm's environment (P3-4b-3r-env-r8b).
const toolPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

func command(name string, o childproc.Options, args ...string) *childproc.Cmd {
	return childproc.Command(context.Background(), childproc.NewEnv(toolPath), o, name, args...)
}
