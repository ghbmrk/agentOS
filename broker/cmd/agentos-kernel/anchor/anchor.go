// Package anchor opens the kernel process's log anchor (LOG-2, STO-1): the
// TPM counter enrollment defined (STO-2c), over the TPM connection the
// unlock step hands the kernel on handoff.TPMFD, with the counter's
// reference and auth value from the hand-off. It is the kernel main's, kept
// apart so the unlock step's end-to-end test runs the same code.
package anchor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/tpmseal"
)

// ErrNoTPM: descriptor TPMFD is not a TPM connection, so there is no
// counter to anchor the log with. MemAnchor would forget every head at a
// restart, so a rolled-back log would pass (LOG-2): the kernel starts nothing.
var ErrNoTPM = errors.New("agentos-kernel: I have no connection to this PC's TPM for my log's counter; I start nothing")

// Open is the counter anchor (proc.CounterAnchor) over the
// counter the hand-off names. It fails closed: a missing, rolled-back or
// forged head file, or a counter the TPM does not answer for, starts
// nothing.
func Open(dir string, keys handoff.KernelKeys, f *os.File) (kernel.Anchor, error) {
	t, err := tpmConn(f)
	if err != nil {
		return nil, err
	}
	c := tpmseal.Counter{
		TPM: t, SRK: keys.Counter.SRK, Auth: keys.Counter.Auth,
		Ref: tpmseal.CounterRef{Handle: keys.Counter.Handle, Name: keys.Counter.Name},
	}
	a, err := proc.OpenCounterAnchor(dir, c, keys.Head)
	if err != nil {
		return nil, fmt.Errorf("agentos-kernel: my log's anchor: %w", err)
	}
	return a, nil
}

// tpmConn is the TPM on f: the kernel's resource manager, a character
// device, or a software TPM's stream socket in tests. Anything else, or a
// closed descriptor, is ErrNoTPM.
func tpmConn(f *os.File) (transport.TPM, error) {
	if f == nil {
		return nil, ErrNoTPM
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return nil, ErrNoTPM
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFCHR:
		return transport.FromReadWriteCloser(f), nil
	case syscall.S_IFSOCK:
		return streamTPM{f}, nil
	}
	return nil, ErrNoTPM
}

// streamTPM sends commands over one stream connection, reading each
// response whole by the size in its header, since a stream may return it in
// parts.
type streamTPM struct{ f *os.File }

const (
	tpmHeader      = 10
	maxTPMResponse = 4096
)

func (s streamTPM) Send(cmd []byte) ([]byte, error) {
	if _, err := s.f.Write(cmd); err != nil {
		return nil, err
	}
	h := make([]byte, tpmHeader)
	if _, err := io.ReadFull(s.f, h); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[2:6])
	if n < tpmHeader || n > maxTPMResponse {
		return nil, errors.New("agentos-kernel: a TPM response of a size no TPM sends")
	}
	b := make([]byte, n)
	copy(b, h)
	if _, err := io.ReadFull(s.f, b[tpmHeader:]); err != nil {
		return nil, err
	}
	return b, nil
}
