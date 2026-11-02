// Package driver is the requalification sandbox's in-image case driver
// (UPD-5r-b2): the program a release ships at /usr/lib/agentos/
// agentos-requal-driver that the host boots under gVisor with the
// release's /usr as its root. It reads cases on its stdin, runs each in
// the release through an Evaluator and writes the output on its stdout
// (package wire). Its only way out is that channel: a model call goes to
// the host, which meters it against the installed release's evaluation
// budget (HLD-2) and may refuse it.
package driver

import (
	"errors"
	"fmt"
	"io"

	"github.com/ghbmrk/agentos/broker/vm/requal/wire"
)

// Models is the host's model channel, as an Evaluator sees it.
type Models interface {
	// Call sends one model request and returns the answer, or an error
	// wrapping ErrRefused when the host refused the call.
	Call(req []byte) ([]byte, error)
}

// Evaluator runs one case's input in the release and returns its output.
// An error ends the case as a case error, never as an answer.
type Evaluator func(input []byte, m Models) ([]byte, error)

// ErrRefused is a model call the host refused (no model channel, or the
// evaluation budget spent).
var ErrRefused = errors.New("driver: model call refused")

// ErrNoEvaluator is a case this release has no evaluator for. The host
// takes the case error as a failed case for a candidate and as a failed
// run for the baseline, so the gate holds (UPD-5r-b1-3).
var ErrNoEvaluator = errors.New("driver: no evaluator for this case")

// Refuse is the evaluator of a release that runs no suite yet: every case
// is ErrNoEvaluator.
func Refuse([]byte, Models) ([]byte, error) { return nil, ErrNoEvaluator }

// maxReason bounds a case error's text.
const maxReason = 1 << 10

// Serve answers cases from r on w until r ends between frames. A frame
// out of turn or a broken channel is an error and ends the driver.
func Serve(r io.Reader, w io.Writer, eval Evaluator) error {
	m := &models{r: r, w: w}
	for {
		kind, body, err := wire.Read(r, wire.MaxBody)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if kind != wire.Case {
			return fmt.Errorf("driver: frame %q out of turn", kind)
		}
		out, err := eval(body, m)
		if m.err != nil {
			return m.err
		}
		if err != nil {
			reason := []byte(err.Error())
			if len(reason) > maxReason {
				reason = reason[:maxReason]
			}
			if err := wire.Write(w, wire.CaseError, reason); err != nil {
				return err
			}
			continue
		}
		if err := wire.Write(w, wire.Answer, out); err != nil {
			return err
		}
	}
}

// models is the model channel over the case channel. A broken channel or
// a frame out of turn is kept in err, and Serve ends on it.
type models struct {
	r   io.Reader
	w   io.Writer
	err error
}

func (m *models) Call(req []byte) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	if err := wire.Write(m.w, wire.ModelCall, req); err != nil {
		m.err = err
		return nil, err
	}
	kind, body, err := wire.Read(m.r, wire.MaxBody)
	switch {
	case err != nil:
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		m.err = err
	case kind == wire.ModelResult:
		return body, nil
	case kind == wire.ModelRefuse:
		return nil, fmt.Errorf("%w: %s", ErrRefused, body)
	default:
		m.err = fmt.Errorf("driver: frame %q out of turn", kind)
	}
	return nil, m.err
}
