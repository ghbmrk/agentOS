package change

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/ghbmrk/agentos/broker/journal"
)

// These versions are broker policy, never candidate-selected grader code.
// Changing their meaning requires CHG-2 approval and a new version.
const (
	MailSendResultV1 = "mail.send/effect-v1"
	ObservedResultV1 = "broker-effects/v1"
)

var ErrUnsupportedResult = errors.New("change: unsupported observed result")

// ObservedEvaluator returns an envelope made by the replay broker, separately
// from the guest's display reply. A plain Evaluator cannot supply evidence for
// a versioned effect case. Expectations and owner verdicts never enter Probe.
type ObservedEvaluator interface {
	RunObserved(context.Context, Tree, Probe) ([]byte, error)
}

type ObservedEffect struct {
	Fingerprint string        `json:"fingerprint"`
	State       journal.State `json:"state"`
}

type ObservedResult struct {
	Version string           `json:"version"`
	Reply   []byte           `json:"reply"`
	Effects []ObservedEffect `json:"effects"`
}

type effectExpectation struct {
	Version     string `json:"version"`
	Fingerprint string `json:"fingerprint"`
}

// EffectFingerprint binds precisely the fields matched by recorded replay.
// Broker-assigned run/request IDs differ in replay and confer no extra credit.
func EffectFingerprint(in journal.Intent) (string, error) {
	b, err := json.Marshal(struct {
		Account    string         `json:"a"`
		Action     string         `json:"b"`
		Params     map[string]any `json:"c"`
		Recipients []string       `json:"d"`
	}{in.Account, in.Action, in.Params, in.Recipients})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// MailSendExpectation is constructed from a broker-bound intent, not a guest's
// completion text. The production caller must refuse redacted snapshots; this
// does not recover original values or enable pre-redaction replay.
func MailSendExpectation(in journal.Intent) ([]byte, error) {
	_, subject := in.Params["subject"].(string)
	_, body := in.Params["body"].(string)
	if in.Action != "mail.send" || in.Account == "" || in.Account == journal.BrokerAccount || len(in.Recipients) == 0 || len(in.Params) != 2 || !subject || !body {
		return nil, ErrUnsupportedResult
	}
	for _, recipient := range in.Recipients {
		if recipient == "" {
			return nil, ErrUnsupportedResult
		}
	}
	fp, err := EffectFingerprint(in)
	if err != nil {
		return nil, err
	}
	return json.Marshal(effectExpectation{Version: MailSendResultV1, Fingerprint: fp})
}

func strictResult(b []byte, v any) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return false
	}
	return d.Decode(new(any)) == io.EOF
}

// ObservedEffectGrader proves only this exact single-effect contract. For a
// rejected case, an empty trace proves absence of the refused effect, not that
// the task was otherwise useful. Any attempted effect fails that negative case.
// Prose, including a forged observation in Reply, is never interpreted.
func ObservedEffectGrader(c Case, out []byte) bool {
	if !SupportedEffectCase(c) {
		return false
	}
	var want effectExpectation
	var got ObservedResult
	_ = json.Unmarshal(c.Expect, &want) // SupportedEffectCase validated this
	if !strictResult(out, &got) || got.Version != ObservedResultV1 {
		return false
	}
	switch c.Outcome {
	case Accepted:
		return len(got.Effects) == 1 && got.Effects[0].Fingerprint == want.Fingerprint && got.Effects[0].State == journal.Succeeded
	case Rejected:
		return len(got.Effects) == 0
	default:
		return false // correction/artifact contracts require separate qualification
	}
}

// SupportedEffectCase checks a broker-produced expectation before harvesting
// or evaluating it. Empty/unknown contracts never fall back to text grading.
func SupportedEffectCase(c Case) bool {
	if c.Security || c.Class != ClassTask || c.Task == "" || c.ResultFormat != MailSendResultV1 || (c.Outcome != Accepted && c.Outcome != Rejected) {
		return false
	}
	var want effectExpectation
	if !strictResult(c.Expect, &want) || want.Version != MailSendResultV1 {
		return false
	}
	b, err := hex.DecodeString(want.Fingerprint)
	return err == nil && len(b) == sha256.Size
}
