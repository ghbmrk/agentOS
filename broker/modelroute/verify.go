package modelroute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// VerifyRequest asks the vault process to check a code-generator code for
// the owner channel (egress K7). After is the channel's last accepted step.
// Counted is false for the channel's silent checks of codes in chat (O5),
// which the vault process bounds apart from the rest.
type VerifyRequest struct {
	Code    string `json:"code"`
	After   int64  `json:"after"`
	Counted bool   `json:"counted"`
}

// HeaderPausedUntil carries, on a 429 from the verify socket, when checks
// of that kind resume (RFC 3339).
const HeaderPausedUntil = "Agentos-Paused-Until"

// VerifyFailure says why the vault process did not check a code.
type VerifyFailure int

const (
	VerifyDown   VerifyFailure = iota // not reached, or it failed; nothing was checked
	VerifyLocked                      // the vault is not open
	VerifyPaused                      // too many wrong codes until Until
	VerifyLost                        // sent, but no answer: the code may have been spent
)

// VerifyError is returned when no answer says whether the code matched.
type VerifyError struct {
	Kind  VerifyFailure
	Until time.Time
}

func (e *VerifyError) Error() string {
	return [...]string{"vault process down", "vault locked", "verify paused", "verify answer lost"}[e.Kind]
}

// VerifyResult is the vault process's answer: whether the code matched and
// the step it matched. It never carries the seed.
type VerifyResult struct {
	OK   bool  `json:"ok"`
	Step int64 `json:"step"`
}

// Verifier is the owner channel's high-tier check over the
// vault process's verify socket, so the code-generator seed stays in the
// vault process and agentosd holds none (egress K7).
type Verifier struct{ c *http.Client }

// NewVerifier returns a Verifier for the verify socket at path. The channel
// waits on it while holding its lock, so the timeout is short: a hung vault
// process delays STOP by at most that much.
func NewVerifier(path string) *Verifier {
	return &Verifier{c: &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
		},
		Proxy: nil,
	}}}
}

// VerifyTOTP checks code for the owner channel; agentosd adapts it to
// owner.Verifier. Anything but a well-formed answer is a *VerifyError.
func (v *Verifier) VerifyTOTP(code string, after int64, counted bool) (int64, bool, error) {
	body, _ := json.Marshal(VerifyRequest{Code: code, After: after, Counted: counted})
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/verify"} // over the Unix socket
	resp, err := v.c.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return 0, false, &VerifyError{Kind: VerifyDown}
		}
		return 0, false, &VerifyError{Kind: VerifyLost}
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return 0, false, &VerifyError{Kind: VerifyLocked}
	case http.StatusTooManyRequests:
		until, err := time.Parse(time.RFC3339, resp.Header.Get(HeaderPausedUntil))
		if err != nil {
			until = time.Now().Add(10 * time.Minute)
		}
		return 0, false, &VerifyError{Kind: VerifyPaused, Until: until}
	default:
		return 0, false, &VerifyError{Kind: VerifyDown}
	}
	var res VerifyResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&res); err != nil {
		return 0, false, &VerifyError{Kind: VerifyLost}
	}
	return res.Step, res.OK, nil
}

// ErrVaultLocked means the vault process is up but its vault is not open.
var ErrVaultLocked = errors.New("vault locked")

// RecallKey fetches the recall index's identity key from the vault process
// (recall K5). It fails with ErrVaultLocked until the owner unlocks the
// vault; agentosd retries until then.
func (v *Verifier) RecallKey() ([]byte, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/recall-key"} // over the Unix socket
	resp, err := v.c.Post(u.String(), "application/octet-stream", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return nil, ErrVaultLocked
	default:
		return nil, fmt.Errorf("recall key: vault process answered %s", resp.Status)
	}
	key, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return nil, err
	}
	if len(key) < 16 {
		return nil, errors.New("recall key: too short")
	}
	return key, nil
}

// EnrollResult is the vault process's answer to an enroll: the new
// code-generator seed's otpauth:// link, handed out this once (Security L7
// on the P2-2w plan). It is never logged.
type EnrollResult struct {
	URI string `json:"uri"`
}

// String keeps the link out of logs.
func (EnrollResult) String() string { return "[code-generator enrollment]" }

// EnrollConfirmRequest is the code the owner entered from the new seed
// (ONB-3); the answer is a VerifyResult with only OK set.
type EnrollConfirmRequest struct {
	Code string `json:"code"`
}

// ErrEnrolled means enrollment is sealed: a new seed needs the recovery
// key (REC-3). ErrNoEnrollment means no seed waits for confirmation.
var (
	ErrEnrolled     = errors.New("code generator already enrolled")
	ErrNoEnrollment = errors.New("no enrollment waiting for confirmation")
)

// Enroll asks the vault process for a new code-generator seed, made in
// the vault and returned once as an otpauth:// link for setup's page.
func (v *Verifier) Enroll() (string, error) {
	var res EnrollResult
	if err := v.enrollCall("/enroll", nil, &res); err != nil {
		return "", err
	}
	if res.URI == "" {
		return "", errors.New("enroll: empty answer")
	}
	return res.URI, nil
}

// ConfirmEnroll checks one code from the new seed; a match seals the
// enrollment and makes the seed the owner channel's. A *VerifyError with
// VerifyPaused means too many wrong codes.
func (v *Verifier) ConfirmEnroll(code string) (bool, error) {
	body, _ := json.Marshal(EnrollConfirmRequest{Code: code})
	var res VerifyResult
	if err := v.enrollCall("/enroll/confirm", body, &res); err != nil {
		return false, err
	}
	return res.OK, nil
}

func (v *Verifier) enrollCall(path string, body []byte, res any) error {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: path} // over the Unix socket
	resp, err := v.c.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return ErrVaultLocked
	case http.StatusGone:
		return ErrEnrolled
	case http.StatusConflict:
		return ErrNoEnrollment
	case http.StatusTooManyRequests:
		until, err := time.Parse(time.RFC3339, resp.Header.Get(HeaderPausedUntil))
		if err != nil {
			until = time.Now().Add(10 * time.Minute)
		}
		return &VerifyError{Kind: VerifyPaused, Until: until}
	default:
		return fmt.Errorf("enroll: vault process answered %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(res)
}

// SecondLineState is what the vault process tells agentosd about the
// second line's calling account (egress K13): only whether it waits on
// the owner, never its settings (potency R1 on #139).
type SecondLineState string

const (
	// SecondLineOK: no account, an account waiting for its first
	// registration, or a confirmed one. Nothing for the owner to do.
	SecondLineOK SecondLineState = ""
	// SecondLineConfirm: the first registration recorded a realm the
	// owner has not confirmed, so texts and calls are not signed.
	SecondLineConfirm SecondLineState = "confirm"
	// SecondLineUnreached: no registration reached the vault process
	// within the window after setup.
	SecondLineUnreached SecondLineState = "unreached"
)

// SecondLine asks the vault process for the second line's state. It
// fails with ErrVaultLocked while the vault is locked.
func (v *Verifier) SecondLine(ctx context.Context) (SecondLineState, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/second-line"} // over the Unix socket
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := v.c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return "", ErrVaultLocked
	default:
		return "", fmt.Errorf("second line: vault process answered %s", resp.Status)
	}
	var out struct {
		State SecondLineState `json:"state"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&out); err != nil {
		return "", err
	}
	switch out.State {
	case SecondLineOK, SecondLineConfirm, SecondLineUnreached:
		return out.State, nil
	}
	return "", fmt.Errorf("second line: unknown state %q", out.State)
}

// TextsState is what the vault process tells agentosd about the second
// line's texting account (egress K16): only whether its polls have been
// failing, and which way, never its settings (UX-159-1).
type TextsState string

const (
	// TextsOK: no texting account, or its polls are getting through.
	TextsOK TextsState = ""
	// TextsSignIn: the provider has refused the account's polls for
	// TextsQuiet or longer.
	TextsSignIn TextsState = "signin"
	// TextsUnreached: the provider has not answered the account's polls
	// for TextsQuiet or longer.
	TextsUnreached TextsState = "unreached"
)

// TextsQuiet is how long polls fail before the owner is told.
const TextsQuiet = 5 * time.Minute

// SecondLineTexts asks the vault process for the texting account's
// state. It fails with ErrVaultLocked while the vault is locked.
func (v *Verifier) SecondLineTexts(ctx context.Context) (TextsState, error) {
	u := url.URL{Scheme: "http", Host: "agentos-egress", Path: "/second-line/texts"} // over the Unix socket
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := v.c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusServiceUnavailable:
		return "", ErrVaultLocked
	default:
		return "", fmt.Errorf("second line texts: vault process answered %s", resp.Status)
	}
	var out struct {
		Texts TextsState `json:"texts"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&out); err != nil {
		return "", err
	}
	switch out.Texts {
	case TextsOK, TextsSignIn, TextsUnreached:
		return out.Texts, nil
	}
	return "", fmt.Errorf("second line texts: unknown state %q", out.Texts)
}
