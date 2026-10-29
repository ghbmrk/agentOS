package localui

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// The Owner Card confirm's hand-off to the keeper (HW-1, STO-2; brief
// OWN-card-flow decision 5): the page sends the shown card's passphrase and
// recovery key, as the card prints them, with the fingerprint it printed, to
// agentos-keeper-setup.socket. Root's one-shot (agentos-enroll -take-factors)
// writes them where enrollment reads them and answers one word.

// KeeperSetupSock is the keeper's hand-off socket on the image.
const KeeperSetupSock = "/run/agentos-keeper/setup.sock"

// The keeper's answers (agentos-enroll takeWord).
const (
	KeeperOK        = "ok"
	KeeperBad       = "bad"
	KeeperAuthority = "authority"
	KeeperTaken     = "taken"
	KeeperKept      = "kept"
)

// CardKeeper hands a confirmed card's factors to the keeper and returns
// its word. An error is a request not sent, or one whose answer was lost.
type CardKeeper interface {
	Hand(ctx context.Context, c *card.Card, fingerprint string) (string, error)
}

// KeeperSetup is the hand-off over the keeper's socket. Only a socket
// whose peer is UID (root on the image: PID 1 listens for the one-shot) is
// spoken to.
type KeeperSetup struct {
	Socket string
	UID    int
}

// keeperSetupFor bounds one hand-off: with a store in place the keeper
// stretches the passphrase to try it.
const keeperSetupFor = time.Minute

// maxKeeperWord bounds the keeper's answer.
const maxKeeperWord = 64

var (
	errKeeperUnreachable = errors.New("localui: the keeper's hand-off socket did not answer")
	errKeeperRequest     = errors.New("localui: the card's text cannot go in the keeper's request")
)

// Hand sends one request and returns the keeper's word, without its
// newline. The request is built in one slice, cleared after.
func (k KeeperSetup) Hand(ctx context.Context, c *card.Card, fingerprint string) (string, error) {
	req, err := keeperSetupRequest(c, fingerprint)
	defer clear(req)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, keeperSetupFor)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", k.Socket)
	if err != nil {
		return "", errKeeperUnreachable
	}
	defer conn.Close()
	if uid, ok := sockets.PeerUID(conn); !ok || uid != k.UID {
		return "", errKeeperUnreachable
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if _, err := conn.Write(req); err != nil {
		return "", errKeeperUnreachable
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); !ok || cw.CloseWrite() != nil {
		return "", errKeeperUnreachable
	}
	line, err := bufio.NewReader(io.LimitReader(conn, maxKeeperWord)).ReadString('\n')
	if err != nil {
		return "", errKeeperUnreachable
	}
	return strings.TrimSuffix(line, "\n"), nil
}

// keeperSetupRequest is -take-factors' request,
// {"v":1,"passphrase":…,"recovery_key":…,"fingerprint":…}, appended
// straight in. The keeper refuses any JSON escape, and the card prints no
// character that needs one, so a value holding one is refused here.
func keeperSetupRequest(c *card.Card, fingerprint string) ([]byte, error) {
	for _, v := range []string{c.VaultPassphrase, c.RecoveryKey, fingerprint} {
		if v == "" || strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == '"' || r == '\\' || r >= 0x7f }) {
			return nil, errKeeperRequest
		}
	}
	b := make([]byte, 0, 96+len(c.VaultPassphrase)+len(c.RecoveryKey)+len(fingerprint))
	b = append(b, `{"v":1,"passphrase":"`...)
	b = append(b, c.VaultPassphrase...)
	b = append(b, `","recovery_key":"`...)
	b = append(b, c.RecoveryKey...)
	b = append(b, `","fingerprint":"`...)
	b = append(b, fingerprint...)
	return append(b, `"}`...), nil
}

// The page's fixed lines for the keeper's refusals (decision 10). An
// authority refusal says firstboot.ErrNoAuthority's line, and kept is
// firstboot.ErrKept.
const (
	keeperUnreachableLine = "I couldn't save your Owner Card's keys. Wait a minute and confirm again."
	keeperTakenLine       = "I couldn't save this Owner Card's keys, because I already hold another card's. Restart me and open this page again, and I will make you a new card."
	keeperBadLine         = "I couldn't save your Owner Card's keys. Restart me and open this page again. If you see this again, tell me in a text."
)

// handOff gives the keeper the confirmed card's factors (decision 9: before
// the vault). nil is ok; firstboot.ErrKept latches the card step; every
// other refusal is a firstboot.Line, so the page shows its fixed line and
// keeps the card, and nothing goes to the vault.
func handOff(k CardKeeper, c *card.Card, authority []byte) error {
	if k == nil {
		return firstboot.Line(keeperUnreachableLine)
	}
	word, err := k.Hand(context.Background(), c, card.Fingerprint(authority))
	switch {
	case err != nil && !errors.Is(err, errKeeperRequest):
		return firstboot.Line(keeperUnreachableLine)
	case err != nil:
		return firstboot.Line(keeperBadLine)
	}
	switch word {
	case KeeperOK:
		return nil
	case KeeperKept:
		return firstboot.ErrKept
	case KeeperAuthority:
		return firstboot.Line(firstboot.ErrNoAuthority.Error())
	case KeeperTaken:
		return firstboot.Line(keeperTakenLine)
	case KeeperBad:
		return firstboot.Line(keeperBadLine)
	}
	// No word, or one the keeper never says: the request may not have
	// landed, and a retry of the same card is safe (F10).
	return firstboot.Line(keeperUnreachableLine)
}
