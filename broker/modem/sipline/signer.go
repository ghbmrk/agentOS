package sipline

import (
	"context"
	"errors"
	"strings"

	"github.com/icholy/digest"
)

// Challenge is one digest challenge (RFC 3261 22.4) for one request.
type Challenge struct {
	// Header is the WWW-Authenticate or Proxy-Authenticate value.
	Header string
	// Method and URI are the challenged request's method and Request-URI.
	Method, URI string
}

// Signer answers a digest challenge with the Authorization (or
// Proxy-Authorization) value. The vault process holds the account password
// and implements it (Account), so the password never enters the process
// that runs the line (CRED-1).
type Signer interface {
	Sign(ctx context.Context, c Challenge) (string, error)
}

// Errors from Account.
var (
	ErrRealm  = errors.New("sipline: challenge is for another realm")
	ErrMethod = errors.New("sipline: not a method the second line signs")
)

// signable are the requests the line sends: registering, texts, calls and
// ending them.
var signable = map[string]bool{"REGISTER": true, "MESSAGE": true, "INVITE": true, "BYE": true, "CANCEL": true}

// Account is the vault side of the account: the only holder of its
// password. It answers challenges only for the realm recorded at setup and
// only for the requests the line sends, so a process that can ask it to
// sign cannot use it for another service that shares the password.
type Account struct {
	Username, Password string
	// Realm is the provider's digest realm, recorded at setup from the
	// first registration over verified TLS. Empty refuses everything.
	Realm string
}

// Sign implements Signer.
func (a Account) Sign(_ context.Context, c Challenge) (string, error) {
	ch, err := digest.ParseChallenge(c.Header)
	if err != nil {
		return "", err
	}
	ch.Algorithm = strings.ToUpper(ch.Algorithm)
	if a.Realm == "" || ch.Realm != a.Realm {
		return "", ErrRealm
	}
	if !signable[c.Method] {
		return "", ErrMethod
	}
	if !digest.CanDigest(ch) || (len(ch.QOP) > 0 && !ch.SupportsQOP("auth")) {
		return "", errors.New("sipline: unsupported digest challenge")
	}
	cred, err := digest.Digest(ch, digest.Options{Method: c.Method, URI: c.URI, Username: a.Username, Password: a.Password})
	if err != nil {
		return "", err
	}
	return cred.String(), nil
}
