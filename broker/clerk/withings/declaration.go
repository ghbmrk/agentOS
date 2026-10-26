package withings

import (
	"crypto/sha1"
	"crypto/subtle"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Operation is one declared device operation and its verb (DEV-4).
type Operation struct {
	Name string
	Verb key.Verb
}

// Declaration is the scale's DEV-12 declaration: one operation, a read of
// the stored measurements. The scale reaches nothing else through this
// package (allow.go).
var Declaration = struct {
	Device     string
	Service    string
	Char       string
	Operations []Operation
}{
	Device:     "withings-body-smart",
	Service:    ServiceUUID,
	Char:       CharacteristicUUID,
	Operations: []Operation{{"read-measurements", key.Read}},
}

// KeyProver answers for the scale's secret kl. It is the custody side
// (CLK-1): the clerk that holds kl from the sealed store builds one, and the
// session only ever sees answers. It never prints kl.
type KeyProver struct{ kl []byte }

// NewKeyProver holds a copy of kl.
func NewKeyProver(kl []byte) *KeyProver { return &KeyProver{append([]byte(nil), kl...)} }

// answerFor hashes one scratch buffer and wipes it, so no digest state
// keeps kl after the answer.
func answerFor(challenge []byte, mac string, kl []byte) []byte {
	b := make([]byte, 0, len(challenge)+len(mac)+len(kl))
	b = append(append(append(b, challenge...), mac...), kl...)
	sum := sha1.Sum(b)
	clear(b)
	return sum[:]
}

// Answer is SHA1(challenge ‖ mac ‖ kl).
func (p *KeyProver) Answer(challenge []byte, mac string) ([]byte, error) {
	return answerFor(challenge, mac, p.kl), nil
}

// Check compares in constant time.
func (p *KeyProver) Check(own []byte, mac string, answer []byte) bool {
	return subtle.ConstantTimeCompare(answerFor(own, mac, p.kl), answer) == 1
}

// Format prints no field, whatever the verb.
func (p KeyProver) Format(f fmt.State, _ rune) { fmt.Fprint(f, "withings.KeyProver{kl: redacted}") }
