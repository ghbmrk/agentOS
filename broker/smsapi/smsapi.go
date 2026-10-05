// Package smsapi is the second line's texts over a provider's HTTP API
// (ADP-12, potency PL1 on #102; P2-3c part 5): for providers whose SIP
// accounts carry no MESSAGE, the vault process sends and fetches texts
// with the provider's API token, which never leaves it (CRED-1).
//
// The vault process serves Handler on sms.sock to the modem bridge's uid
// only; the bridge uses Client. Neither side chooses the provider's host,
// path, method or sending number: those come from the owner's setup, from
// a closed list of providers (security Q1 on the #142 design read).
//
// Budget and recipient rules are the vault process's, shared with the SIP
// account's MESSAGE signing (security Q2, C1), so a compromised bridge can
// send no more than the owner's second line may.
package smsapi

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/modem"
)

// Vault entry names and kinds for the HTTP account (egress K16).
const (
	SettingsName = "second-line-sms"
	TokenName    = "second-line-sms-token"
	KindSettings = "sms_account"
	KindToken    = "sms_token"
)

// Providers on the closed list.
const (
	Twilio     = "twilio"
	SignalWire = "signalwire"
)

// Settings is the HTTP account: the provider, its SignalWire space, the
// account (a Twilio account SID or a SignalWire project ID) and the line's
// number. None of it is secret; the token is a vault entry of its own.
type Settings struct {
	Provider string `json:"provider"`
	Space    string `json:"space,omitempty"`
	Account  string `json:"account"`
	Number   string `json:"number"`
}

// Setup refusals, one per field (the vault process words them).
var (
	ErrProvider = fieldErr("provider")
	ErrSpace    = fieldErr("space")
	ErrAccount  = fieldErr("account")
	ErrNumber   = fieldErr("number")
	// ErrSettings matches each of them (errors.Is).
	ErrSettings = errors.New("smsapi: settings refused")
)

type fieldErr string

func (e fieldErr) Error() string        { return "smsapi: bad " + string(e) }
func (e fieldErr) Is(target error) bool { return target == ErrSettings }

var (
	spaceRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	sidRe   = regexp.MustCompile(`^AC[0-9a-f]{32}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	e164Re  = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)
)

// Normalize lowercases the provider, space and a SignalWire project ID,
// and drops spaces, dashes, dots and brackets from the number.
func (s Settings) Normalize() Settings {
	s.Provider = strings.ToLower(strings.TrimSpace(s.Provider))
	s.Space = strings.ToLower(strings.TrimSpace(s.Space))
	s.Account = strings.TrimSpace(s.Account)
	if s.Provider == SignalWire {
		s.Account = strings.ToLower(s.Account)
	}
	s.Number = strings.Map(func(r rune) rune {
		if strings.ContainsRune(" -.()", r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s.Number))
	return s
}

// Check refuses settings off the closed list (security Q1): a Twilio
// account SID is AC and 32 hex digits; a SignalWire space is one DNS label
// and its project a UUID; the number is E.164.
func (s Settings) Check() error {
	switch s.Provider {
	case Twilio:
		if s.Space != "" {
			return ErrSpace
		}
		if !sidRe.MatchString(s.Account) {
			return ErrAccount
		}
	case SignalWire:
		if !spaceRe.MatchString(s.Space) {
			return ErrSpace
		}
		if !uuidRe.MatchString(s.Account) {
			return ErrAccount
		}
	default:
		return ErrProvider
	}
	if !e164Re.MatchString(s.Number) {
		return ErrNumber
	}
	return nil
}

// Host is the provider's API host; the space is joined only as
// <space>.signalwire.com.
func (s Settings) Host() string {
	if s.Provider == SignalWire {
		return s.Space + ".signalwire.com"
	}
	return "api.twilio.com"
}

// MessagesPath is the account's Messages resource.
func (s Settings) MessagesPath() string {
	p := "/2010-04-01/Accounts/" + s.Account + "/Messages.json"
	if s.Provider == SignalWire {
		p = "/api/laml" + p
	}
	return p
}

// Refusals the bridge sees, each with its own owner wording in sipline.
var (
	ErrLocked    = errors.New("smsapi: the vault is locked")
	ErrNoAccount = errors.New("smsapi: no HTTP account is set up")
	// ErrRecipient: not a number the second line may text (security C1).
	ErrRecipient = errors.New("smsapi: recipient refused")
	// ErrTooLong: more than MaxParts segments (security C2).
	ErrTooLong = errors.New("smsapi: text too long")
	// ErrLimited: the second line's budget is spent (security Q2).
	ErrLimited = errors.New("smsapi: the second line's sending limit is reached")
	// ErrRefused: the provider refused the text.
	ErrRefused = errors.New("smsapi: the provider refused the text")
	// ErrUnreachable: the provider did not answer, or answered 5xx.
	ErrUnreachable = errors.New("smsapi: the provider is unreachable")
	// ErrTooSoon: a poll within MinPollGap of the last.
	ErrTooSoon = errors.New("smsapi: polled too soon")
)

// MaxParts bounds one text, as at.MaxParts does (security C2).
const MaxParts = 10

// MaxText bounds a text's bytes, as sipline's maxText does.
const MaxText = 1600

// CheckText refuses a text that is not UTF-8, is longer than MaxText
// bytes, or takes more than MaxParts segments.
func CheckText(text string) error {
	if text == "" || !utf8.ValidString(text) || len(text) > MaxText {
		return ErrTooLong
	}
	if n, _ := modem.Segments(text); n > MaxParts {
		return ErrTooLong
	}
	return nil
}

// CheckRecipient applies security C1: an E.164 number of at least 8
// digits (no short or premium codes), never the owner's number or the
// line's own.
func CheckRecipient(to, owner, own string) error {
	if !e164Re.MatchString(to) || len(to)-1 < 8 || to == owner || to == own || Premium(to) {
		return ErrRecipient
	}
	return nil
}

// premium are premium-rate and revenue-share ranges as country code and
// national prefix (SR2-5; ADP-12: a premium-rate code needs an
// owner-created contact). The national prefix is written without any
// trunk 0, the way it follows the country code. An empty one means the
// whole country code is premium-rate: ITU's shared-cost (IPRS) and
// global satellite and network codes (security F2 on #164). The list is
// not exhaustive: it covers the ranges most open to abuse in the box's
// first markets, and the shared budget bounds the rest (egress K16).
var premium = []struct{ cc, nat string }{
	{"1", "900"}, {"1", "976"}, // NANP
	{"44", "9"}, {"44", "87"}, // UK 09 and 087
	{"49", "900"}, {"49", "137"}, {"49", "118"}, // DE
	{"33", "89"},                                // FR 089
	{"39", "899"}, {"39", "892"}, {"39", "895"}, // IT
	{"34", "803"}, {"34", "806"}, {"34", "807"}, {"34", "905"}, // ES
	{"31", "900"}, {"31", "906"}, {"31", "909"}, // NL
	{"32", "90"},                                // BE 090x
	{"41", "900"}, {"41", "901"}, {"41", "906"}, // CH
	{"43", "900"}, {"43", "930"}, // AT
	{"61", "190"},                                                   // AU
	{"64", "900"},                                                   // NZ
	{"353", "15"},                                                   // IE 15xx
	{"979", ""}, {"881", ""}, {"882", ""}, {"883", ""}, {"870", ""}, // ITU
}

// Premium says number (E.164) is in a premium-rate range on the list.
func Premium(number string) bool {
	d, ok := strings.CutPrefix(number, "+")
	if !ok {
		return false
	}
	for _, p := range premium {
		if strings.HasPrefix(d, p.cc+p.nat) {
			return true
		}
	}
	return false
}

// PremiumDialed says dialed, the digits of a Request-URI on an account
// that dials without the +, may reach a premium-rate range on the list,
// for an account whose own number (E.164) is own. The provider may read
// the digits as international, after an international prefix (00, 011 or
// 0011), or as national in the account's own country, after a trunk 0 or
// none (security F1 on #164: "9005551234" is a US 900 number, not +90).
func PremiumDialed(dialed, own string) bool {
	d := strings.TrimLeft(dialed, "0")
	forms := []string{d}
	if rest, ok := strings.CutPrefix(d, "11"); ok { // 011, 0011
		forms = append(forms, rest)
	}
	for _, p := range premium {
		for _, f := range forms {
			if strings.HasPrefix(f, p.cc+p.nat) {
				return true
			}
		}
		if p.nat != "" && strings.HasPrefix(own, "+"+p.cc) && strings.HasPrefix(d, p.nat) {
			return true
		}
	}
	return false
}

// SameNumber says dialed, the digits of a Request-URI on an account that
// dials without the + (no +), may reach number (E.164): after any leading
// zeros (a trunk or international prefix), one is the other or ends with
// it. So a national form ("5550109999", "07700900123") or an
// international-prefix form ("0115550109999") of the owner's number or the
// line's own is caught, whatever the provider's country (L3 MUST-1 on
// #159, security C1).
func SameNumber(dialed, number string) bool {
	d := strings.TrimLeft(dialed, "0")
	n := strings.TrimPrefix(number, "+")
	if len(d) < 7 || n == "" {
		return false
	}
	return strings.HasSuffix(n, d) || strings.HasSuffix(d, n)
}

// Budget limits (security Q2): the whole second line, SIP MESSAGE and
// HTTP texts together, and each recipient.
const (
	PerHour          = 30
	PerDay           = 200
	PerRecipientHour = 10
	// Calls spend the same budget and have a lower cap of their own
	// (SR2-5; L3 SHOULD-1 on #159).
	CallsPerHour = 10
	CallsPerDay  = 50
)

// Budget is the second line's sending budget, held in the vault process
// and shared by every way the line sends. It is in memory: a restart of
// the vault process starts it again. That needs the owner's unlock unless
// a trusted PC unlocks the box (bootTrusted), so a vault process that
// restarts often could send past it (egress K16 residual).
type Budget struct {
	mu   sync.Mutex
	sent []sent
}

type sent struct {
	at   time.Time
	to   string
	call bool
}

// Take spends one text to to at now, or refuses with ErrLimited.
func (b *Budget) Take(to string, now time.Time) error { return b.take(to, now, false) }

// TakeCall spends one call to to at now, or refuses with ErrLimited.
func (b *Budget) TakeCall(to string, now time.Time) error { return b.take(to, now, true) }

func (b *Budget) take(to string, now time.Time, call bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	kept := b.sent[:0]
	hour, toHour, calls, callsHour := 0, 0, 0, 0
	for _, s := range b.sent {
		if now.Sub(s.at) >= 24*time.Hour {
			continue
		}
		kept = append(kept, s)
		if s.call {
			calls++
		}
		if now.Sub(s.at) < time.Hour {
			hour++
			if s.to == to {
				toHour++
			}
			if s.call {
				callsHour++
			}
		}
	}
	b.sent = kept
	if len(kept) >= PerDay || hour >= PerHour || toHour >= PerRecipientHour {
		return ErrLimited
	}
	if call && (calls >= CallsPerDay || callsHour >= CallsPerHour) {
		return ErrLimited
	}
	b.sent = append(b.sent, sent{now, to, call})
	return nil
}

// Inbound is one text the provider received for the line.
type Inbound struct {
	ID   string    `json:"id"`
	From string    `json:"from"`
	Text string    `json:"text"`
	At   time.Time `json:"at"`
	// Named: From is a sender name, not a number (sipline's named
	// senders).
	Named bool `json:"named,omitempty"`
}

// checkSender returns from as a number, or as a name of at most 32
// printable ASCII characters (security C3).
func checkSender(from string) (string, bool, bool) {
	if e164Re.MatchString(from) {
		return from, false, true
	}
	if from == "" || len(from) > 32 {
		return "", false, false
	}
	for _, r := range from {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return "", false, false
		}
	}
	return from, true, true
}
