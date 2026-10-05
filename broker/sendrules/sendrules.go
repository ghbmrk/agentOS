// Package sendrules is the second line's recipient rules and sending
// budget (ADP-12; security C1 and Q2 on the #142 design read; SR2-5). It
// is a leaf with no network code, so the modem side can apply the rules
// without linking the provider client in smsapi (L3 SHOULD-1 on #164).
package sendrules

import (
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	// ErrRecipient: not a number the second line may text or call
	// (security C1).
	ErrRecipient = errors.New("sendrules: recipient refused")
	// ErrLimited: the second line's budget is spent (security Q2).
	ErrLimited = errors.New("sendrules: the second line's sending limit is reached")
)

var e164Re = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

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

// Budget is the second line's sending budget. The vault process holds
// one, shared by every way an account line sends; the second-SIM tool
// holds another (modem/at M12). It is in memory: a restart of its process
// starts it again. The vault process's needs the owner's unlock unless a
// trusted PC unlocks the box (bootTrusted), so a vault process that
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
