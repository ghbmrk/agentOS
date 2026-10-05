package sipline

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pion/sdp/v3"
	"github.com/pion/srtp/v3"
)

// Suite is the only SRTP crypto suite offered (RFC 4568 SDES, the suite
// every SRTP-capable provider supports).
const Suite = "AES_CM_128_HMAC_SHA1_80"

const profile = srtp.ProtectionProfileAes128CmHmacSha1_80

// keyLen is the master key plus master salt for Suite.
const keyLen = 16 + 14

// ErrNoSRTP is returned when the far end answers without SRTP: a call whose
// audio would cross the internet in the clear is hung up before anything is
// said.
var ErrNoSRTP = errors.New("sipline: the provider answered without SRTP")

// Payload types offered, in order of preference.
const (
	PCMU = 0
	PCMA = 8
)

// offer is the SDP offer for one call: audio only, PCMU or PCMA, SRTP.
type offer struct {
	ip   net.IP
	port int
	key  []byte // master key and salt
}

func newOffer(ip net.IP, port int) (offer, error) {
	k := make([]byte, keyLen)
	if _, err := rand.Read(k); err != nil {
		return offer{}, err
	}
	return offer{ip: ip, port: port, key: k}, nil
}

func (o offer) String() string {
	fam := "IP4"
	if o.ip.To4() == nil {
		fam = "IP6"
	}
	b := new(strings.Builder)
	fmt.Fprintf(b, "v=0\r\no=- 0 0 IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\n", fam, o.ip, fam, o.ip)
	fmt.Fprintf(b, "m=audio %d RTP/SAVP %d %d\r\n", o.port, PCMU, PCMA)
	fmt.Fprintf(b, "a=crypto:1 %s inline:%s\r\n", Suite, base64.StdEncoding.EncodeToString(o.key))
	fmt.Fprintf(b, "a=rtpmap:%d PCMU/8000\r\na=rtpmap:%d PCMA/8000\r\na=ptime:20\r\na=sendrecv\r\n", PCMU, PCMA)
	return b.String()
}

// answerSDP is the line's answer to a caller's offer: the one codec it
// chose and its own key under the offer's tag.
func (o offer) answerSDP(pt int, tag string) string {
	fam := "IP4"
	if o.ip.To4() == nil {
		fam = "IP6"
	}
	enc := "PCMU"
	if pt == PCMA {
		enc = "PCMA"
	}
	b := new(strings.Builder)
	fmt.Fprintf(b, "v=0\r\no=- 0 0 IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\n", fam, o.ip, fam, o.ip)
	fmt.Fprintf(b, "m=audio %d RTP/SAVP %d\r\n", o.port, pt)
	fmt.Fprintf(b, "a=crypto:%s %s inline:%s\r\n", tag, Suite, base64.StdEncoding.EncodeToString(o.key))
	fmt.Fprintf(b, "a=rtpmap:%d %s/8000\r\na=ptime:20\r\na=sendonly\r\n", pt, enc)
	return b.String()
}

// answer is what the far end chose.
type answer struct {
	addr *net.UDPAddr
	pt   int
	key  []byte // the far end's master key and salt, for its audio to us
	tag  string // the crypto tag the key was under
}

// ErrMediaAddress is returned when an answer aims the call's audio at an
// address the line will not send to.
var ErrMediaAddress = errors.New("sipline: the provider's audio address is not a public unicast address")

// parseAnswer reads an SDP answer. It fails closed: no audio stream, a
// codec that was not offered, a stream without SAVP and an
// AES_CM_128_HMAC_SHA1_80 key under the offer's tag, or an audio address
// that is not public unicast is refused. A private or loopback address is
// allowed only when the provider itself is on one (private), so a provider
// answer cannot aim the call's packets at the box's own network.
func parseAnswer(body []byte, private bool) (answer, error) { return parseSDP(body, private, "1") }

// parseOffer reads a caller's SDP offer under the same rules as an answer,
// with the key under any crypto tag; the answer must echo that tag (RFC
// 4568 5.1).
func parseOffer(body []byte, private bool) (answer, error) { return parseSDP(body, private, "") }

// parseSDP reads the first audio stream of an offer or answer, with its
// SRTP key under tag ("" for any tag).
func parseSDP(body []byte, private bool, tag string) (answer, error) {
	var d sdp.SessionDescription
	if err := d.Unmarshal(body); err != nil {
		return answer{}, fmt.Errorf("sipline: SDP answer: %w", err)
	}
	for _, m := range d.MediaDescriptions {
		if m.MediaName.Media != "audio" || m.MediaName.Port.Value == 0 {
			continue
		}
		if strings.Join(m.MediaName.Protos, "/") != "RTP/SAVP" {
			return answer{}, ErrNoSRTP
		}
		var a answer
		a.pt = -1
		for _, f := range m.MediaName.Formats {
			if pt, err := strconv.Atoi(f); err == nil && (pt == PCMU || pt == PCMA) {
				a.pt = pt
				break
			}
		}
		if a.pt < 0 {
			return answer{}, errors.New("sipline: the provider chose no offered codec")
		}
		for _, at := range m.Attributes {
			if at.Key != "crypto" {
				continue
			}
			f := strings.Fields(at.Value)
			if len(f) < 3 || !cryptoTag(f[0]) || tag != "" && f[0] != tag || f[1] != Suite || !strings.HasPrefix(f[2], "inline:") {
				continue
			}
			kp, _, _ := strings.Cut(strings.TrimPrefix(f[2], "inline:"), "|")
			k, err := base64.StdEncoding.DecodeString(kp)
			if err != nil || len(k) != keyLen {
				continue
			}
			a.key, a.tag = k, f[0]
			break
		}
		if a.key == nil {
			return answer{}, ErrNoSRTP
		}
		c := m.ConnectionInformation
		if c == nil {
			c = d.ConnectionInformation
		}
		if c == nil || c.Address == nil {
			return answer{}, errors.New("sipline: SDP answer has no address")
		}
		ip := net.ParseIP(c.Address.Address)
		if !mediaAddr(ip, private) {
			return answer{}, ErrMediaAddress
		}
		a.addr = &net.UDPAddr{IP: ip, Port: m.MediaName.Port.Value}
		return a, nil
	}
	return answer{}, errors.New("sipline: SDP answer has no audio")
}

// cryptoTag is RFC 4568's tag: 1 to 9 digits. A caller's tag is echoed
// into the answer, so nothing else is accepted.
func cryptoTag(t string) bool {
	if len(t) < 1 || len(t) > 9 {
		return false
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mediaAddr(ip net.IP, private bool) bool {
	switch {
	case ip == nil:
		return false
	case ip.IsLoopback():
		return private
	case !ip.IsGlobalUnicast():
		return false // unspecified, multicast, link-local, broadcast
	case ip.IsPrivate():
		return private
	}
	return true
}

// Context returns the SRTP context for a master key and salt.
func Context(key []byte) (*srtp.Context, error) {
	if len(key) != keyLen {
		return nil, errors.New("sipline: bad SRTP key length")
	}
	return srtp.CreateContext(key[:16], key[16:], profile)
}

// OfferKey reads the SRTP key from an SDP offer this package wrote. The SIP
// simulator uses it to decrypt what the line sends.
func OfferKey(body []byte) ([]byte, error) {
	var d sdp.SessionDescription
	if err := d.Unmarshal(body); err != nil {
		return nil, err
	}
	for _, m := range d.MediaDescriptions {
		for _, at := range m.Attributes {
			if f := strings.Fields(at.Value); at.Key == "crypto" && len(f) >= 3 && f[1] == Suite {
				return base64.StdEncoding.DecodeString(strings.TrimPrefix(f[2], "inline:"))
			}
		}
	}
	return nil, ErrNoSRTP
}
