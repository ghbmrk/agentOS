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

// answer is what the far end chose.
type answer struct {
	addr *net.UDPAddr
	pt   int
	key  []byte // the far end's master key and salt, for its audio to us
}

// parseAnswer reads an SDP answer. It fails closed: no audio stream, a
// codec that was not offered, or a stream without SAVP and an
// AES_CM_128_HMAC_SHA1_80 key is refused.
func parseAnswer(body []byte) (answer, error) {
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
			if len(f) < 3 || f[1] != Suite || !strings.HasPrefix(f[2], "inline:") {
				continue
			}
			kp, _, _ := strings.Cut(strings.TrimPrefix(f[2], "inline:"), "|")
			k, err := base64.StdEncoding.DecodeString(kp)
			if err != nil || len(k) != keyLen {
				continue
			}
			a.key = k
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
		if ip == nil || ip.IsUnspecified() {
			return answer{}, errors.New("sipline: SDP answer has no usable address")
		}
		a.addr = &net.UDPAddr{IP: ip, Port: m.MediaName.Port.Value}
		return a, nil
	}
	return answer{}, errors.New("sipline: SDP answer has no audio")
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
