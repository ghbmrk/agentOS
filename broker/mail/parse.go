package mail

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// maxParts bounds the MIME parts walked in one message.
const maxParts = 64

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, r io.Reader) (io.Reader, error) {
	e, err := htmlindex.Get(charset)
	if err != nil {
		return nil, err
	}
	return e.NewDecoder().Reader(r), nil
}

// Parse reads a raw RFC 5322 message: its headers, its plain text (from
// the first text/plain part, else text/html with the tags dropped), and
// whether it carries attachments. Folder, UID and Flags are the caller's.
func Parse(raw []byte) (Message, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return Message{}, err
	}
	h := m.Header
	out := Message{
		MessageID:   strings.TrimSpace(h.Get("Message-Id")),
		Subject:     decodeHeader(h.Get("Subject")),
		InReplyTo:   firstID(h.Get("In-Reply-To")),
		References:  ids(h.Get("References")),
		AuthResults: h["Authentication-Results"],
	}
	if d, err := h.Date(); err == nil {
		out.Date = d
	}
	if l := addrs(h, "From"); len(l) > 0 {
		out.From = l[0]
	}
	out.To = addrs(h, "To")
	out.Cc = addrs(h, "Cc")
	var text, html string
	parts := 0
	walk(h, m.Body, &text, &html, &out.Attachments, &parts, 0)
	if text == "" && html != "" {
		text = stripTags(html)
	}
	out.Text = bound(strings.TrimSpace(text), MaxText)
	return out, nil
}

type getter interface{ Get(string) string }

func walk(h getter, body io.Reader, text, html *string, attach *bool, parts *int, depth int) {
	*parts++
	if *parts > maxParts || depth > 8 {
		return
	}
	ct := h.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = "application/octet-stream"
	}
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	if disp == "attachment" || dparams["filename"] != "" || (params["name"] != "" && !strings.HasPrefix(mt, "multipart/")) {
		*attach = true
		return
	}
	if strings.HasPrefix(mt, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return
			}
			walk(p.Header, p, text, html, attach, parts, depth+1)
		}
	}
	if mt != "text/plain" && mt != "text/html" {
		if !strings.HasPrefix(mt, "multipart/") && mt != "message/rfc822" {
			*attach = true
		}
		return
	}
	if (mt == "text/plain" && *text != "") || (mt == "text/html" && *html != "") {
		return
	}
	var r io.Reader = io.LimitReader(body, 4*MaxText)
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, newlineStripper{r})
	}
	if cs := params["charset"]; cs != "" && !strings.EqualFold(cs, "utf-8") && !strings.EqualFold(cs, "us-ascii") {
		if cr, err := charsetReader(cs, r); err == nil {
			r = cr
		}
	}
	b, _ := io.ReadAll(io.LimitReader(r, 4*MaxText))
	s := strings.ToValidUTF8(string(b), "�")
	if mt == "text/plain" {
		*text = s
	} else {
		*html = s
	}
}

// newlineStripper drops CR and LF so base64 decodes across lines.
type newlineStripper struct{ r io.Reader }

func (n newlineStripper) Read(p []byte) (int, error) {
	for {
		k, err := n.r.Read(p)
		j := 0
		for _, c := range p[:k] {
			if c != '\r' && c != '\n' {
				p[j] = c
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

var (
	tagPat   = regexp.MustCompile(`(?s)<(script|style)\b.*?</(script|style)\s*>|<[^>]*>`)
	spacePat = regexp.MustCompile(`[ \t]+`)
	linesPat = regexp.MustCompile(`\n{3,}`)
)

func stripTags(s string) string {
	s = tagPat.ReplaceAllString(s, " ")
	for _, r := range [][2]string{{"&nbsp;", " "}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", `"`}, {"&#39;", "'"}, {"&amp;", "&"}} {
		s = strings.ReplaceAll(s, r[0], r[1])
	}
	s = spacePat.ReplaceAllString(s, " ")
	return linesPat.ReplaceAllString(s, "\n\n")
}

func bound(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func decodeHeader(s string) string {
	d, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s
	}
	return d
}

func addrs(h mail.Header, key string) []string {
	if h.Get(key) == "" {
		return nil
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	l, err := p.ParseList(h.Get(key))
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range l {
		if a.Address != "" {
			out = append(out, strings.ToLower(a.Address))
		}
	}
	return out
}

var idPat = regexp.MustCompile(`<[^<>\s]+>`)

func ids(s string) []string { return idPat.FindAllString(s, 50) }

func firstID(s string) string {
	if l := ids(s); len(l) > 0 {
		return l[0]
	}
	return ""
}
