package homekit

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Accessory responses are hostile input (risk 19). net/http cannot read
// EVENT/1.0, so the framing is hand-written with fixed bounds: lines of at
// most maxLine bytes, at most maxHeaders headers, bodies of at most maxBody
// bytes whether by Content-Length or chunked, and no redirects.
const (
	maxLine     = 1024
	maxHeaders  = 32
	maxBody     = 256 << 10
	maxChunks   = 1024
	readBufSize = 4096
)

type response struct {
	event       bool // EVENT/1.0
	status      int
	contentType string
	body        []byte
}

func readLine(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxLine {
		return nil, fmt.Errorf("%w: line over %d bytes", ErrProtocol, maxLine)
	}
	if err != nil {
		if err == io.EOF && len(line) > 0 {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	line = bytes.TrimSuffix(line[:len(line)-1], []byte("\r"))
	return line, nil
}

// readResponse reads one HTTP/1.1 or EVENT/1.0 response.
func readResponse(br *bufio.Reader) (*response, error) {
	line, err := readLine(br)
	if err != nil {
		return nil, err
	}
	r := &response{}
	var rest []byte
	switch {
	case bytes.HasPrefix(line, []byte("HTTP/1.1 ")):
		rest = line[9:]
	case bytes.HasPrefix(line, []byte("EVENT/1.0 ")):
		rest, r.event = line[10:], true
	default:
		return nil, fmt.Errorf("%w: bad status line", ErrProtocol)
	}
	if len(rest) < 3 || (len(rest) > 3 && rest[3] != ' ') {
		return nil, fmt.Errorf("%w: bad status code", ErrProtocol)
	}
	for _, c := range rest[:3] {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("%w: bad status code", ErrProtocol)
		}
	}
	r.status, _ = strconv.Atoi(string(rest[:3]))
	if r.status < 100 || r.status >= 600 {
		return nil, fmt.Errorf("%w: status %d", ErrProtocol, r.status)
	}
	length, chunked := -1, false
	for i := 0; ; i++ {
		if i > maxHeaders {
			return nil, fmt.Errorf("%w: over %d headers", ErrProtocol, maxHeaders)
		}
		h, err := readLine(br)
		if err != nil {
			return nil, err
		}
		if len(h) == 0 {
			break
		}
		k, v, ok := bytes.Cut(h, []byte(":"))
		if !ok {
			return nil, fmt.Errorf("%w: bad header", ErrProtocol)
		}
		v = bytes.TrimSpace(v)
		switch string(bytes.ToLower(bytes.TrimSpace(k))) {
		case "content-length":
			n, err := strconv.Atoi(string(v))
			if err != nil || n < 0 || length >= 0 || n > maxBody || len(v) > 7 {
				return nil, fmt.Errorf("%w: bad content-length", ErrProtocol)
			}
			length = n
		case "transfer-encoding":
			if !bytes.EqualFold(v, []byte("chunked")) || chunked {
				return nil, fmt.Errorf("%w: unsupported transfer-encoding", ErrProtocol)
			}
			chunked = true
		case "content-type":
			r.contentType = string(v)
		}
	}
	switch {
	case length >= 0 && chunked:
		return nil, fmt.Errorf("%w: both content-length and chunked", ErrProtocol)
	case chunked:
		r.body, err = readChunked(br)
	case length >= 0:
		r.body = make([]byte, length)
		_, err = io.ReadFull(br, r.body)
	case r.status == 204 || r.status == 304 || r.status < 200:
	default:
		return nil, fmt.Errorf("%w: body without a length", ErrProtocol)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func readChunked(br *bufio.Reader) ([]byte, error) {
	var body []byte
	for i := 0; ; i++ {
		if i > maxChunks {
			return nil, fmt.Errorf("%w: over %d chunks", ErrProtocol, maxChunks)
		}
		line, err := readLine(br)
		if err != nil {
			return nil, err
		}
		if j := bytes.IndexByte(line, ';'); j >= 0 {
			line = line[:j]
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || len(line) > 6 {
			return nil, fmt.Errorf("%w: bad chunk size", ErrProtocol)
		}
		n, err := strconv.ParseUint(string(line), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: bad chunk size", ErrProtocol)
		}
		if n == 0 {
			break
		}
		if len(body)+int(n) > maxBody {
			return nil, fmt.Errorf("%w: chunked body over %d bytes", ErrProtocol, maxBody)
		}
		start := len(body)
		body = append(body, make([]byte, n)...)
		if _, err := io.ReadFull(br, body[start:]); err != nil {
			return nil, err
		}
		if crlf, err := readLine(br); err != nil || len(crlf) != 0 {
			return nil, fmt.Errorf("%w: bad chunk end", ErrProtocol)
		}
	}
	for i := 0; ; i++ { // trailers
		if i > maxHeaders {
			return nil, fmt.Errorf("%w: over %d trailers", ErrProtocol, maxHeaders)
		}
		t, err := readLine(br)
		if err != nil {
			return nil, err
		}
		if len(t) == 0 {
			return body, nil
		}
	}
}

// writeRequest frames one request in a single Write.
func writeRequest(w io.Writer, method, path, host, contentType string, body []byte) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, path, host)
	if body != nil {
		fmt.Fprintf(&b, "Content-Type: %s\r\nContent-Length: %d\r\n", contentType, len(body))
	}
	b.WriteString("\r\n")
	b.Write(body)
	_, err := w.Write(b.Bytes())
	return err
}
