package homekit

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// The encrypted session (HAP R2 6.5.2): each frame is a 2-byte little-endian
// length n (1 to 1024), then n bytes of ChaCha20-Poly1305 ciphertext and a
// 16-byte tag, with the length as additional data. The nonce is four zero
// bytes and a 64-bit little-endian counter per direction, never sent, so a
// replayed, reordered or altered frame fails to open and ends the session.
const maxFrame = 1024

type frameCipher struct {
	aead cipher.AEAD
	n    uint64
}

func newFrameCipher(key []byte) (*frameCipher, error) {
	a, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &frameCipher{aead: a}, nil
}

func (c *frameCipher) nonce() ([]byte, error) {
	if c.n == ^uint64(0) {
		return nil, fmt.Errorf("%w: frame counter exhausted", ErrClosed)
	}
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.n)
	c.n++
	return nonce, nil
}

// frameWriter seals plaintext into frames of at most maxFrame bytes.
type frameWriter struct {
	w io.Writer
	c *frameCipher
}

func (fw *frameWriter) Write(p []byte) (int, error) {
	var out []byte
	for done := 0; done < len(p); {
		n := min(len(p)-done, maxFrame)
		hdr := make([]byte, 2)
		putU16le(hdr, n)
		nonce, err := fw.c.nonce()
		if err != nil {
			return 0, err
		}
		out = append(out, hdr...)
		out = fw.c.aead.Seal(out, nonce, p[done:done+n], hdr)
		done += n
	}
	if _, err := fw.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// frameReader opens frames. Its first failure is permanent.
type frameReader struct {
	r   io.Reader
	c   *frameCipher
	buf []byte
	err error
	ct  [2 + maxFrame + 16]byte
}

func (fr *frameReader) Read(p []byte) (int, error) {
	for len(fr.buf) == 0 {
		if fr.err != nil {
			return 0, fr.err
		}
		fr.buf, fr.err = fr.next()
	}
	n := copy(p, fr.buf)
	fr.buf = fr.buf[n:]
	return n, nil
}

func (fr *frameReader) next() ([]byte, error) {
	if _, err := io.ReadFull(fr.r, fr.ct[:2]); err != nil {
		return nil, err
	}
	n := u16le(fr.ct[:2])
	if n == 0 || n > maxFrame {
		return nil, fmt.Errorf("%w: frame length %d", ErrProtocol, n)
	}
	if _, err := io.ReadFull(fr.r, fr.ct[2:2+n+16]); err != nil {
		return nil, err
	}
	nonce, err := fr.c.nonce()
	if err != nil {
		return nil, err
	}
	plain, err := fr.c.aead.Open(nil, nonce, fr.ct[2:2+n+16], fr.ct[:2])
	if err != nil {
		return nil, fmt.Errorf("%w: frame does not authenticate", ErrProtocol)
	}
	return plain, nil
}
