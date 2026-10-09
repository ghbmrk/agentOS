package at

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
)

// Call audio reaches the host one of two ways (Profile.Audio). Either way
// the broker sees 8 kHz, 16-bit little-endian mono PCM: Read is the far
// end's voice (uplink), Write is what the box says (downlink).

// Stream is one call's audio.
type Stream interface {
	io.ReadWriteCloser
}

// AudioOpener opens a call's audio once the call is active and the
// profile's AudioOn commands have run.
type AudioOpener func(ctx context.Context) (Stream, error)

// SerialAudio carries audio on a serial interface (SIMCom AT+CPCMREG=1).
// open is OpenSerial on the modem's audio port outside tests.
func SerialAudio(open func() (io.ReadWriteCloser, error)) AudioOpener {
	return func(context.Context) (Stream, error) { return open() }
}

// Runner starts ALSA capture and playback on a sound card.
type Runner interface {
	Record(ctx context.Context, card string) (io.ReadCloser, error)
	Play(ctx context.Context, card string) (io.WriteCloser, error)
}

// UACAudio carries audio on a USB Audio Class card (Quectel AT+QPCMV=1,2),
// through alsa-utils' arecord and aplay unless r is set.
func UACAudio(card string, r Runner) AudioOpener {
	if r == nil {
		r = ALSA{}
	}
	return func(ctx context.Context) (Stream, error) {
		ctx, cancel := context.WithCancel(ctx)
		rec, err := r.Record(ctx, card)
		if err != nil {
			cancel()
			return nil, err
		}
		play, err := r.Play(ctx, card)
		if err != nil {
			_ = rec.Close()
			cancel()
			return nil, err
		}
		return &uacStream{rec: rec, play: play, cancel: cancel}, nil
	}
}

type uacStream struct {
	rec    io.ReadCloser
	play   io.WriteCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (s *uacStream) Read(p []byte) (int, error)  { return s.rec.Read(p) }
func (s *uacStream) Write(p []byte) (int, error) { return s.play.Write(p) }
func (s *uacStream) Close() error {
	s.once.Do(func() {
		_ = s.play.Close()
		_ = s.rec.Close()
		s.cancel()
	})
	return nil
}

// ALSA runs arecord and aplay with fixed arguments: raw 8 kHz S16_LE mono
// on plughw:<card>. Nothing from a call reaches their argument lists.
type ALSA struct{}

// alsaEnv is all of arecord's and aplay's environment: a fixed PATH.
// plughw:<card> names the device, so they need no ALSA_* variable, HOME
// (~/.asoundrc) or locale, and nothing in agentos-modem's environment
// reaches them (P3-4b-3r-env).
var alsaEnv = []string{"PATH=/usr/bin:/bin"}

func alsaArgs(card string) []string {
	return []string{"-q", "-D", "plughw:" + card, "-f", "S16_LE", "-r", "8000", "-c", "1", "-t", "raw"}
}

// Record starts arecord and returns its output.
func (ALSA) Record(ctx context.Context, card string) (io.ReadCloser, error) {
	if !validCard(card) {
		return nil, errors.New("at: bad sound card")
	}
	cmd := exec.CommandContext(ctx, "arecord", alsaArgs(card)...)
	cmd.Env = alsaEnv
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &procReader{ReadCloser: out, cmd: cmd}, nil
}

// Play starts aplay and returns its input.
func (ALSA) Play(ctx context.Context, card string) (io.WriteCloser, error) {
	if !validCard(card) {
		return nil, errors.New("at: bad sound card")
	}
	cmd := exec.CommandContext(ctx, "aplay", alsaArgs(card)...)
	cmd.Env = alsaEnv
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &procWriter{WriteCloser: in, cmd: cmd}, nil
}

func validCard(card string) bool {
	if card == "" || len(card) > 3 {
		return false
	}
	for _, c := range card {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

type procReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (p *procReader) Close() error {
	_ = p.ReadCloser.Close()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
	return nil
}

type procWriter struct {
	io.WriteCloser
	cmd *exec.Cmd
}

func (p *procWriter) Close() error {
	_ = p.WriteCloser.Close()
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	_ = p.cmd.Wait()
	return nil
}
