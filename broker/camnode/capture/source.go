package capture

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/childproc"
)

// Config is the board's capture as the binary declares it.
type Config struct {
	// Encoder is rpicam-vid's path and any fixed arguments; Args adds the
	// bundle's settings.
	Encoder []string
	// Thermal opens the Lepton's VoSPI device; nil when no core is fitted.
	Thermal func() (io.ReadCloser, error)
	// Shape is the fitted Lepton's (Lepton2 or Lepton3); zero for none.
	Shape camwire.Shape
	// IR sets the illuminator (camwire.IROff, IROn or IRAuto); nil when
	// none is fitted, and the node's Ranges then refuse IR.
	IR func(mode uint8) error
	// Restart is the wait before an encoder or thermal reader that ended is
	// started again; zero is one second.
	Restart time.Duration
	// Log takes fixed-text events. Nil discards them.
	Log func(event string)
}

// Camera is camnode.Source on the board. Read is safe for concurrent use
// (#3588 item 1): frames come from one channel, so a stream being replaced
// and its successor never share a reader's state. Only the newest frames
// are kept while nothing reads them (the oldest is dropped), so a core that
// reconnects gets live frames; the encoder's repeated SPS and PPS and its intra period (Args)
// let the core's decoder pick up at the next IDR (ASSUMPTIONS
// CAM-capture-2).
type Camera struct {
	cfg    Config
	frames chan camwire.Frame

	mu   sync.Mutex
	stop chan struct{} // closes the running producers; nil when none run
	wg   sync.WaitGroup
}

// New is a camera that captures nothing until Apply.
func New(cfg Config) *Camera {
	if cfg.Restart <= 0 {
		cfg.Restart = time.Second
	}
	return &Camera{cfg: cfg, frames: make(chan camwire.Frame, 8)}
}

// Args are rpicam-vid's arguments for s: no preview, run until stopped,
// H.264 from the hardware encoder with SPS and PPS before every IDR, an IDR
// every two seconds, each frame flushed to the pipe at once, written to
// standard output.
func Args(s camwire.Settings) []string {
	fps := int(s.FPS)
	return []string{
		"--nopreview", "--timeout", "0", "--codec", "h264", "--inline", "--flush",
		"--width", strconv.Itoa(int(s.Width)), "--height", strconv.Itoa(int(s.Height)),
		"--framerate", strconv.Itoa(fps), "--bitrate", strconv.Itoa(int(s.BitrateKbps) * 1000),
		"--intra", strconv.Itoa(2 * fps), "--output", "-",
	}
}

// Apply stops the running capture and starts it again with s: the
// encoder while the stream is on, the thermal reader while thermal is on.
// Settings it refuses leave capture stopped.
// The node calls it only with settings within its declared ranges.
func (c *Camera) Apply(s camwire.Settings) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Stop first, so settings refused below leave the sensor off, never
	// capturing at the old ones (Security on #3617, finding 2).
	c.halt()
	for len(c.frames) > 0 {
		<-c.frames // frames at the old settings
	}
	if c.cfg.IR != nil {
		if err := c.cfg.IR(s.IR); err != nil {
			return err
		}
	} else if s.IR != camwire.IROff {
		return errors.New("capture: no IR illuminator fitted")
	}
	if s.Thermal && (c.cfg.Thermal == nil || c.cfg.Shape == (camwire.Shape{})) {
		return errors.New("capture: no thermal core fitted")
	}
	stop := make(chan struct{})
	c.stop = stop
	if s.Stream {
		c.run(stop, func() (func() (camwire.Frame, error), func(), error) { return c.encoder(s) })
		if s.Thermal {
			c.run(stop, c.thermal)
		}
	}
	return nil
}

// Close stops capture.
func (c *Camera) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.halt()
	return nil
}

// halt stops the producers and waits for them. c.mu is held.
func (c *Camera) halt() {
	if c.stop != nil {
		close(c.stop)
		c.stop = nil
	}
	c.wg.Wait()
}

// Read blocks for the next frame.
func (c *Camera) Read() (camwire.Frame, error) {
	return <-c.frames, nil
}

// run keeps one producer going until stop: open starts it and gives its
// next-frame function and its closer; a producer that ends or fails is
// started again after cfg.Restart.
func (c *Camera) run(stop chan struct{}, open func() (func() (camwire.Frame, error), func(), error)) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			// A closed stop wins over a restart that came due in the same
			// instant, so a camera that sees stop closed starts no producer.
			// One opened as stop closes is killed by its watcher, and halt
			// waits for it.
			select {
			case <-stop:
				return
			default:
			}
			next, closer, err := open()
			if err == nil {
				done := make(chan struct{})
				go func() {
					select {
					case <-stop:
						closer()
					case <-done:
					}
				}()
				for {
					f, err := next()
					if err != nil {
						break
					}
					c.offer(f)
				}
				close(done)
				closer()
			}
			c.log("capture ended: restarting")
			select {
			case <-stop:
				return
			case <-time.After(c.cfg.Restart):
			}
		}
	}()
}

// offer queues f, dropping the oldest frame queued when the buffer is
// full, so a stream that starts reading gets the newest frames, and a
// drop under load loses old frames rather than the ones a decoder needs
// next (L3 on #3617, finding 4).
func (c *Camera) offer(f camwire.Frame) {
	for {
		select {
		case c.frames <- f:
			return
		default:
		}
		select {
		case <-c.frames:
		default:
		}
	}
}

// encoder starts rpicam-vid for s and reads its access units.
func (c *Camera) encoder(s camwire.Settings) (func() (camwire.Frame, error), func(), error) {
	if len(c.cfg.Encoder) == 0 {
		return nil, nil, errors.New("capture: no encoder")
	}
	// The encoder gets an empty environment: nothing of the node's, and it
	// needs none (childproc, P3-4b-3r-env-r8).
	cmd := childproc.Command(context.Background(), childproc.NewEnv(), childproc.Options{WaitDelay: time.Second},
		c.cfg.Encoder[0], append(append([]string{}, c.cfg.Encoder[1:]...), Args(s)...)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	var once sync.Once
	closer := func() {
		once.Do(func() {
			cmd.Kill()
			cmd.Wait()
		})
	}
	aus := NewAccessUnits(out)
	return func() (camwire.Frame, error) {
		au, err := aus.Next()
		if err != nil {
			return camwire.Frame{}, err
		}
		return camwire.Frame{Type: camwire.TypeVideo, Payload: au}, nil
	}, closer, nil
}

// thermal opens the Lepton and reads its frames.
func (c *Camera) thermal() (func() (camwire.Frame, error), func(), error) {
	dev, err := c.cfg.Thermal()
	if err != nil {
		return nil, nil, err
	}
	l, err := NewLepton(dev, c.cfg.Shape)
	if err != nil {
		dev.Close()
		return nil, nil, err
	}
	var once sync.Once
	return func() (camwire.Frame, error) {
		p, err := l.Next()
		if err != nil {
			return camwire.Frame{}, err
		}
		return camwire.Frame{Type: camwire.TypeThermal, Payload: p}, nil
	}, func() { once.Do(func() { dev.Close() }) }, nil
}

func (c *Camera) log(event string) {
	if c.cfg.Log != nil {
		c.cfg.Log(event)
	}
}
