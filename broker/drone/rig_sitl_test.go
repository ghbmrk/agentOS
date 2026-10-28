//go:build sitl

package drone

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"

	"github.com/ghbmrk/agentos/broker/drone/sitl"
)

// rig is one SITL aircraft with a provisioned key and a key-holder on one of
// its ports.
type rig struct {
	t     *testing.T
	sim   *sitl.Instance
	key   Key
	owner ed25519.PrivateKey
	state string
	logs  *syncBuffer
	port  int
	link  *Link
	h     *Holder
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newRig boots SITL, provisions a fresh key over SERIAL0 and starts a holder
// there; with load, it loads the fixture policy and requires it to read back.
func newRig(t *testing.T, load bool) *rig {
	t.Helper()
	sim := sitl.Start(t, sitl.Options{})
	ports := sim.Ports()
	if len(ports) < 3 {
		t.Fatalf("SITL exposes %d serial ports, want at least 3:\n%s", len(ports), sim.Output())
	}
	k, err := NewKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, sim: sim, key: k, owner: testOwner(t, 1), state: t.TempDir(), logs: &syncBuffer{}}
	c := sim.Dial(ports[0])
	if err := Provision(c, k, time.Now()); err != nil {
		t.Fatal(err)
	}
	r.attach(ports[0], c)
	if load {
		if err := r.h.Load(signPolicy(t, testPolicy(), r.owner)); err != nil {
			t.Fatalf("loading the fixture policy: %v\nlog:\n%s", err, r.logs)
		}
	}
	return r
}

// attach starts a holder on conn (a connection to port) and waits for a
// signed heartbeat.
func (r *rig) attach(port int, c net.Conn) {
	r.t.Helper()
	l, err := Dial(c, r.key)
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := l.WaitHeartbeat(time.Time{}, 20*time.Second); err != nil {
		r.t.Fatalf("no signed heartbeat on port %d: %v\n%s", port, err, r.sim.Output())
	}
	h, err := NewHolder(l, r.owner.Public().(ed25519.PublicKey), r.state, log.New(r.logs, "", 0))
	if err != nil {
		r.t.Fatal(err)
	}
	r.port, r.link, r.h = port, l, h
	r.t.Cleanup(func() { l.Close() })
}

// moveTo restarts the holder on another port.
func (r *rig) moveTo(port int) {
	r.t.Helper()
	r.link.Close()
	time.Sleep(500 * time.Millisecond)
	r.attach(port, r.sim.Dial(port))
}

// state is everything an attack could change on the aircraft, read over the
// signed link.
type aircraft struct {
	Params  map[string]float32
	Fence   []Item
	Rally   []Item
	Mission []Item
	Mode    uint32
	Armed   bool
}

// watched are parameters read beyond the policy's: the boot count (a reboot
// would raise it) and the signing timestamp's neighbours do not move unless
// something changed the aircraft.
var watched = []string{"STAT_BOOTCNT", "FENCE_ENABLE", "SCR_ENABLE", "RC_PROTOCOLS", "MAV1_OPTIONS", "MAV2_OPTIONS",
	"MAV3_OPTIONS", "FENCE_ALT_MAX", "FS_GCS_ENABLE", "BATT_FS_LOW_ACT", "MAV_OPTIONS"}

func (r *rig) snapshot() aircraft {
	r.t.Helper()
	a := aircraft{Params: map[string]float32{}}
	names := append([]string(nil), watched...)
	if p := r.h.Policy(); p != nil {
		names = append(names, Derive(p).ReadBackNames()...)
	}
	for _, n := range names {
		v, err := r.link.GetParam(n)
		if err != nil {
			r.t.Fatalf("reading %s: %v", n, err)
		}
		a.Params[n] = v
	}
	var err error
	if a.Fence, err = r.link.Download(MissionFence); err != nil {
		r.t.Fatal(err)
	}
	if a.Rally, err = r.link.Download(MissionRally); err != nil {
		r.t.Fatal(err)
	}
	if a.Mission, err = r.link.Download(MissionMission); err != nil {
		r.t.Fatal(err)
	}
	if len(a.Mission) > 0 {
		// Item 0 is home, which the aircraft sets itself at its first GPS fix.
		a.Mission = a.Mission[1:]
	}
	hb, err := r.link.WaitHeartbeat(time.Now(), 5*time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	a.Mode, a.Armed = hb.CustomMode, hb.Armed
	return a
}

func (r *rig) requireSame(before aircraft, what string) {
	r.t.Helper()
	after := r.snapshot()
	if !reflect.DeepEqual(before, after) {
		r.t.Errorf("%s changed the aircraft:\nbefore %+v\nafter  %+v", what, before, after)
	}
	if after.Armed {
		r.t.Errorf("%s: the aircraft is armed", what)
	}
}

// newSender writes frames as an attacker: unsigned (key nil) or signed with key,
// from the key-holder's own system and component ids, so that the only thing
// between it and the aircraft is the signature.
func newSender(t *testing.T, out io.Writer, key *frame.V2Key, linkID byte) *frame.Writer {
	t.Helper()
	w, err := frame.NewWriter(frame.WriterConf{Writer: out, DialectRW: dialectRW(), OutVersion: frame.V2,
		OutSystemID: holderSysID, OutComponentID: holderCompID, OutSignatureLinkID: linkID, OutKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func send(t *testing.T, w *frame.Writer, msgs ...message.Message) {
	t.Helper()
	for _, m := range msgs {
		if err := w.WriteMessage(m); err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ftp builds a MAVLink FTP request.
func ftp(seq uint16, session, opcode byte, offset uint32, data []byte) *common.MessageFileTransferProtocol {
	m := &common.MessageFileTransferProtocol{TargetSystem: targetSysID, TargetComponent: targetCompID}
	binary.LittleEndian.PutUint16(m.Payload[0:], seq)
	m.Payload[2], m.Payload[3], m.Payload[4] = session, opcode, byte(len(data))
	binary.LittleEndian.PutUint32(m.Payload[8:], offset)
	copy(m.Payload[12:], data)
	return m
}

const (
	ftpTerminate  = 1
	ftpCreateFile = 6
	ftpWriteFile  = 7
)

// canaryFiles finds files named canary* anywhere under SITL's directory, the
// root of its MAVLink FTP.
func canaryFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && strings.HasPrefix(d.Name(), "canary") {
			found = append(found, p)
		}
		return nil
	})
	return found
}
