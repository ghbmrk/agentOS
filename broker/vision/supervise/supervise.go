// Package supervise starts and keeps up the camera vision service
// (agentos-vision) for agentosd. It is infer/supervise's jail and restart
// loop, reused rather than copied: the service runs in the inference cgroup
// leaf (RES-2), as its own user, in new user, network and IPC namespaces,
// with no_new_privs, handed only its listener. Two things differ, and are
// fixed here so no caller can forget them: the supervisor's lines name the
// vision service, and the service's own output goes to /dev/null, never to
// agentosd's log, since an untrusted process that sees capture could write
// an encoding there (DEV-7). The supervisor's lines carry causes and counts
// only.
//
// The service gets a second listener, its control socket, as fd 4, at
// ControlPath(Socket) in the same 0700 directory: the enrolment and lend
// calls (VIS-faces) are served there only, so a feed that comes to reach
// the first socket can never lend or ask for a template.
package supervise

import (
	"context"
	"io"

	"github.com/ghbmrk/agentos/broker/cgroup"
	isupervise "github.com/ghbmrk/agentos/broker/infer/supervise"
)

// Options say what to start and where.
type Options struct {
	// Path is the agentos-vision binary, Args its arguments.
	Path string
	Args []string
	// Socket is the listener's path; its directory is made 0700 and
	// owned by the caller.
	Socket string
	// Cgroup is the inference leaf (budget.Groups.Inference); nil starts
	// the service in the caller's group, which only tests do.
	Cgroup *cgroup.Group
	// UID and GID are the service's own user, never the inference
	// service's: the vision service holds templates (part c) that
	// agentos-infer must not reach. UID 0 is refused.
	UID, GID uint32
	// Log receives the supervisor's lines; nil drops them.
	Log     io.Writer
	Backoff Backoff
}

// Backoff is the restart delay, as infer/supervise's.
type Backoff = isupervise.Backoff

// Supervisor keeps the service up until its context ends; State reports
// it for STATUS.
type Supervisor = isupervise.Supervisor

// Status is what State reports.
type Status = isupervise.Status

// States the supervisor reports.
const (
	Starting    = isupervise.Starting
	Up          = isupervise.Up
	Unavailable = isupervise.Unavailable
	Stopped     = isupervise.Stopped
)

// Start checks o and starts the restart loop; it returns before the
// service is up. The loop ends, killing the service, when ctx ends.
func Start(ctx context.Context, o Options) (*Supervisor, error) {
	return isupervise.Start(ctx, isupervise.Options{
		Path:       o.Path,
		Args:       o.Args,
		Socket:     o.Socket,
		Control:    ControlPath(o.Socket),
		Cgroup:     o.Cgroup,
		UID:        o.UID,
		GID:        o.GID,
		Log:        o.Log,
		Backoff:    o.Backoff,
		Name:       "vision",
		QuietChild: true,
	})
}

// ControlPath is the control socket for a service whose socket is socket:
// beside it, in the same directory.
func ControlPath(socket string) string { return socket + ".control" }
