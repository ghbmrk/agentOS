package localsrv

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Backups is the owner side's backup ops (cmd/agentosd, BAK-1 e4b), so
// localsrv links no kernel. Every error is a sockets.Code from
// localapi.BackupCodes, or ErrBadArgs; any other reaches the page as
// ErrBackupUnavailable, so no kernel text does.
type Backups interface {
	List(ctx context.Context) (localapi.BackupChoice, error)
	// Begin returns the challenge a hardware key signs to add p.
	Begin(ctx context.Context, p localapi.BackupPlace) (localapi.BackupBegun, error)
	// Add adds p as destination n under the hardware key whose get()
	// assertion over Begin's challenge this is.
	Add(ctx context.Context, p localapi.BackupPlace, n int, authData, clientData, sig []byte) error
	// Remove stops new backups to the listed destination name.
	Remove(ctx context.Context, name string) error
}

// BackupBeginsPerMinute bounds add starts on the socket: each asks the
// kernel to check a directory.
const BackupBeginsPerMinute = 6

func (s *Server) backupOps() map[string]sockets.Handler {
	return map[string]sockets.Handler{
		localapi.OpBackups:      s.backups,
		localapi.OpBackupBegin:  s.backupBegin,
		localapi.OpBackupAdd:    s.backupAdd,
		localapi.OpBackupRemove: s.backupRemove,
	}
}

// backupErr is err as one of the closed set of codes.
func backupErr(err error) error {
	var c sockets.Code
	if errors.As(err, &c) && (slices.Contains(localapi.BackupCodes, string(c)) || c == errBadArgs) {
		return c
	}
	return sockets.Code(localapi.ErrBackupUnavailable)
}

// backupPlace is p in the frame's bounds; the kernel checks its shape.
func backupPlace(p localapi.BackupPlace) bool {
	return p.Kind == localapi.BackupKindDir && p.Name != "" && len(p.Name) <= localapi.MaxBackupName &&
		p.Locator != "" && len(p.Locator) <= localapi.MaxBackupLocator && p.Newest == 0
}

func (s *Server) backups(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.Auth
	if decode(args, &in) != nil || !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	c, err := s.cfg.Backups.List(ctx)
	if err != nil {
		return nil, backupErr(err)
	}
	return c, nil
}

func (s *Server) backupBegin(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.BackupBegin
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !backupPlace(in.Place) {
		return nil, errBadArgs
	}
	if !s.allowPerMinute(&s.backupBegins, BackupBeginsPerMinute) {
		return nil, errLimited
	}
	b, err := s.cfg.Backups.Begin(ctx, in.Place)
	if err != nil {
		return nil, backupErr(err)
	}
	if len(b.Challenge) != localapi.PasskeyChallenge {
		return nil, sockets.Code(localapi.ErrBackupUnavailable)
	}
	return b, nil
}

func (s *Server) backupAdd(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.BackupAdd
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || !backupPlace(in.Place) || in.N < 0 || in.N > localapi.MaxBackupN ||
		!assertionPart(in.AuthenticatorData) || !assertionPart(in.ClientDataJSON) || !assertionPart(in.Signature) {
		return nil, errBadArgs
	}
	if err := s.cfg.Backups.Add(ctx, in.Place, in.N, in.AuthenticatorData, in.ClientDataJSON, in.Signature); err != nil {
		return nil, backupErr(err)
	}
	return localapi.Text{}, nil
}

func (s *Server) backupRemove(ctx context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
	var in localapi.BackupRemove
	err := decode(args, &in)
	if !s.valid(in.Token) {
		return nil, errUnauthorized
	}
	if err != nil || in.Name == "" || len(in.Name) > localapi.MaxBackupName {
		return nil, errBadArgs
	}
	if err := s.cfg.Backups.Remove(ctx, in.Name); err != nil {
		return nil, backupErr(err)
	}
	return localapi.Text{}, nil
}
