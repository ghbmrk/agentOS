package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/guest"
	"golang.org/x/sys/unix"
)

// The managed tree's procedures, skills and context reach a live agent
// through the broker tool managed_tree (W4), which answers only a machine
// labelled private. syncTree keeps the tree directory a copy of it, so
// /skills/mcp serves what the box has adopted. A failed fetch changes
// nothing: a replay machine, whose broker serves no such tool, keeps the
// tree it was seeded with, and a public machine keeps none.

// treeNamespaces are the only directories a sync writes or removes in.
var treeNamespaces = []string{"procedures", "skills", "context"}

type treeAnswer struct {
	Version   string            `json:"version"`
	Unchanged bool              `json:"unchanged"`
	Files     map[string][]byte `json:"files"`
}

// syncTree fetches the tree every interval until ctx ends.
func syncTree(ctx context.Context, broker *http.Client, dir string, every time.Duration) {
	version, last := "", ""
	for {
		v, err := syncOnce(ctx, broker, dir, version)
		version = v
		switch {
		case err != nil && err.Error() != last:
			last = err.Error()
			log.Printf("managed tree: %v", err)
		case err == nil:
			last = ""
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// syncOnce fetches the tree unless it is still version, and writes it.
// It returns the version now held, on error too: a failed mirror may have
// written part of the new tree, so it holds no version, and the next
// fetch, an UNDO to the old version included, is answered whole (CHG-6).
func syncOnce(ctx context.Context, broker *http.Client, dir, version string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	text, err := callTool(ctx, broker, "managed_tree", map[string]string{"version": version})
	if err != nil {
		return version, err
	}
	var ans treeAnswer
	if err := json.Unmarshal([]byte(text), &ans); err != nil {
		return version, fmt.Errorf("broker answer: %v", err)
	}
	if !ans.Unchanged && ans.Version == "" {
		// Not a tree: mirroring it would delete the whole tree. The broker
		// never folds managed_tree (guest.TreeTool), so a fold stand-in is
		// refused here too.
		return version, errors.New("broker answer: no tree version; nothing changed")
	}
	if ans.Unchanged {
		if ans.Version != version {
			// Not ours: an unchanged answer never wipes the tree.
			return version, errors.New("broker answer: unchanged, but not the version held")
		}
		return version, nil
	}
	if err := mirror(dir, ans.Files); err != nil {
		return "", err
	}
	return ans.Version, nil
}

// callTool calls the broker tool name and returns its result's text.
func callTool(ctx context.Context, broker *http.Client, name string, args any) (string, error) {
	a, _ := json.Marshal(args)
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": json.RawMessage(a)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://broker.localhost/mcp", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := broker.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		Result *struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	// The guest plane refuses a managed_tree answer longer than
	// guest.MaxTreeAnswer, so one read whole fits under this limit.
	if err := json.NewDecoder(io.LimitReader(resp.Body, guest.MaxTreeAnswer)).Decode(&out); err != nil {
		return "", fmt.Errorf("broker answer: %v", err)
	}
	switch {
	case out.Error != nil:
		return "", errors.New(out.Error.Message)
	case out.Result == nil || len(out.Result.Content) == 0:
		return "", errors.New("empty broker answer")
	case out.Result.IsError:
		return "", errors.New(out.Result.Content[0].Text)
	}
	return out.Result.Content[0].Text, nil
}

// mirror makes dir's tree namespaces hold exactly files. Every path is
// checked before anything is written, so a bad answer changes nothing.
// New and changed files are written first, each written aside and
// renamed, so the skill server never reads half of one; files gone from
// the tree are removed last, so a failed write leaves the old tree's
// files rather than fewer. Only what is in a new file's way goes first: a
// file where it needs a directory, or a directory where it needs the
// file, since the tree holds neither.
//
// A symlink on a tree path, from its namespace down to the file itself,
// is refused: without that, a link such as skills/l -> ../other would let
// a write or a removal land in other, outside the namespaces. Guest root
// (ARC-7) can swap a directory for a link while a sync runs, so no name
// is checked and then used again: each directory is opened with
// O_NOFOLLOW below one already held, and every create, rename, unlink
// and enumeration acts on a held directory, never on a path (#1732).
func mirror(dir string, files map[string][]byte) error {
	for p := range files {
		ns, _, _ := strings.Cut(p, "/")
		if !filepath.IsLocal(p) || filepath.Clean(p) != p || !inTree(ns) || ns == p {
			return fmt.Errorf("bad tree path %q", p)
		}
		for a := filepath.Dir(p); a != ns; a = filepath.Dir(a) {
			if _, ok := files[a]; ok {
				return fmt.Errorf("bad tree path %q: %q is a file", p, a)
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// dir itself is the bridge's own flag, so it may be reached through a
	// link; nothing below it is.
	root, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	abs, _ := filepath.Abs(dir)
	t := &treeDir{dir: abs, root: root}
	// The namespaces first, so a link at one is refused before anything
	// is written, even when the tree holds no file in it.
	for _, ns := range treeNamespaces {
		if fi, err := t.lstat(root, ns); err == nil && fi.Mode&unix.S_IFMT == unix.S_IFLNK {
			return t.linkErr(ns)
		}
	}
	for p, b := range files {
		if err := t.write(p, b); err != nil {
			return err
		}
	}
	for _, ns := range treeNamespaces {
		d, err := t.openDir(root, ns, ns)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		err = t.prune(d, ns, files)
		d.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// treeDir is a mirror's open tree directory.
type treeDir struct {
	dir  string // absolute, for messages
	root *os.File
}

// linkErr names the tree directory and the link, never the file being
// written, so it is the same for every file and syncTree logs it once.
func (t *treeDir) linkErr(rel string) error {
	return fmt.Errorf("tree directory %s: %s is a symlink; the sync is refused until it is removed", t.dir, rel)
}

func (t *treeDir) lstat(d *os.File, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Fstatat(int(d.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

// openDir opens the directory name in d without following a link; rel
// is its path in the tree. A link there is refused, whatever an earlier
// look found.
func (t *treeDir) openDir(d *os.File, name, rel string) (*os.File, error) {
	fd, err := unix.Openat(int(d.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if st, serr := t.lstat(d, name); errors.Is(err, unix.ELOOP) || serr == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, t.linkErr(rel)
		}
		return nil, &fs.PathError{Op: "open", Path: filepath.Join(t.dir, rel), Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(t.dir, rel)), nil
}

// write makes the tree file p hold b, unless it already does.
func (t *treeDir) write(p string, b []byte) error {
	parts := strings.Split(p, "/")
	d := t.root
	for i, name := range parts[:len(parts)-1] {
		rel := strings.Join(parts[:i+1], "/")
		st, err := t.lstat(d, name)
		switch {
		case errors.Is(err, unix.ENOENT):
		case err != nil:
			return &fs.PathError{Op: "lstat", Path: filepath.Join(t.dir, rel), Err: err}
		case st.Mode&unix.S_IFMT == unix.S_IFLNK:
			return t.linkErr(rel)
		case st.Mode&unix.S_IFMT == unix.S_IFREG && i > 0:
			// An earlier tree's file where this one needs a directory.
			if err := unix.Unlinkat(int(d.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return &fs.PathError{Op: "remove", Path: filepath.Join(t.dir, rel), Err: err}
			}
		}
		if err := unix.Mkdirat(int(d.Fd()), name, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
			return &fs.PathError{Op: "mkdir", Path: filepath.Join(t.dir, rel), Err: err}
		}
		next, err := t.openDir(d, name, rel)
		if d != t.root {
			d.Close()
		}
		if err != nil {
			return err
		}
		d = next
	}
	defer d.Close()
	dfd, name := int(d.Fd()), parts[len(parts)-1]
	st, err := t.lstat(d, name)
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return &fs.PathError{Op: "lstat", Path: filepath.Join(t.dir, p), Err: err}
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return t.linkErr(p)
	case st.Mode&unix.S_IFMT == unix.S_IFDIR:
		// An earlier tree's directory where this one needs the file.
		if err := t.removeAll(d, name, p); err != nil {
			return err
		}
	case st.Mode&unix.S_IFMT == unix.S_IFREG:
		// O_NONBLOCK: a FIFO swapped in since the lstat must not hang the
		// sync; whatever is not this content is replaced by the rename.
		if fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0); err == nil {
			f := os.NewFile(uintptr(fd), name)
			old, err := io.ReadAll(io.LimitReader(f, int64(len(b))+1))
			f.Close()
			if err == nil && bytes.Equal(old, b) {
				return nil
			}
		}
	}
	var n [8]byte
	rand.Read(n[:])
	tmp := ".tree-" + hex.EncodeToString(n[:])
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return &fs.PathError{Op: "create", Path: filepath.Join(t.dir, filepath.Dir(p), tmp), Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if err = unix.Renameat(dfd, tmp, dfd, name); err != nil { // durable:exempt path-based durable.Rename would follow a swapped link (#1732); the mirror is rebuilt each sync
			err = &fs.PathError{Op: "rename", Path: filepath.Join(t.dir, p), Err: err}
		}
	}
	if err != nil {
		unix.Unlinkat(dfd, tmp, 0)
	}
	return err
}

// removeAll removes name in d and everything below it, through held
// directories: a link found anywhere is unlinked, never followed.
func (t *treeDir) removeAll(d *os.File, name, rel string) error {
	err := unix.Unlinkat(int(d.Fd()), name, 0)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return nil
	}
	sub, oerr := t.openDir(d, name, rel)
	if oerr != nil {
		return &fs.PathError{Op: "remove", Path: filepath.Join(t.dir, rel), Err: err}
	}
	names, err := sub.Readdirnames(-1)
	for _, n := range names {
		if err == nil {
			err = t.removeAll(sub, n, rel+"/"+n)
		}
	}
	sub.Close()
	if err != nil {
		return err
	}
	if err := unix.Unlinkat(int(d.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return &fs.PathError{Op: "remove", Path: filepath.Join(t.dir, rel), Err: err}
	}
	return nil
}

// prune removes every file below the held directory d (the tree path
// rel) that files does not hold. Directories stay; a link is a file
// here, unlinked and never followed.
func (t *treeDir) prune(d *os.File, rel string, files map[string][]byte) error {
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, n := range names {
		p := rel + "/" + n
		fd, err := unix.Openat(int(d.Fd()), n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			sub := os.NewFile(uintptr(fd), p)
			err = t.prune(sub, p, files)
			sub.Close()
			if err != nil {
				return err
			}
		case errors.Is(err, unix.ENOENT):
		case errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP):
			if _, keep := files[p]; keep {
				continue
			}
			if err := unix.Unlinkat(int(d.Fd()), n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return &fs.PathError{Op: "remove", Path: filepath.Join(t.dir, p), Err: err}
			}
		default:
			return &fs.PathError{Op: "open", Path: filepath.Join(t.dir, p), Err: err}
		}
	}
	return nil
}

func inTree(ns string) bool {
	for _, n := range treeNamespaces {
		if n == ns {
			return true
		}
	}
	return false
}
