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
)

// The managed tree's procedures, skills and context reach a live agent
// through the broker tool managed_tree (W4), which answers only a machine
// labelled private. syncTree keeps the tree directory a copy of it, so
// /skills/mcp serves what the box has adopted. A failed fetch changes
// nothing: a replay machine, whose broker serves no such tool, keeps the
// tree it was seeded with, and a public machine keeps none.

// treeNamespaces are the only directories a sync writes or removes in, as
// long as no process in the guest changes the tree directory while it runs
// (#1732).
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
// file, since the tree holds neither. Everything goes through an os.Root,
// so a symlink in dir cannot send a write outside it.
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, ns := range treeNamespaces {
		if err := refuseLinks(root, ns); err != nil {
			return err
		}
	}
	for p, b := range files {
		if err := refuseLinks(root, p); err != nil {
			return err
		}
		if old, err := root.ReadFile(p); err == nil && bytes.Equal(old, b) {
			continue
		}
		if err := clearWay(root, p); err != nil {
			return err
		}
		if err := root.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		var n [8]byte
		rand.Read(n[:])
		tmp := filepath.Join(filepath.Dir(p), ".tree-"+hex.EncodeToString(n[:]))
		f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		_, err = f.Write(b)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = root.Chmod(tmp, 0o644)
		}
		if err == nil {
			err = root.Rename(tmp, p)
		}
		if err != nil {
			root.Remove(tmp)
			return err
		}
	}
	for _, ns := range treeNamespaces {
		var gone []string
		fs.WalkDir(root.FS(), ns, func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if _, keep := files[path]; !keep {
					gone = append(gone, path)
				}
			}
			return nil
		})
		for _, p := range gone {
			if err := root.Remove(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// refuseLinks fails if any component of p, from its namespace down to p
// itself, is a symlink. The os.Root follows one that stays inside the tree
// directory, so without this check a link such as skills/l -> ../other
// would let a write or a removal land in other, outside the namespaces.
// mirror checks the three namespaces themselves first, so the removal walk
// cannot follow one either. A component that does not exist yet is not a
// link, and nothing below it exists either. The error names the tree
// directory and the link, never p, so it is the same for every file and
// syncTree logs it once. The check is not atomic: a process in the guest
// that swaps a directory for a link between the check and the write or
// removal is not stopped (#1732).
func refuseLinks(root *os.Root, p string) error {
	var path []string
	for a := p; a != "."; a = filepath.Dir(a) {
		path = append(path, a)
	}
	for i := len(path) - 1; i >= 0; i-- {
		fi, err := root.Lstat(path[i])
		if err != nil {
			return nil
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			dir, _ := filepath.Abs(root.Name())
			return fmt.Errorf("tree directory %s: %s is a symlink; the sync is refused until it is removed", dir, path[i])
		}
	}
	return nil
}

// clearWay removes what an earlier tree left in the way of the file p: a
// regular file where p needs a directory, or a directory at p itself. The
// caller has checked with refuseLinks that no symlink lay on p's path a
// moment ago, so the Lstat and RemoveAll here act on the path they name
// unless a guest process swaps one in between (#1732).
func clearWay(root *os.Root, p string) error {
	ns, _, _ := strings.Cut(p, "/")
	var up []string
	for a := filepath.Dir(p); a != ns; a = filepath.Dir(a) {
		up = append(up, a)
	}
	for i := len(up) - 1; i >= 0; i-- {
		fi, err := root.Lstat(up[i])
		if err != nil {
			break
		}
		if fi.Mode().IsRegular() {
			return root.Remove(up[i])
		}
	}
	if fi, err := root.Lstat(p); err == nil && fi.IsDir() {
		return root.RemoveAll(p)
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
