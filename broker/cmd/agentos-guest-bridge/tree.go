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
)

// The managed tree's procedures, skills and context reach a live agent
// through the broker tool managed_tree (W4), which answers only a machine
// labelled private. syncTree keeps the tree directory a copy of it, so
// /skills/mcp serves what the box has adopted. A failed fetch changes
// nothing: a replay machine, whose broker serves no such tool, keeps the
// tree it was seeded with, and a public machine keeps none.

// treeNamespaces are the only directories a sync writes or removes in.
var treeNamespaces = []string{"procedures", "skills", "context"}

// maxTreeAnswer bounds a managed_tree answer as read: the broker's own
// limit (4 MiB of files) after JSON's base64.
const maxTreeAnswer = 8 << 20

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
		switch {
		case err != nil && err.Error() != last:
			last = err.Error()
			log.Printf("managed tree: %v", err)
		case err == nil:
			version, last = v, ""
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
// It returns the version now held.
func syncOnce(ctx context.Context, broker *http.Client, dir, version string) (string, error) {
	args, _ := json.Marshal(map[string]string{"version": version})
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "managed_tree", "arguments": json.RawMessage(args)},
	})
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://broker.localhost/mcp", bytes.NewReader(body))
	if err != nil {
		return version, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := broker.Do(req)
	if err != nil {
		return version, err
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTreeAnswer)).Decode(&out); err != nil {
		return version, fmt.Errorf("broker answer: %v", err)
	}
	switch {
	case out.Error != nil:
		return version, errors.New(out.Error.Message)
	case out.Result == nil || len(out.Result.Content) == 0:
		return version, errors.New("empty broker answer")
	case out.Result.IsError:
		return version, errors.New(out.Result.Content[0].Text)
	}
	var ans treeAnswer
	if err := json.Unmarshal([]byte(out.Result.Content[0].Text), &ans); err != nil {
		return version, fmt.Errorf("broker answer: %v", err)
	}
	if ans.Unchanged {
		if ans.Version != version {
			// Not ours: an unchanged answer never wipes the tree.
			return version, errors.New("broker answer: unchanged, but not the version held")
		}
		return version, nil
	}
	if err := mirror(dir, ans.Files); err != nil {
		return version, err
	}
	return ans.Version, nil
}

// mirror makes dir's tree namespaces hold exactly files. Every path is
// checked before anything is written, so a bad answer changes nothing.
// New and changed files are written first, each written aside and
// renamed, so the skill server never reads half of one; files gone from
// the tree are removed last, so a failed write leaves the old tree's
// files rather than fewer. Everything goes through an os.Root, so a
// symlink in dir cannot send a write outside it.
func mirror(dir string, files map[string][]byte) error {
	for p := range files {
		ns, _, _ := strings.Cut(p, "/")
		if !filepath.IsLocal(p) || filepath.Clean(p) != p || !inTree(ns) || ns == p {
			return fmt.Errorf("bad tree path %q", p)
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
	for p, b := range files {
		if old, err := root.ReadFile(p); err == nil && bytes.Equal(old, b) {
			continue
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

func inTree(ns string) bool {
	for _, n := range treeNamespaces {
		if n == ns {
			return true
		}
	}
	return false
}
