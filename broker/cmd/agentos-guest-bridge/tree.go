package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	if ans.Unchanged && ans.Version == version {
		return version, nil
	}
	if err := mirror(dir, ans.Files); err != nil {
		return version, err
	}
	return ans.Version, nil
}

// mirror makes dir's tree namespaces hold exactly files. Every path is
// checked before anything is written, so a bad answer changes nothing.
// Each file is replaced whole (written aside, then renamed), so the skill
// server never reads half of one.
func mirror(dir string, files map[string][]byte) error {
	for p := range files {
		ns, _, _ := strings.Cut(p, "/")
		if !filepath.IsLocal(p) || filepath.Clean(p) != p || !inTree(ns) || ns == p {
			return fmt.Errorf("bad tree path %q", p)
		}
	}
	for _, ns := range treeNamespaces {
		root := filepath.Join(dir, ns)
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if _, keep := files[filepath.ToSlash(rel)]; !keep {
				return os.Remove(path)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for p, b := range files {
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if old, err := os.ReadFile(dst); err == nil && bytes.Equal(old, b) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(dst), ".tree-*")
		if err != nil {
			return err
		}
		_, err = tmp.Write(b)
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			err = os.Chmod(tmp.Name(), 0o644)
		}
		if err == nil {
			err = os.Rename(tmp.Name(), dst)
		}
		if err != nil {
			os.Remove(tmp.Name())
			return err
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
